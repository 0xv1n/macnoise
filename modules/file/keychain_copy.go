package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const (
	defaultKeychainStageDir = "/tmp/macnoise_keychain"
	// systemKeychainDir holds the machine-wide keychains. Named rather than
	// inlined so the enumeration can be pointed at a temp directory in tests.
	systemKeychainDir = "/Library/Keychains"
)

// errStageWrite marks a failure to write the staged copy, as opposed to a
// failure to read the keychain. The two must stay distinguishable: a full disk
// is a macnoise fault, while a refused read is the credential-access signal
// this module exists to produce, and reporting one as the other would put a
// privacy decision in the audit log that the host never made.
var errStageWrite = errors.New("staging write failed")

type fileKeychainCopy struct {
	stageDir string
}

// keychainTarget is one keychain database to copy, tagged with which store it
// is so a consumer can tell a user keychain from the system one without parsing
// the path.
type keychainTarget struct {
	kind string
	path string
}

func (f *fileKeychainCopy) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_keychain_copy",
		Description: "Copies macOS keychain databases wholesale into a staging directory to generate keychain collection telemetry",
		Category:    module.CategoryFile,
		Tags:        []string{"credentials", "keychain", "collection", "staging"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			// T1555.001 covers reading the keychain database directly rather
			// than through the security command, and names login.keychain-db in
			// its own procedure examples. T1074.001 is the staging half: the
			// copies are left in one directory so file_archive can zip them, the
			// same order AMOS performs them in.
			{Technique: "T1555", SubTech: ".001", Name: "Credentials from Password Stores: Keychain"},
			{Technique: "T1074", SubTech: ".001", Name: "Data Staged: Local Data Staging"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (f *fileKeychainCopy) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "stage_dir",
			Description:  "Directory to stage the keychain copies in",
			Required:     false,
			DefaultValue: defaultKeychainStageDir,
			Example:      "/var/tmp/macnoise_kc",
		},
	}
}

func (f *fileKeychainCopy) CheckPrereqs() error { return nil }

// defaultKeychainTargets lists the keychain databases to copy. Both directories
// are parameters so tests can point the enumeration at temp directories.
//
// The legacy login.keychain-db is what AMOS and most public reporting name, but
// it is created by a GUI login and is simply absent on an account that has never
// had one. The data-protection keychain that superseded it lives under a
// per-user UUID directory, so it has to be globbed rather than named. Probing
// every store means a host missing any one of them still produces signal, and
// the root-owned system-keychain-2.db yields a clean denial when not root.
func defaultKeychainTargets(home, systemDir string) []keychainTarget {
	keychainDir := filepath.Join(home, "Library", "Keychains")

	targets := []keychainTarget{
		{kind: "login_keychain", path: filepath.Join(keychainDir, "login.keychain-db")},
	}
	// Glob only errors on a malformed pattern, which this is not, so an error
	// here means no matches and is safe to ignore.
	matches, _ := filepath.Glob(filepath.Join(keychainDir, "*", "keychain-2.db"))
	for _, m := range matches {
		targets = append(targets, keychainTarget{kind: "data_protection_keychain", path: m})
	}
	return append(targets,
		keychainTarget{kind: "system_keychain", path: filepath.Join(systemDir, "System.keychain")},
		keychainTarget{kind: "system_data_protection_keychain", path: filepath.Join(systemDir, "system-keychain-2.db")},
	)
}

// stagedNames assigns each target a unique destination filename. Basenames are
// not unique on their own - a host with more than one keychain directory has
// several keychain-2.db - and a collision would mean one copy silently
// overwriting another, so a repeat gets a numeric suffix.
func stagedNames(targets []keychainTarget) []string {
	seen := map[string]int{}
	names := make([]string, len(targets))
	for i, t := range targets {
		name := t.kind + "_" + filepath.Base(t.path)
		if n := seen[name]; n > 0 {
			names[i] = fmt.Sprintf("%s.%d", name, n)
		} else {
			names[i] = name
		}
		seen[name]++
	}
	return names
}

// copyKeychain copies src to dst and returns the bytes written. A source error
// is returned unwrapped so the caller can classify it as absent or denied; a
// destination error is wrapped in errStageWrite.
//
// The 0600 mode, and the 0700 staging directory in Generate, are deliberately
// tighter than the 0644/0755 the other file modules use. This writes a real
// copy of a credential store into a world-writable /tmp, and inheriting the
// conventional mode would leave the copy readable by everyone on the host when
// the original was not.
func copyKeychain(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", errStageWrite, err)
	}
	defer func() { _ = out.Close() }()

	n, err := io.Copy(out, in)
	if err != nil {
		return n, fmt.Errorf("%w: %w", errStageWrite, err)
	}
	return n, nil
}

// keychainEvents copies one target and returns the telemetry for it. Kept
// separate from Generate, and taking plain paths, so the absent/denied/copied
// classification runs against real temp files in the cross-platform test job
// rather than only behind a darwin build tag.
func keychainEvents(info module.ModuleInfo, t keychainTarget, dst string) []module.TelemetryEvent {
	n, err := copyKeychain(t.path, dst)

	switch {
	case errors.Is(err, errStageWrite):
		// macnoise could not write the copy. Nothing about the host's handling
		// of the keychain can be concluded from that, so it is reported as the
		// tool fault it is rather than as a read result.
		ev := output.NewEvent(info, "keychain_copy", false,
			fmt.Sprintf("staging %s to %s failed", t.kind, dst))
		ev = output.WithDetails(ev, map[string]any{
			"kind":        t.kind,
			"source_path": t.path,
			"staged_path": dst,
		})
		return []module.TelemetryEvent{output.WithError(ev, err)}

	case os.IsNotExist(err):
		// Absent store: nothing was read and no access decision was made, the
		// same distinction cred_files and the TCC probes draw.
		ev := output.NewEvent(info, "keychain_read", true,
			fmt.Sprintf("%s not present: %s", t.kind, t.path))
		ev = output.WithOutcome(ev, module.OutcomeIndeterminate, nil)
		return []module.TelemetryEvent{output.WithDetails(ev, map[string]any{
			"kind":   t.kind,
			"path":   t.path,
			"exists": false,
		})}

	case err != nil:
		// The store exists but could not be opened. That refusal is the signal a
		// detection keys on, not a module failure, so it is a completed and
		// refused read rather than an error.
		ev := output.NewEvent(info, "keychain_read", true,
			fmt.Sprintf("%s read denied: %s", t.kind, t.path))
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		return []module.TelemetryEvent{output.WithDetails(ev, map[string]any{
			"kind":       t.kind,
			"path":       t.path,
			"exists":     true,
			"accessible": false,
		})}

	default:
		// A copy is a read of the source and a create of the destination, and
		// OCSF has no single activity covering both, so each half is emitted as
		// what it actually was. Both matter to a consumer: the read of a
		// keychain is the credential access, and a keychain-shaped file
		// appearing in a staging directory is the collection.
		readEv := output.NewEvent(info, "keychain_read", true,
			fmt.Sprintf("%s read: %s (%d bytes)", t.kind, t.path, n))
		readEv = output.WithDetails(readEv, map[string]any{
			"kind":       t.kind,
			"path":       t.path,
			"exists":     true,
			"accessible": true,
			"bytes_read": n,
		})

		copyEv := output.NewEvent(info, "keychain_copy", true,
			fmt.Sprintf("%s staged to %s (%d bytes)", t.kind, dst, n))
		copyEv = output.WithDetails(copyEv, map[string]any{
			"kind":         t.kind,
			"source_path":  t.path,
			"staged_path":  dst,
			"bytes_copied": n,
		})
		return []module.TelemetryEvent{readEv, copyEv}
	}
}

func (f *fileKeychainCopy) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	info := f.Info()

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	stageDir := params.Get("stage_dir", defaultKeychainStageDir)
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", stageDir, err)
	}
	f.stageDir = stageDir

	targets := defaultKeychainTargets(home, systemKeychainDir)
	names := stagedNames(targets)

	for i, target := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		for _, ev := range keychainEvents(info, target, filepath.Join(stageDir, names[i])) {
			emit(ev)
		}
	}
	return nil
}

func (f *fileKeychainCopy) DryRun(params module.Params) []string {
	stageDir := params.Get("stage_dir", defaultKeychainStageDir)
	return []string{
		fmt.Sprintf("mkdir -p %s (mode 0700)", stageDir),
		fmt.Sprintf("cp ~/Library/Keychains/login.keychain-db ~/Library/Keychains/<uuid>/keychain-2.db %s/System.keychain %s/system-keychain-2.db %s/ (mode 0600)",
			systemKeychainDir, systemKeychainDir, stageDir),
	}
}

// Cleanup removes the staged copies. Leaving real credential stores duplicated
// on disk is not an acceptable default, so this runs unless --no-cleanup is
// passed, which announces itself.
func (f *fileKeychainCopy) Cleanup() error {
	if f.stageDir == "" {
		return nil
	}
	return os.RemoveAll(f.stageDir)
}

func init() {
	module.Register(&fileKeychainCopy{})
}
