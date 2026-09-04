package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type fileCredFiles struct{}

// credTarget is a single credential file to probe, tagged with the class of
// secret it holds so a consumer can act on the kind without parsing the path.
type credTarget struct {
	kind string
	path string
}

func (f *fileCredFiles) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_cred_files",
		EventTypes:  []string{"cred_file_probe", "cred_file_read"},
		Description: "Reads well-known credential files (SSH keys, cloud and container configs, .env) to generate credential-in-files access telemetry",
		Category:    module.CategoryFile,
		Tags:        []string{"credentials", "ssh", "aws", "kubernetes", "docker", "dotenv"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1552", SubTech: ".001", Name: "Unsecured Credentials: Credentials In Files"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (f *fileCredFiles) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "paths",
			Description:  "Comma-separated extra file paths to probe, e.g. a project .env",
			Required:     false,
			DefaultValue: "",
			Example:      "/Users/dev/project/.env,/Users/dev/.netrc",
		},
	}
}

func (f *fileCredFiles) CheckPrereqs() error { return nil }

// sshKeyPaths lists the SSH private keys to probe. The well-known names are
// always included so an absent key still produces telemetry, and a glob catches
// any non-standard key names actually present. Public keys are skipped: a .pub
// file is not a secret, and reading it would be misleading credential-access
// telemetry.
func sshKeyPaths(home string) []string {
	sshDir := filepath.Join(home, ".ssh")

	seen := map[string]bool{}
	var paths []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	for _, name := range []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"} {
		add(filepath.Join(sshDir, name))
	}
	// Glob failure only occurs on a bad pattern, which this is not, so an error
	// here means no matches and is safe to ignore.
	matches, _ := filepath.Glob(filepath.Join(sshDir, "id_*"))
	for _, m := range matches {
		if strings.HasSuffix(m, ".pub") {
			continue
		}
		add(m)
	}
	return paths
}

// defaultCredTargets is the fixed set of well-known credential locations, built
// relative to home so tests can point it at a temp directory.
func defaultCredTargets(home string) []credTarget {
	var targets []credTarget
	for _, p := range sshKeyPaths(home) {
		targets = append(targets, credTarget{kind: "ssh_private_key", path: p})
	}
	targets = append(targets,
		credTarget{kind: "aws_credentials", path: filepath.Join(home, ".aws", "credentials")},
		credTarget{kind: "kube_config", path: filepath.Join(home, ".kube", "config")},
		credTarget{kind: "docker_config", path: filepath.Join(home, ".docker", "config.json")},
		credTarget{kind: "dotenv", path: filepath.Join(home, ".env")},
	)
	return targets
}

// parseExtraPaths splits the user-supplied paths parameter, dropping empties so
// a trailing comma or blank value does not produce a probe for "".
func parseExtraPaths(param string) []string {
	if param == "" {
		return nil
	}
	var paths []string
	for _, p := range strings.Split(param, ",") {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

func (f *fileCredFiles) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	info := f.Info()

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	targets := defaultCredTargets(home)
	for _, p := range parseExtraPaths(params.Get("paths", "")) {
		targets = append(targets, credTarget{kind: "custom", path: p})
	}

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		emit(credEvent(info, target))
	}
	return nil
}

// credEvent probes one target and builds its telemetry event. Kept separate
// from Generate so the absent/denied/read classification is exercised
// cross-platform against real temp files rather than only behind a darwin build
// tag.
func credEvent(info module.ModuleInfo, target credTarget) module.TelemetryEvent {
	n, readErr := readCredFile(target.path)

	switch {
	case os.IsNotExist(readErr) || errors.Is(readErr, errNotRegularFile):
		ev := output.NewEvent(info, "cred_file_probe", true,
			fmt.Sprintf("%s not present: %s", target.kind, target.path))
		// Absent target: nothing was read and no access decision was made, the
		// same distinction the TCC probes and browser_creds draw.
		ev = output.WithOutcome(ev, module.OutcomeIndeterminate, nil)
		return output.WithDetails(ev, map[string]any{
			"kind":   target.kind,
			"path":   target.path,
			"exists": false,
		})

	case readErr != nil:
		// The file exists but could not be read. A permission denial is the
		// signal a detection wants, not a module failure, so it is reported as
		// a completed, refused read attempt. os.Open, not os.Stat, is what
		// draws this line: Stat succeeds on a file the caller cannot open.
		ev := output.NewEvent(info, "cred_file_read", true,
			fmt.Sprintf("%s read denied: %s", target.kind, target.path))
		ev = output.WithOutcome(ev, module.OutcomeDenied, readErr)
		return output.WithDetails(ev, map[string]any{
			"kind":       target.kind,
			"path":       target.path,
			"exists":     true,
			"accessible": false,
		})

	default:
		ev := output.NewEvent(info, "cred_file_read", true,
			fmt.Sprintf("%s read: %s (%d bytes)", target.kind, target.path, n))
		return output.WithDetails(ev, map[string]any{
			"kind":       target.kind,
			"path":       target.path,
			"exists":     true,
			"accessible": true,
			"bytes_read": n,
		})
	}
}

func (f *fileCredFiles) DryRun(params module.Params) []string {
	extra := parseExtraPaths(params.Get("paths", ""))
	lines := []string{
		"open and read ~/.ssh/id_* (private keys only), ~/.aws/credentials, ~/.kube/config, ~/.docker/config.json, ~/.env (contents discarded)",
	}
	if len(extra) > 0 {
		lines = append(lines, fmt.Sprintf("open and read extra paths: %s (contents discarded)", strings.Join(extra, ", ")))
	}
	return lines
}

func (f *fileCredFiles) Cleanup() error { return nil }

func init() {
	module.Register(&fileCredFiles{})
}
