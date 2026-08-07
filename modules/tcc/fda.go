// Package tcc provides telemetry modules for TCC (Transparency, Consent, and Control)
// permission probing. Modules attempt to access protected resources and emit telemetry
// whether access is granted or denied, since both outcomes represent EDR-relevant events.
package tcc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type tccFDA struct{}

func (t *tccFDA) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "tcc_fda",
		Description: "Attempts to read TCC.db to probe Full Disk Access permission",
		Category:    module.CategoryTCC,
		Tags:        []string{"tcc", "fda", "full-disk-access", "privacy"},
		Privileges:  module.PrivilegeTCC,
		MITRE: []module.MITRE{
			{Technique: "T1555", Name: "Credentials from Password Stores"},
			{Technique: "T1082", Name: "System Information Discovery"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (t *tccFDA) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "tcc_path",
			Description:  "Path to the TCC-gated file to probe (defaults to the per-user TCC.db)",
			Required:     false,
			DefaultValue: "~/Library/Application Support/com.apple.TCC/TCC.db",
			Example:      "/Library/Application Support/com.apple.TCC/TCC.db",
		},
	}
}

func (t *tccFDA) CheckPrereqs() error { return nil }

// defaultFDAPath returns the per-user TCC database.
//
// The system database under /Library is root-owned, so an unprivileged process
// is refused by ordinary POSIX permissions before TCC is ever consulted, and
// the probe cannot tell a privacy denial from a plain mode-bit denial. The
// per-user database is owned by the user running the probe, so POSIX permits
// the read and only Full Disk Access decides the outcome.
func defaultFDAPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db"), nil
}

func (t *tccFDA) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	tccPath := params.Get("tcc_path", "")
	if tccPath == "" {
		var err error
		if tccPath, err = defaultFDAPath(); err != nil {
			return err
		}
	}
	info := t.Info()

	ev := output.NewEvent(info, "tcc_fda_probe", true, fmt.Sprintf("attempting to read %s", tccPath))
	details := map[string]any{"path": tccPath}

	f, err := os.Open(tccPath)
	outcome := classifyProbe(err)
	details["result"] = string(outcome)

	switch outcome {
	case probeGranted:
		defer func() { _ = f.Close() }()
		ev.Message = fmt.Sprintf("TCC FDA probe: read access granted to %s", tccPath)
		if stat, statErr := f.Stat(); statErr == nil {
			details["file_size"] = stat.Size()
		}
	case probeDenied:
		ev.Message = fmt.Sprintf("TCC FDA probe: access denied to %s (expected without FDA)", tccPath)
	case probeAbsent:
		ev.Message = fmt.Sprintf("TCC FDA probe: %s does not exist, no TCC decision was made", tccPath)
		ev = output.WithError(ev, err)
		ev.Success = true
	default:
		ev.Message = fmt.Sprintf("TCC FDA probe: unexpected failure reading %s", tccPath)
		ev = output.WithError(ev, err)
		ev.Success = true
	}

	ev = output.WithDetails(ev, details)
	emit(ev)
	return nil
}

func (t *tccFDA) DryRun(params module.Params) []string {
	path := params.Get("tcc_path", "")
	if path == "" {
		path, _ = defaultFDAPath()
	}
	return []string{fmt.Sprintf("open %s for reading (probes FDA permission)", path)}
}

func (t *tccFDA) Cleanup() error { return nil }

func init() {
	module.Register(&tccFDA{})
}
