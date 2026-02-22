// Package tcc provides telemetry modules for TCC (Transparency, Consent, and Control)
// permission probing. Modules attempt to access protected resources and emit telemetry
// whether access is granted or denied, since both outcomes represent EDR-relevant events.
package tcc

import (
	"context"
	"fmt"
	"os"

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
			Description:  "Path to TCC.db",
			Required:     false,
			DefaultValue: "/Library/Application Support/com.apple.TCC/TCC.db",
			Example:      "~/Library/Application Support/com.apple.TCC/TCC.db",
		},
	}
}

func (t *tccFDA) CheckPrereqs() error { return nil }

func (t *tccFDA) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	tccPath := params.Get("tcc_path", "/Library/Application Support/com.apple.TCC/TCC.db")
	info := t.Info()

	ev := output.NewEvent(info, "tcc_fda_probe", false, fmt.Sprintf("attempting to read %s", tccPath))

	f, err := os.Open(tccPath)
	if err != nil {
		ev.Success = true
		ev.Message = fmt.Sprintf("TCC FDA probe: access denied to %s (expected without FDA)", tccPath)
		ev = output.WithDetails(ev, map[string]any{
			"path":   tccPath,
			"result": "denied",
			"note":   "Access denied indicates TCC is working; grant Full Disk Access to test FDA bypass",
		})
		if !os.IsPermission(err) {
			ev = output.WithError(ev, err)
		}
		emit(ev)
		return nil
	}
	defer func() { _ = f.Close() }()

	stat, _ := f.Stat()
	ev.Success = true
	ev.Message = fmt.Sprintf("TCC FDA probe: read access granted to %s", tccPath)
	ev = output.WithDetails(ev, map[string]any{
		"path":      tccPath,
		"result":    "granted",
		"file_size": stat.Size(),
	})
	emit(ev)
	return nil
}

func (t *tccFDA) DryRun(params module.Params) []string {
	path := params.Get("tcc_path", "/Library/Application Support/com.apple.TCC/TCC.db")
	return []string{fmt.Sprintf("open %s for reading (probes FDA permission)", path)}
}

func (t *tccFDA) Cleanup() error { return nil }

func init() {
	module.Register(&tccFDA{})
}
