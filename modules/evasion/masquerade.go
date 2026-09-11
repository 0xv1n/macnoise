package evasion

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const (
	defaultMasqueradeStageDir = "/tmp/macnoise_masquerade"
	defaultMasqueradeSource   = "/usr/bin/true"
	// A real macOS system process name. Running a copy of a benign utility under
	// this name from a non-standard path is the masquerade: the process advertises
	// itself as a trusted system component it is not.
	defaultMasqueradeName = "com.apple.WindowServer"
)

type evadeMasquerade struct {
	stageDir string
}

func (e *evadeMasquerade) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "evade_masquerade",
		EventTypes:  []string{"masquerade_copy", "masquerade_exec"},
		Description: "Copies a system utility to a name impersonating a legitimate process and executes it to generate masquerading telemetry",
		Category:    module.CategoryEvasion,
		Tags:        []string{"evasion", "masquerade", "rename", "defense-evasion"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1036", SubTech: ".003", Name: "Masquerading: Rename System Utilities"},
			{Technique: "T1036", SubTech: ".005", Name: "Masquerading: Match Legitimate Name or Location"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (e *evadeMasquerade) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "stage_dir", Description: "Directory for the masqueraded binary", Required: false, DefaultValue: defaultMasqueradeStageDir, Example: "/var/tmp/macnoise_masquerade"},
		{Name: "source_binary", Description: "Benign system utility to copy and run", Required: false, DefaultValue: defaultMasqueradeSource, Example: "/bin/cp"},
		{Name: "masquerade_name", Description: "Legitimate-looking name to run the copy under", Required: false, DefaultValue: defaultMasqueradeName, Example: "mdworker_shared"},
	}
}

func (e *evadeMasquerade) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

// copyExecutable copies src to dst with executable permissions. It is the pure,
// cross-platform-testable half of the module; the exec that follows is the
// macOS-specific part.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func (e *evadeMasquerade) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	runID := module.RunIDFromContext(ctx)
	stageDir := module.TagPath(params.Get("stage_dir", defaultMasqueradeStageDir), runID)
	source := params.Get("source_binary", defaultMasqueradeSource)
	masqName := params.Get("masquerade_name", defaultMasqueradeName)
	info := e.Info()

	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", stageDir, err)
	}
	e.stageDir = stageDir
	destPath := filepath.Join(stageDir, masqName)

	copyEv := output.NewEvent(info, "masquerade_copy", false,
		fmt.Sprintf("copying %s to %s (masquerading as %q)", source, destPath, masqName))
	if err := copyExecutable(source, destPath); err != nil {
		copyEv = output.WithError(copyEv, err)
		emit(copyEv)
		return nil
	}
	copyEv.Success = true
	copyEv.Message = fmt.Sprintf("staged %s as %s", source, destPath)
	copyEv = output.WithDetails(copyEv, map[string]any{
		"source":         source,
		"path":           destPath,
		"masqueraded_as": masqName,
	})
	emit(copyEv)

	execEv := output.NewEvent(info, "masquerade_exec", false,
		fmt.Sprintf("executing %s under masquerading name %q", destPath, masqName))
	out, err := exec.CommandContext(ctx, destPath).CombinedOutput()
	if err != nil {
		// The environment refused the launch (SIP, noexec, missing loader). That
		// is the host declining, not macnoise breaking, and the attempted exec is
		// still the telemetry a masquerading detection keys on.
		execEv = output.WithOutcome(execEv, module.OutcomeDenied, err)
		execEv.Message = fmt.Sprintf("masqueraded exec of %s could not be launched", destPath)
		execEv = output.WithDetails(execEv, map[string]any{
			"path":           destPath,
			"masqueraded_as": masqName,
			"output":         strings.TrimSpace(string(out)),
		})
	} else {
		execEv.Success = true
		execEv.Message = fmt.Sprintf("ran %s as %q (real binary: %s)", destPath, masqName, source)
		execEv = output.WithDetails(execEv, map[string]any{
			"path":           destPath,
			"masqueraded_as": masqName,
			"real_source":    source,
		})
	}
	emit(execEv)
	return nil
}

func (e *evadeMasquerade) DryRun(params module.Params) []string {
	source := params.Get("source_binary", defaultMasqueradeSource)
	masqName := params.Get("masquerade_name", defaultMasqueradeName)
	stageDir := params.Get("stage_dir", defaultMasqueradeStageDir)
	dest := filepath.Join(stageDir, masqName)
	return []string{
		fmt.Sprintf("copy %s to %s (T1036.003)", source, dest),
		fmt.Sprintf("execute %s masquerading as %q (T1036.005)", dest, masqName),
	}
}

func (e *evadeMasquerade) Cleanup(ctx context.Context) error {
	if e.stageDir == "" {
		return nil
	}
	return os.RemoveAll(e.stageDir)
}

func init() {
	module.Register(func() module.Generator { return &evadeMasquerade{} })
}
