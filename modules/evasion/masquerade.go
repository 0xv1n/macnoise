package evasion

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/ownership"
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
	stagedBinary ownership.File
	createdDirs  []ownership.Directory
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
		{Name: "stage_dir", Description: "Directory for the masqueraded binary", Type: module.ParamPath, Default: defaultMasqueradeStageDir, Example: "/var/tmp/macnoise_masquerade"},
		{Name: "source_binary", Description: "Benign system utility to copy and run", Type: module.ParamPath, Default: defaultMasqueradeSource, Example: "/bin/cp"},
		{Name: "masquerade_name", Description: "Legitimate-looking name to run the copy under", Type: module.ParamString, Default: defaultMasqueradeName, Example: "mdworker_shared"},
	}
}

func (e *evadeMasquerade) ValidateParams(params module.Params) error {
	name := params.String("masquerade_name", defaultMasqueradeName)
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("masquerade_name must be a filename: %q", name)
	}
	return nil
}

func (e *evadeMasquerade) CheckPrereqs(ctx context.Context, params module.Params) error {
	return e.ValidateParams(params)
}

// copyExecutable copies src to dst with executable permissions. It is the pure,
// cross-platform-testable half of the module; the exec that follows is the
// macOS-specific part.
func copyExecutable(src, dst string) (ownership.File, error) {
	in, err := os.Open(src)
	if err != nil {
		return ownership.File{}, err
	}
	defer func() { _ = in.Close() }()
	return ownership.CreateFileFrom(dst, in, 0o755)
}

func (e *evadeMasquerade) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := e.ValidateParams(params); err != nil {
		return err
	}
	runID := module.RunIDFromContext(ctx)
	stageDir := module.TagPath(params.String("stage_dir", defaultMasqueradeStageDir), runID)
	source := params.String("source_binary", defaultMasqueradeSource)
	masqName := params.String("masquerade_name", defaultMasqueradeName)
	info := e.Info()

	createdDirs, err := ownership.EnsureDirectories(stageDir, 0o755)
	e.createdDirs = append(e.createdDirs, createdDirs...)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", stageDir, err)
	}
	destPath := filepath.Join(stageDir, masqName)

	copyEv := output.NewEvent(info, "masquerade_copy", module.OutcomeError, module.File(destPath),
		fmt.Sprintf("copying %s to %s (masquerading as %q)", source, destPath, masqName))
	stagedBinary, err := copyExecutable(source, destPath)
	if err != nil {
		copyEv = output.WithError(copyEv, err)
		return errors.Join(err, emit(copyEv))
	}
	e.stagedBinary = stagedBinary
	copyEv.Outcome = module.OutcomeExecuted
	copyEv.Message = fmt.Sprintf("staged %s as %s", source, destPath)
	copyEv = output.WithDetails(copyEv, map[string]any{
		"source":         source,
		"path":           destPath,
		"masqueraded_as": masqName,
	})
	if err := emit(copyEv); err != nil {
		return err
	}

	execEv := output.NewEvent(info, "masquerade_exec", module.OutcomeError,
		module.Process(filepath.Base(destPath), destPath, destPath, 0),
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
		execEv.Outcome = module.OutcomeExecuted
		execEv.Message = fmt.Sprintf("ran %s as %q (real binary: %s)", destPath, masqName, source)
		execEv = output.WithDetails(execEv, map[string]any{
			"path":           destPath,
			"masqueraded_as": masqName,
			"real_source":    source,
		})
	}
	return emit(execEv)
}

func (e *evadeMasquerade) DryRun(params module.Params) []string {
	source := params.String("source_binary", defaultMasqueradeSource)
	masqName := params.String("masquerade_name", defaultMasqueradeName)
	stageDir := params.String("stage_dir", defaultMasqueradeStageDir)
	dest := filepath.Join(stageDir, masqName)
	return []string{
		fmt.Sprintf("copy %s to %s (T1036.003)", source, dest),
		fmt.Sprintf("execute %s masquerading as %q (T1036.005)", dest, masqName),
	}
}

func (e *evadeMasquerade) Cleanup(ctx context.Context) error {
	return errors.Join(e.stagedBinary.Remove(), ownership.RemoveDirectories(e.createdDirs))
}

func init() {
	module.Register(func() module.Generator { return &evadeMasquerade{} })
}
