package file

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type fileHide struct {
	files []ownedFile
	dirs  []ownedDir
}

func (f *fileHide) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_hide",
		EventTypes:  []string{"file_hide_chflags", "file_hide_dotfile"},
		Description: "Creates hidden files using chflags and dotfile naming to generate file hiding telemetry",
		Category:    module.CategoryFile,
		Tags:        []string{"hide", "chflags", "dotfile", "stealth"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1564", SubTech: ".001", Name: "Hide Artifacts: Hidden Files and Directories"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileHide) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:        "work_dir",
			Description: "Working directory for hidden file creation",
			Type:        module.ParamPath,
			Required:    true,
			Default:     "/tmp/macnoise_hide",
			Example:     "/var/tmp/macnoise_hide",
		},
	}
}

func (f *fileHide) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (f *fileHide) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	workDir := params.String("work_dir", "/tmp/macnoise_hide")
	info := f.Info()

	createdDirs, err := ensureDirs(workDir, 0o755)
	f.dirs = append(f.dirs, createdDirs...)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", workDir, err)
	}

	chflagsTarget := filepath.Join(workDir, "visible_file.txt")
	owned, err := createOwnedFile(chflagsTarget, []byte("macnoise chflags hidden test\n"), 0o644)
	if err != nil {
		return err
	}
	f.files = append(f.files, owned)
	chflagsEv := output.NewEvent(info, "file_hide_chflags", module.OutcomeError, module.File(chflagsTarget), fmt.Sprintf("hiding %s via chflags", chflagsTarget))
	chflagsOut, chflagsErr := exec.CommandContext(ctx, "chflags", "hidden", chflagsTarget).CombinedOutput()
	if chflagsErr != nil {
		chflagsEv = output.WithError(chflagsEv, fmt.Errorf("%v: %s", chflagsErr, chflagsOut))
	} else {
		chflagsEv.Outcome = module.OutcomeExecuted
		chflagsEv.Message = fmt.Sprintf("file hidden via chflags: %s", chflagsTarget)
		chflagsEv = output.WithDetails(chflagsEv, map[string]any{"path": chflagsTarget, "method": "chflags hidden"})
	}
	resultErr := errors.Join(chflagsErr, emit(chflagsEv))

	dotTarget := filepath.Join(workDir, ".macnoise_hidden")
	dotEv := output.NewEvent(info, "file_hide_dotfile", module.OutcomeError, module.File(dotTarget), fmt.Sprintf("creating dotfile: %s", dotTarget))
	owned, err = createOwnedFile(dotTarget, []byte("macnoise dotfile hidden test\n"), 0o644)
	if err != nil {
		dotEv = output.WithError(dotEv, err)
	} else {
		f.files = append(f.files, owned)
		dotEv.Outcome = module.OutcomeExecuted
		dotEv.Message = fmt.Sprintf("dotfile created: %s", dotTarget)
		dotEv = output.WithDetails(dotEv, map[string]any{"path": dotTarget, "method": "dotfile"})
	}
	return errors.Join(resultErr, err, emit(dotEv))
}

func (f *fileHide) DryRun(params module.Params) []string {
	workDir := params.String("work_dir", "/tmp/macnoise_hide")
	return []string{
		fmt.Sprintf("mkdir -p %s", workDir),
		fmt.Sprintf("create %s/visible_file.txt && chflags hidden %s/visible_file.txt", workDir, workDir),
		fmt.Sprintf("create dotfile %s/.macnoise_hidden", workDir),
	}
}

func (f *fileHide) Cleanup(ctx context.Context) error {
	err := errors.Join(removeOwnedFiles(f.files), removeOwnedDirs(f.dirs))
	f.files = nil
	f.dirs = nil
	return err
}

func init() {
	module.Register(func() module.Generator { return &fileHide{} })
}
