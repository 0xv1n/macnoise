package file

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type fileHide struct {
	workDir string
}

func (f *fileHide) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_hide",
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
			Name:         "work_dir",
			Description:  "Working directory for hidden file creation",
			Required:     false,
			DefaultValue: "/tmp/macnoise_hide",
			Example:      "/var/tmp/macnoise_hide",
		},
	}
}

func (f *fileHide) CheckPrereqs() error { return nil }

func (f *fileHide) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	workDir := params.Get("work_dir", "/tmp/macnoise_hide")
	f.workDir = workDir
	info := f.Info()

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", workDir, err)
	}

	chflagsTarget := filepath.Join(workDir, "visible_file.txt")
	if err := os.WriteFile(chflagsTarget, []byte("macnoise chflags hidden test\n"), 0o644); err == nil {
		chflagsEv := output.NewEvent(info, "file_hide_chflags", false, fmt.Sprintf("hiding %s via chflags", chflagsTarget))
		chflagsOut, chflagsErr := exec.CommandContext(ctx, "chflags", "hidden", chflagsTarget).CombinedOutput()
		if chflagsErr != nil {
			chflagsEv = output.WithError(chflagsEv, fmt.Errorf("%v: %s", chflagsErr, chflagsOut))
		} else {
			chflagsEv.Success = true
			chflagsEv.Message = fmt.Sprintf("file hidden via chflags: %s", chflagsTarget)
			chflagsEv = output.WithDetails(chflagsEv, map[string]any{"path": chflagsTarget, "method": "chflags hidden"})
		}
		emit(chflagsEv)
	}

	dotTarget := filepath.Join(workDir, ".macnoise_hidden")
	dotEv := output.NewEvent(info, "file_hide_dotfile", false, fmt.Sprintf("creating dotfile: %s", dotTarget))
	if err := os.WriteFile(dotTarget, []byte("macnoise dotfile hidden test\n"), 0o644); err != nil {
		dotEv = output.WithError(dotEv, err)
	} else {
		dotEv.Success = true
		dotEv.Message = fmt.Sprintf("dotfile created: %s", dotTarget)
		dotEv = output.WithDetails(dotEv, map[string]any{"path": dotTarget, "method": "dotfile"})
	}
	emit(dotEv)

	return nil
}

func (f *fileHide) DryRun(params module.Params) []string {
	workDir := params.Get("work_dir", "/tmp/macnoise_hide")
	return []string{
		fmt.Sprintf("mkdir -p %s", workDir),
		fmt.Sprintf("create %s/visible_file.txt && chflags hidden %s/visible_file.txt", workDir, workDir),
		fmt.Sprintf("create dotfile %s/.macnoise_hidden", workDir),
	}
}

func (f *fileHide) Cleanup() error {
	if f.workDir != "" {
		return os.RemoveAll(f.workDir)
	}
	return nil
}

func init() {
	module.Register(&fileHide{})
}
