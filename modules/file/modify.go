package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type fileModify struct {
	targetPath  string
	origContent []byte
}

func (f *fileModify) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_modify",
		Description: "Modifies an existing file's content to generate file write/modify telemetry",
		Category:    module.CategoryFile,
		Tags:        []string{"file", "modify", "write"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1565", SubTech: ".001", Name: "Data Manipulation: Stored Data Manipulation"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileModify) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target_path", Description: "File to modify (created if absent)", Required: false, DefaultValue: "/tmp/macnoise_modify_target.txt", Example: "/tmp/test.txt"},
		{Name: "content", Description: "Content to append", Required: false, DefaultValue: "macnoise modification", Example: "injected data"},
	}
}

func (f *fileModify) CheckPrereqs() error { return nil }

func (f *fileModify) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	targetPath := params.Get("target_path", "/tmp/macnoise_modify_target.txt")
	content := params.Get("content", "macnoise modification")
	info := f.Info()

	f.targetPath = targetPath

	orig, err := os.ReadFile(targetPath)
	if os.IsNotExist(err) {
		if err2 := os.MkdirAll(filepath.Dir(targetPath), 0o755); err2 != nil {
			ev := output.NewEvent(info, "file_modify", false, "failed to create parent directory")
			ev = output.WithError(ev, err2)
			emit(ev)
			return err2
		}
		orig = []byte{}
	} else if err != nil {
		ev := output.NewEvent(info, "file_modify", false, fmt.Sprintf("failed to read %s", targetPath))
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	f.origContent = orig

	newContent := append(orig, []byte(fmt.Sprintf("\n%s [%s]", content, time.Now().UTC()))...)
	ev := output.NewEvent(info, "file_modify", false, fmt.Sprintf("modifying %s", targetPath))
	if err := os.WriteFile(targetPath, newContent, 0o644); err != nil {
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	ev.Success = true
	ev.Message = fmt.Sprintf("modified %s (+%d bytes)", targetPath, len(newContent)-len(orig))
	ev = output.WithDetails(ev, map[string]any{
		"path":      targetPath,
		"orig_size": len(orig),
		"new_size":  len(newContent),
	})
	emit(ev)
	return nil
}

func (f *fileModify) DryRun(params module.Params) []string {
	target := params.Get("target_path", "/tmp/macnoise_modify_target.txt")
	content := params.Get("content", "macnoise modification")
	return []string{
		fmt.Sprintf("read original content of %s", target),
		fmt.Sprintf("append %q with timestamp to %s", content, target),
	}
}

func (f *fileModify) Cleanup() error {
	if f.targetPath == "" {
		return nil
	}
	if f.origContent == nil {
		return os.Remove(f.targetPath)
	}
	return os.WriteFile(f.targetPath, f.origContent, 0o644)
}

func init() {
	module.Register(&fileModify{})
}
