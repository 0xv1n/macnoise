package file

import (
	"context"
	"errors"
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
	origMode    os.FileMode
	existed     bool
	version     ownedFile
	dirs        []ownedDir
}

func (f *fileModify) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_modify",
		EventTypes:  []string{"file_modify"},
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
		{Name: "target_path", Description: "File to modify (created if absent)", Type: module.ParamPath, Required: true, Default: "/tmp/macnoise_modify_target.txt", Example: "/tmp/test.txt"},
		{Name: "content", Description: "Content to append", Type: module.ParamString, Default: "macnoise modification", Example: "injected data"},
	}
}

func (f *fileModify) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (f *fileModify) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{{Name: "path", Description: "Concrete path modified by this invocation", Type: module.ParamPath}}
}

func (f *fileModify) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	targetPath := params.String("target_path", "/tmp/macnoise_modify_target.txt")
	content := params.String("content", "macnoise modification")
	info := f.Info()

	f.targetPath = targetPath

	orig, err := os.ReadFile(targetPath)
	switch {
	case os.IsNotExist(err):
		createdDirs, err2 := ensureDirs(filepath.Dir(targetPath), 0o755)
		f.dirs = append(f.dirs, createdDirs...)
		if err2 != nil {
			ev := output.NewEvent(info, "file_modify", module.OutcomeError, module.File(targetPath), "failed to create parent directory")
			ev = output.WithError(ev, err2)
			return errors.Join(err2, emit(ev))
		}
		orig = []byte{}
		f.existed = false
	case err != nil:
		ev := output.NewEvent(info, "file_modify", module.OutcomeError, module.File(targetPath), fmt.Sprintf("failed to read %s", targetPath))
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	default:
		f.existed = true
		fileInfo, statErr := os.Stat(targetPath)
		if statErr != nil {
			return statErr
		}
		f.origMode = fileInfo.Mode().Perm()
	}
	f.origContent = orig

	newContent := append(append([]byte(nil), orig...), []byte(fmt.Sprintf("\n%s [%s]", content, time.Now().UTC()))...)
	ev := output.NewEvent(info, "file_modify", module.OutcomeError, module.File(targetPath), fmt.Sprintf("modifying %s", targetPath))
	if f.existed {
		err = os.WriteFile(targetPath, newContent, f.origMode)
		var captureErr error
		f.version, captureErr = captureOwnedFile(targetPath)
		err = errors.Join(err, captureErr)
	} else {
		f.version, err = createOwnedFile(targetPath, newContent, 0o644)
	}
	if err != nil {
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}
	ev.Outcome = module.OutcomeExecuted
	ev.Message = fmt.Sprintf("modified %s (+%d bytes)", targetPath, len(newContent)-len(orig))
	ev = output.WithDetails(ev, map[string]any{
		"path":      targetPath,
		"orig_size": len(orig),
		"new_size":  len(newContent),
	})
	return errors.Join(module.PublishOutput(ctx, "path", targetPath), emit(ev))
}

func (f *fileModify) DryRun(params module.Params) []string {
	target := params.String("target_path", "/tmp/macnoise_modify_target.txt")
	content := params.String("content", "macnoise modification")
	return []string{
		fmt.Sprintf("read original content of %s", target),
		fmt.Sprintf("append %q with timestamp to %s", content, target),
	}
}

func (f *fileModify) Cleanup(ctx context.Context) error {
	if f.targetPath == "" {
		return nil
	}
	if f.existed {
		if _, err := os.Stat(f.targetPath); os.IsNotExist(err) {
			return fmt.Errorf("cleanup conflict: %s was removed after macnoise modified it", f.targetPath)
		} else if err != nil {
			return err
		}
		if err := f.version.verifyCurrent(); err != nil {
			return err
		}
		if err := os.WriteFile(f.targetPath, f.origContent, f.origMode); err != nil {
			return err
		}
		f.targetPath = ""
		f.origContent = nil
		f.version = ownedFile{}
		return nil
	}
	return errors.Join(removeOwnedFile(f.version), removeOwnedDirs(f.dirs))
}

func init() {
	module.Register(func() module.Generator { return &fileModify{} })
}
