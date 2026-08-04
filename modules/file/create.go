// Package file provides telemetry modules for file system activity simulation,
// covering file creation and modification patterns that trigger EDR file events.
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

type fileCreate struct {
	createdPaths []string
}

func (f *fileCreate) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_create",
		Description: "Creates files in a target directory to generate file creation telemetry",
		Category:    module.CategoryFile,
		Tags:        []string{"file", "create", "write"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1074", SubTech: ".001", Name: "Data Staged: Local Data Staging"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileCreate) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "base_dir", Description: "Directory to create files in", Required: false, DefaultValue: "/tmp/macnoise_test", Example: "/var/tmp/macnoise"},
		{Name: "count", Description: "Number of files to create", Required: false, DefaultValue: "3", Example: "10"},
		{Name: "prefix", Description: "File name prefix", Required: false, DefaultValue: "mnfile_", Example: "test_"},
	}
}

func (f *fileCreate) CheckPrereqs() error { return nil }

func (f *fileCreate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	baseDir := params.Get("base_dir", "/tmp/macnoise_test")
	countStr := params.Get("count", "3")
	prefix := params.Get("prefix", "mnfile_")

	count := 3
	fmt.Sscanf(countStr, "%d", &count) //nolint:errcheck

	info := f.Info()

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		ev := output.NewEvent(info, "dir_create", false, fmt.Sprintf("failed to create directory %s", baseDir))
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fname := fmt.Sprintf("%s%s%d.txt", prefix, time.Now().Format("20060102_150405"), i)
		fpath := filepath.Join(baseDir, fname)
		content := fmt.Sprintf("MacNoise telemetry file %d created at %s\n", i, time.Now().UTC())

		ev := output.NewEvent(info, "file_create", false, fmt.Sprintf("creating %s", fpath))
		if err := os.WriteFile(fpath, []byte(content), 0o644); err != nil {
			ev = output.WithError(ev, err)
			emit(ev)
			continue
		}
		f.createdPaths = append(f.createdPaths, fpath)
		ev.Success = true
		ev.Message = fmt.Sprintf("created %s (%d bytes)", fpath, len(content))
		ev = output.WithDetails(ev, map[string]any{"path": fpath, "size": len(content)})
		emit(ev)
	}
	return nil
}

func (f *fileCreate) DryRun(params module.Params) []string {
	baseDir := params.Get("base_dir", "/tmp/macnoise_test")
	countStr := params.Get("count", "3")
	prefix := params.Get("prefix", "mnfile_")
	return []string{
		fmt.Sprintf("mkdir -p %s", baseDir),
		fmt.Sprintf("create %s files with prefix %q in %s", countStr, prefix, baseDir),
	}
}

func (f *fileCreate) Cleanup() error {
	var lastErr error
	for _, p := range f.createdPaths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	f.createdPaths = nil
	return lastErr
}

func init() {
	module.Register(&fileCreate{})
}
