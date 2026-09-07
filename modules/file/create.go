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
		EventTypes:  []string{"dir_create", "file_create"},
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
		{Name: "filename", Description: "Exact name for a single file (overrides count and prefix)", Required: false, Example: "RECOVER_YOUR_FILES.txt"},
		{Name: "content", Description: "Contents for a named file", Required: false, Example: "Your files have been encrypted."},
	}
}

func (f *fileCreate) CheckPrereqs() error { return nil }

// stampedFileName builds the file name, folding the run ID in after the prefix
// when one is set so a consumer can correlate the file back to the run.
func stampedFileName(prefix, runID, ts string, i int) string {
	if runID != "" {
		return fmt.Sprintf("%s%s_%s%d.txt", prefix, runID, ts, i)
	}
	return fmt.Sprintf("%s%s%d.txt", prefix, ts, i)
}

func (f *fileCreate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	baseDir := params.Get("base_dir", "/tmp/macnoise_test")
	countStr := params.Get("count", "3")
	prefix := params.Get("prefix", "mnfile_")
	filename := params.Get("filename", "")
	content := params.Get("content", "")
	runID := module.RunIDFromContext(ctx)

	count := 3
	fmt.Sscanf(countStr, "%d", &count) //nolint:errcheck

	info := f.Info()

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		ev := output.NewEvent(info, "dir_create", false, fmt.Sprintf("failed to create directory %s", baseDir))
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}

	if filename != "" {
		if filepath.Base(filename) != filename {
			return fmt.Errorf("filename must not include a directory: %q", filename)
		}
		count = 1
	}

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fname := filename
		if fname == "" {
			fname = stampedFileName(prefix, runID, time.Now().Format("20060102_150405"), i)
		}
		fpath := filepath.Join(baseDir, fname)
		fileContent := content
		if fileContent == "" {
			fileContent = fmt.Sprintf("MacNoise telemetry file %d created at %s\n", i, time.Now().UTC())
		}

		ev := output.NewEvent(info, "file_create", false, fmt.Sprintf("creating %s", fpath))
		if err := os.WriteFile(fpath, []byte(fileContent), 0o644); err != nil {
			ev = output.WithError(ev, err)
			emit(ev)
			continue
		}
		f.createdPaths = append(f.createdPaths, fpath)
		ev.Success = true
		ev.Message = fmt.Sprintf("created %s (%d bytes)", fpath, len(fileContent))
		ev = output.WithDetails(ev, map[string]any{"path": fpath, "size": len(fileContent)})
		emit(ev)
	}
	return nil
}

func (f *fileCreate) DryRun(params module.Params) []string {
	baseDir := params.Get("base_dir", "/tmp/macnoise_test")
	countStr := params.Get("count", "3")
	prefix := params.Get("prefix", "mnfile_")
	filename := params.Get("filename", "")
	if filename != "" {
		return []string{
			fmt.Sprintf("mkdir -p %s", baseDir),
			fmt.Sprintf("create %s in %s", filename, baseDir),
		}
	}
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
