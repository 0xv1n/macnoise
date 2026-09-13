// Package file provides telemetry modules for file system activity simulation,
// covering file creation and modification patterns that trigger EDR file events.
package file

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type fileCreate struct {
	files []ownedFile
	dirs  []ownedDir
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
		{Name: "base_dir", Description: "Directory to create files in", Type: module.ParamPath, Required: true, Default: "/tmp/macnoise_test", Example: "/var/tmp/macnoise"},
		{Name: "count", Description: "Number of files to create", Type: module.ParamInteger, Default: 3, Example: 10, Range: &module.IntegerRange{Min: 1, Max: 100}},
		{Name: "prefix", Description: "File name prefix", Type: module.ParamString, Default: "mnfile_", Example: "test_"},
		{Name: "filename", Description: "Exact name for a single file (overrides count and prefix)", Type: module.ParamString, Example: "RECOVER_YOUR_FILES.txt"},
		{Name: "content", Description: "Contents for a named file", Type: module.ParamString, Example: "Your files have been encrypted."},
	}
}

func (f *fileCreate) ValidateParams(params module.Params) error {
	filename := params.String("filename", "")
	if filename != "" && (filepath.Base(filename) != filename || filename == "." || filename == "..") {
		return fmt.Errorf("filename must not include a directory: %q", filename)
	}
	prefix := params.String("prefix", "mnfile_")
	if filepath.Base(prefix) != prefix || prefix == "." || prefix == ".." {
		return fmt.Errorf("prefix must not include a directory: %q", prefix)
	}
	return nil
}

func (f *fileCreate) CheckPrereqs(ctx context.Context, params module.Params) error {
	return f.ValidateParams(params)
}

func (f *fileCreate) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{
		{Name: "path", Description: "First concrete path created by this invocation", Type: module.ParamPath},
		{Name: "paths", Description: "Concrete paths created by this invocation", Type: module.ParamPathList},
		{Name: "directory", Description: "Literal directory containing the created files", Type: module.ParamPath},
		{Name: "directories", Description: "Literal directory as a path list for bounded discovery", Type: module.ParamPathList},
	}
}

// stampedFileName builds the file name, folding the run ID in after the prefix
// when one is set so a consumer can correlate the file back to the run.
func stampedFileName(prefix, runID, ts string, i int) string {
	if runID != "" {
		return fmt.Sprintf("%s%s_%s%d.txt", prefix, runID, ts, i)
	}
	return fmt.Sprintf("%s%s%d.txt", prefix, ts, i)
}

func (f *fileCreate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := f.ValidateParams(params); err != nil {
		return err
	}
	baseDir := params.String("base_dir", "/tmp/macnoise_test")
	count := params.Int("count", 3)
	prefix := params.String("prefix", "mnfile_")
	filename := params.String("filename", "")
	content := params.String("content", "")
	runID := module.RunIDFromContext(ctx)

	info := f.Info()

	createdDirs, err := ensureDirs(baseDir, 0o755)
	f.dirs = append(f.dirs, createdDirs...)
	if err != nil {
		ev := output.NewEvent(info, "dir_create", module.OutcomeError, module.File(baseDir), fmt.Sprintf("failed to create directory %s", baseDir))
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}

	if filename != "" {
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

		ev := output.NewEvent(info, "file_create", module.OutcomeError, module.File(fpath), fmt.Sprintf("creating %s", fpath))
		owned, err := createOwnedFile(fpath, []byte(fileContent), 0o644)
		if err != nil {
			ev = output.WithError(ev, err)
			return errors.Join(err, emit(ev))
		}
		f.files = append(f.files, owned)
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("created %s (%d bytes)", fpath, len(fileContent))
		ev = output.WithDetails(ev, map[string]any{"path": fpath, "size": len(fileContent)})
		if err := emit(ev); err != nil {
			return err
		}
	}
	paths := make([]string, len(f.files))
	for index, file := range f.files {
		paths[index] = file.path
	}
	return errors.Join(
		module.PublishOutput(ctx, "path", paths[0]),
		module.PublishOutput(ctx, "paths", paths),
		module.PublishOutput(ctx, "directory", baseDir),
		module.PublishOutput(ctx, "directories", []string{baseDir}),
	)
}

func (f *fileCreate) DryRun(params module.Params) []string {
	baseDir := params.String("base_dir", "/tmp/macnoise_test")
	count := params.Int("count", 3)
	prefix := params.String("prefix", "mnfile_")
	filename := params.String("filename", "")
	if filename != "" {
		return []string{
			fmt.Sprintf("mkdir -p %s", baseDir),
			fmt.Sprintf("create %s in %s", filename, baseDir),
		}
	}
	return []string{
		fmt.Sprintf("mkdir -p %s", baseDir),
		fmt.Sprintf("create %d files with prefix %q in %s", count, prefix, baseDir),
	}
}

func (f *fileCreate) Cleanup(ctx context.Context) error {
	err := errors.Join(removeOwnedFiles(f.files), removeOwnedDirs(f.dirs))
	f.files = nil
	f.dirs = nil
	return err
}

func init() {
	module.Register(func() module.Generator { return &fileCreate{} })
}
