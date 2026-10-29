package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/ownership"
	"github.com/0xv1n/macnoise/pkg/module"
)

var errCopyDestination = errors.New("copy destination failed")

type fileCopy struct {
	files       []ownership.File
	dirs        []ownership.Directory
	destination string
}

func (f *fileCopy) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_copy",
		EventTypes:  []string{"file_read", "file_copy"},
		Description: "Copies literal regular-file paths into one staging directory",
		Category:    module.CategoryFile,
		Tags:        []string{"file", "copy", "staging", "collection"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1005", Name: "Data from Local System"},
			{Technique: "T1074", SubTech: ".001", Name: "Data Staged: Local Data Staging"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileCopy) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "source_paths", Description: "Literal regular-file paths to copy", Type: module.ParamPathList, Required: true, Example: []string{"/Users/dev/Documents/report.txt"}},
		{Name: "destination_dir", Description: "Literal directory for staged copies", Type: module.ParamPath, Required: true, Default: "/tmp/macnoise_copy", Example: "/var/tmp/macnoise_stage"},
	}
}

func (f *fileCopy) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{
		{Name: "paths", Description: "Concrete paths copied successfully", Type: module.ParamPathList},
		{Name: "directory", Description: "Literal staging directory", Type: module.ParamPath},
	}
}

func (f *fileCopy) CheckPrereqs(ctx context.Context, params module.Params) error {
	return f.ValidateParams(params)
}

func (f *fileCopy) ValidateParams(params module.Params) error {
	sources := params.Paths("source_paths", nil)
	if len(sources) > maxFileTargets {
		return fmt.Errorf("source_paths contains more than %d targets", maxFileTargets)
	}
	seen := make(map[string]string, len(sources))
	for _, source := range sources {
		base := filepath.Base(source)
		key := strings.ToLower(base)
		if prior, ok := seen[key]; ok {
			return fmt.Errorf("source paths %s and %s have the same destination name %q", prior, source, base)
		}
		seen[key] = source
	}
	return nil
}

func (f *fileCopy) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := f.ValidateParams(params); err != nil {
		return err
	}
	info := f.Info()
	f.destination = params.String("destination_dir", "/tmp/macnoise_copy")
	sources := params.Paths("source_paths", nil)
	if len(sources) > 0 {
		createdDirs, err := ownership.EnsureDirectories(f.destination, 0o700)
		f.dirs = append(f.dirs, createdDirs...)
		if err != nil {
			return err
		}
	}

	var resultErr error
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return errors.Join(resultErr, err)
		}
		destination := filepath.Join(f.destination, filepath.Base(source))
		n, owned, copyErr := copyOwnedFile(source, destination)
		switch {
		case os.IsNotExist(copyErr):
			ev := output.NewEvent(info, "file_read", module.OutcomeIndeterminate, module.File(source), fmt.Sprintf("copy source not present: %s", source))
			ev = output.WithDetails(ev, map[string]any{"path": source, "exists": false})
			resultErr = errors.Join(resultErr, emit(ev))
			continue
		case errors.Is(copyErr, errNotRegularFile):
			ev := output.NewEvent(info, "file_read", module.OutcomeIndeterminate, module.File(source), fmt.Sprintf("copy source is not a regular file: %s", source))
			ev = output.WithDetails(ev, map[string]any{"path": source, "exists": true, "regular": false})
			resultErr = errors.Join(resultErr, emit(ev))
			continue
		case os.IsPermission(copyErr) && !errors.Is(copyErr, errCopyDestination):
			ev := output.NewEvent(info, "file_read", module.OutcomeDenied, module.File(source), fmt.Sprintf("copy source read denied: %s", source))
			ev = output.WithOutcome(ev, module.OutcomeDenied, copyErr)
			resultErr = errors.Join(resultErr, emit(ev))
			continue
		case copyErr != nil:
			ev := output.NewEvent(info, "file_copy", module.OutcomeError, module.File(destination), fmt.Sprintf("copy failed: %s to %s", source, destination))
			ev = output.WithError(ev, copyErr)
			resultErr = errors.Join(resultErr, copyErr, emit(ev))
			continue
		}

		f.files = append(f.files, owned)
		readEvent := output.NewEvent(info, "file_read", module.OutcomeExecuted, module.File(source), fmt.Sprintf("read %s (%d bytes)", source, n))
		readEvent = output.WithDetails(readEvent, map[string]any{"path": source, "bytes_read": n})
		copyEvent := output.NewEvent(info, "file_copy", module.OutcomeExecuted, module.File(destination), fmt.Sprintf("copied %s to %s", source, destination))
		copyEvent = output.WithDetails(copyEvent, map[string]any{"source_path": source, "destination_path": destination, "bytes_copied": n})
		resultErr = errors.Join(resultErr, emit(readEvent), emit(copyEvent))
	}

	paths := make([]string, len(f.files))
	for index, file := range f.files {
		paths[index] = file.Path()
	}
	return errors.Join(resultErr,
		module.PublishOutput(ctx, "paths", paths),
		module.PublishOutput(ctx, "directory", f.destination),
	)
}

func copyOwnedFile(source, destination string) (int64, ownership.File, error) {
	in, err := openRegularFile(source)
	if err != nil {
		return 0, ownership.File{}, err
	}
	defer func() { _ = in.Close() }()

	owned, err := ownership.CreateFileFrom(destination, in, 0o600)
	if err != nil {
		return 0, ownership.File{}, fmt.Errorf("%w: %w", errCopyDestination, err)
	}
	return owned.Size(), owned, nil
}

func (f *fileCopy) DryRun(params module.Params) []string {
	return []string{fmt.Sprintf("copy literal regular files into %s without overwriting: %s",
		params.String("destination_dir", "/tmp/macnoise_copy"), strings.Join(params.Paths("source_paths", nil), ", "))}
}

func (f *fileCopy) Cleanup(ctx context.Context) error {
	err := errors.Join(ownership.RemoveFiles(f.files), ownership.RemoveDirectories(f.dirs))
	f.files = nil
	f.dirs = nil
	return err
}

func init() {
	module.Register(func() module.Generator { return &fileCopy{} })
}
