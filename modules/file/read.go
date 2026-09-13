package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type fileRead struct{}

func (f *fileRead) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_read",
		EventTypes:  []string{"file_probe", "file_read"},
		Description: "Reads literal regular-file paths and discards their contents",
		Category:    module.CategoryFile,
		Tags:        []string{"file", "read", "collection"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1005", Name: "Data from Local System"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileRead) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{{
		Name:        "paths",
		Description: "Literal regular-file paths to read",
		Type:        module.ParamPathList,
		Required:    true,
		Example:     []string{"/Users/dev/Documents/report.txt"},
	}}
}

func (f *fileRead) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{{Name: "paths", Description: "Concrete paths read successfully", Type: module.ParamPathList}}
}

func (f *fileRead) CheckPrereqs(ctx context.Context, params module.Params) error {
	return f.ValidateParams(params)
}

func (f *fileRead) ValidateParams(params module.Params) error {
	if len(params.Paths("paths", nil)) > maxFileTargets {
		return fmt.Errorf("paths contains more than %d targets", maxFileTargets)
	}
	return nil
}

func (f *fileRead) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := f.ValidateParams(params); err != nil {
		return err
	}
	info := f.Info()
	readPaths := make([]string, 0, len(params.Paths("paths", nil)))
	var resultErr error
	for _, path := range params.Paths("paths", nil) {
		if err := ctx.Err(); err != nil {
			return errors.Join(resultErr, err)
		}
		n, readErr := readCredFile(path)
		var ev module.TelemetryEvent
		switch {
		case os.IsNotExist(readErr):
			ev = output.NewEvent(info, "file_probe", module.OutcomeIndeterminate, module.File(path), fmt.Sprintf("file not present: %s", path))
			ev = output.WithDetails(ev, map[string]any{"path": path, "exists": false})
		case errors.Is(readErr, errNotRegularFile):
			ev = output.NewEvent(info, "file_probe", module.OutcomeIndeterminate, module.File(path), fmt.Sprintf("path is not a regular file: %s", path))
			ev = output.WithDetails(ev, map[string]any{"path": path, "exists": true, "regular": false})
		case os.IsPermission(readErr):
			ev = output.NewEvent(info, "file_read", module.OutcomeDenied, module.File(path), fmt.Sprintf("file read denied: %s", path))
			ev = output.WithOutcome(ev, module.OutcomeDenied, readErr)
			ev = output.WithDetails(ev, map[string]any{"path": path, "exists": true, "accessible": false})
		case readErr != nil:
			ev = output.NewEvent(info, "file_read", module.OutcomeError, module.File(path), fmt.Sprintf("file read failed: %s", path))
			ev = output.WithError(ev, readErr)
			resultErr = errors.Join(resultErr, readErr)
		default:
			ev = output.NewEvent(info, "file_read", module.OutcomeExecuted, module.File(path), fmt.Sprintf("read %s (%d bytes)", path, n))
			ev = output.WithDetails(ev, map[string]any{"path": path, "exists": true, "accessible": true, "bytes_read": n})
			readPaths = append(readPaths, path)
		}
		resultErr = errors.Join(resultErr, emit(ev))
	}
	return errors.Join(resultErr, module.PublishOutput(ctx, "paths", readPaths))
}

func (f *fileRead) DryRun(params module.Params) []string {
	paths := params.Paths("paths", nil)
	if len(paths) == 0 {
		return []string{"read no files (empty literal path list)"}
	}
	return []string{"open and read literal paths, discarding contents: " + strings.Join(paths, ", ")}
}

func (f *fileRead) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &fileRead{} })
}
