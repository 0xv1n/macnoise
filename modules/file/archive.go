package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/internal/subprocess"
	"github.com/0xv1n/macnoise/pkg/module"
)

type fileArchive struct {
	files []ownedFile
	dirs  []ownedDir
}

func (f *fileArchive) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_archive",
		EventTypes:  []string{"archive_create"},
		Description: "Archives one existing literal file or directory without changing the source",
		Category:    module.CategoryFile,
		Tags:        []string{"archive", "zip", "staging", "collection"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1560", SubTech: ".001", Name: "Archive Collected Data: Archive via Utility"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileArchive) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "source_path", Description: "Existing literal file or directory to archive", Type: module.ParamPath, Required: true, Example: "/var/tmp/stage"},
		{Name: "output_path", Description: "Literal output archive path", Type: module.ParamPath, Required: true, Default: "/tmp/macnoise_archive.zip", Example: "/var/tmp/out.zip"},
		{Name: "tool", Description: "Archival tool: zip, ditto, or tar", Type: module.ParamString, Default: "zip", Example: "ditto", Choices: []string{"zip", "ditto", "tar"}},
	}
}

func (f *fileArchive) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{{Name: "path", Description: "Concrete archive path created by this invocation", Type: module.ParamPath}}
}

func (f *fileArchive) CheckPrereqs(ctx context.Context, params module.Params) error {
	if err := f.ValidateParams(params); err != nil {
		return err
	}
	tool := params.String("tool", "zip")
	if !prereqs.HasCommand(tool) {
		return fmt.Errorf("command not found: %s", tool)
	}
	source := params.String("source_path", "/tmp/macnoise_archive_src")
	if _, err := os.Stat(source); err != nil {
		return fmt.Errorf("archive source %s: %w", source, err)
	}
	outputPath := params.String("output_path", "/tmp/macnoise_archive.zip")
	if _, err := os.Lstat(outputPath); err == nil {
		return fmt.Errorf("archive output already exists: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (f *fileArchive) ValidateParams(params module.Params) error {
	sourcePath := params.String("source_path", "/tmp/macnoise_archive_src")
	outputPath := params.String("output_path", "/tmp/macnoise_archive.zip")
	sourceAbs, err := filepath.Abs(sourcePath)
	if err != nil {
		return err
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(sourceAbs, outputAbs)
	if err != nil {
		return err
	}
	if rel == "." {
		return errors.New("source_path and output_path must differ")
	}
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("archive output must be outside source path %s", sourcePath)
	}
	return nil
}

func (f *fileArchive) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := f.ValidateParams(params); err != nil {
		return err
	}
	sourcePath := params.String("source_path", "/tmp/macnoise_archive_src")
	outputPath := params.String("output_path", "/tmp/macnoise_archive.zip")
	tool := params.String("tool", "zip")
	info := f.Info()

	if _, err := os.Stat(sourcePath); err != nil {
		return fmt.Errorf("archive source %s: %w", sourcePath, err)
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return fmt.Errorf("archive output already exists: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	createdDirs, err := ensureDirs(filepath.Dir(outputPath), 0o700)
	f.dirs = append(f.dirs, createdDirs...)
	if err != nil {
		return err
	}

	tempPath, err := reserveArchivePath(filepath.Dir(outputPath), outputPath, tool)
	if err != nil {
		return err
	}
	args := archiveArgs(tool, sourcePath, tempPath)
	ev := output.NewEvent(info, "archive_create", module.OutcomeError, module.File(outputPath), fmt.Sprintf("archiving %s to %s via %s", sourcePath, outputPath, tool))
	result, runErr := subprocess.Run(ctx, tool, args...)
	if ctx.Err() != nil {
		f.capturePartial(tempPath)
		return errors.Join(runErr, ctx.Err())
	}
	if runErr != nil {
		f.capturePartial(tempPath)
		ev = output.WithError(ev, fmt.Errorf("%w: %s", runErr, strings.TrimSpace(string(result.Output))))
		return errors.Join(runErr, emit(ev))
	}

	tempFile, err := captureOwnedFile(tempPath)
	if err != nil {
		return err
	}
	if err := os.Link(tempPath, outputPath); err != nil {
		f.files = append(f.files, tempFile)
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}
	outputFile := ownedFile{path: outputPath, info: tempFile.info, hash: tempFile.hash}
	f.files = append(f.files, outputFile)
	if err := os.Remove(tempPath); err != nil {
		f.files = append(f.files, tempFile)
		return err
	}
	ev.Outcome = module.OutcomeExecuted
	ev.Message = fmt.Sprintf("archive created: %s (%d bytes) via %s", outputPath, outputFile.info.Size(), tool)
	ev = output.WithDetails(ev, map[string]any{
		"source_path":  sourcePath,
		"output_path":  outputPath,
		"tool":         tool,
		"archive_size": outputFile.info.Size(),
	})
	return errors.Join(module.PublishOutput(ctx, "path", outputPath), emit(ev))
}

func archiveArgs(tool, sourcePath, outputPath string) []string {
	switch tool {
	case "ditto":
		return []string{"-c", "-k", "--sequesterRsrc", sourcePath, outputPath}
	case "tar":
		return []string{"-czf", outputPath, "-C", filepath.Dir(sourcePath), filepath.Base(sourcePath)}
	default:
		return []string{"-r", outputPath, sourcePath}
	}
}

func reserveArchivePath(dir, outputPath, tool string) (string, error) {
	suffix := filepath.Ext(outputPath)
	if tool == "zip" && suffix == "" {
		suffix = ".zip"
	}
	f, err := os.CreateTemp(dir, ".macnoise-archive-*"+suffix)
	if err != nil {
		return "", err
	}
	path := f.Name()
	if err := errors.Join(f.Close(), os.Remove(path)); err != nil {
		return "", err
	}
	return path, nil
}

func (f *fileArchive) capturePartial(path string) {
	owned, err := captureOwnedFile(path)
	if err == nil {
		f.files = append(f.files, owned)
	}
}

func (f *fileArchive) DryRun(params module.Params) []string {
	tool := params.String("tool", "zip")
	return []string{tool + " " + strings.Join(archiveArgs(tool,
		params.String("source_path", "/tmp/macnoise_archive_src"),
		params.String("output_path", "/tmp/macnoise_archive.zip")), " ")}
}

func (f *fileArchive) Cleanup(ctx context.Context) error {
	err := errors.Join(removeOwnedFiles(f.files), removeOwnedDirs(f.dirs))
	f.files = nil
	f.dirs = nil
	return err
}

func init() {
	module.Register(func() module.Generator { return &fileArchive{} })
}
