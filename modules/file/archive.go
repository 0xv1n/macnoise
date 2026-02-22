package file

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/pkg/module"
)

type fileArchive struct {
	sourceDir  string
	outputPath string
}

func (f *fileArchive) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_archive",
		Description: "Creates an archive of staged files to generate archive creation telemetry",
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
		{Name: "source_dir", Description: "Directory to archive", Required: false, DefaultValue: "/tmp/macnoise_archive_src", Example: "/var/tmp/stage"},
		{Name: "output_path", Description: "Output archive path", Required: false, DefaultValue: "/tmp/macnoise_archive.zip", Example: "/var/tmp/out.zip"},
		{Name: "tool", Description: "Archival tool: zip, ditto, or tar", Required: false, DefaultValue: "zip", Example: "ditto"},
	}
}

func (f *fileArchive) CheckPrereqs() error { return nil }

func (f *fileArchive) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	sourceDir := params.Get("source_dir", "/tmp/macnoise_archive_src")
	outputPath := params.Get("output_path", "/tmp/macnoise_archive.zip")
	tool := params.Get("tool", "zip")
	f.sourceDir = sourceDir
	f.outputPath = outputPath
	info := f.Info()

	if !prereqs.HasCommand(tool) {
		ev := output.NewEvent(info, "archive_create", false, fmt.Sprintf("required tool %q not found in PATH", tool))
		ev = output.WithError(ev, fmt.Errorf("command not found: %s", tool))
		emit(ev)
		return fmt.Errorf("command not found: %s", tool)
	}

	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", sourceDir, err)
	}
	for i := 0; i < 3; i++ {
		fpath := filepath.Join(sourceDir, fmt.Sprintf("staged_%d.txt", i))
		content := fmt.Sprintf("macnoise staged data file %d\n", i)
		if err := os.WriteFile(fpath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", fpath, err)
		}
	}

	var archiveCmd *exec.Cmd
	switch tool {
	case "ditto":
		archiveCmd = exec.CommandContext(ctx, "ditto", "-c", "-k", "--sequesterRsrc", sourceDir, outputPath)
	case "tar":
		archiveCmd = exec.CommandContext(ctx, "tar", "-czf", outputPath, "-C", filepath.Dir(sourceDir), filepath.Base(sourceDir))
	default:
		archiveCmd = exec.CommandContext(ctx, "zip", "-r", outputPath, sourceDir)
	}

	ev := output.NewEvent(info, "archive_create", false, fmt.Sprintf("archiving %s → %s via %s", sourceDir, outputPath, tool))
	archiveOut, archiveErr := archiveCmd.CombinedOutput()
	if archiveErr != nil {
		ev = output.WithError(ev, fmt.Errorf("%v: %s", archiveErr, archiveOut))
		emit(ev)
		return archiveErr
	}

	var archiveSize int64
	if fi, err := os.Stat(outputPath); err == nil {
		archiveSize = fi.Size()
	}

	ev.Success = true
	ev.Message = fmt.Sprintf("archive created: %s (%d bytes) via %s", outputPath, archiveSize, tool)
	ev = output.WithDetails(ev, map[string]any{
		"source_dir":   sourceDir,
		"output_path":  outputPath,
		"tool":         tool,
		"archive_size": archiveSize,
	})
	emit(ev)
	return nil
}

func (f *fileArchive) DryRun(params module.Params) []string {
	sourceDir := params.Get("source_dir", "/tmp/macnoise_archive_src")
	outputPath := params.Get("output_path", "/tmp/macnoise_archive.zip")
	tool := params.Get("tool", "zip")
	return []string{
		fmt.Sprintf("mkdir -p %s && create 3 staged files", sourceDir),
		fmt.Sprintf("%s -r %s %s", tool, outputPath, sourceDir),
	}
}

func (f *fileArchive) Cleanup() error {
	var lastErr error
	if f.outputPath != "" {
		if err := os.Remove(f.outputPath); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	if f.sourceDir != "" {
		if err := os.RemoveAll(f.sourceDir); err != nil && !os.IsNotExist(err) {
			lastErr = err
		}
	}
	return lastErr
}

func init() {
	module.Register(&fileArchive{})
}
