//go:build unix

package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileCreateExecutableMode(t *testing.T) {
	dir := t.TempDir()
	gen := &fileCreate{}
	params := module.Params{
		"base_dir":   dir,
		"filename":   "install.sh",
		"content":    "#!/bin/sh\nexit 0\n",
		"executable": true,
	}
	ctx, _ := outputContext()
	if err := gen.Generate(ctx, params, func(module.TelemetryEvent) error { return nil }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gen.Cleanup(context.Background()) })

	info, err := os.Stat(filepath.Join(dir, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %#o, want 0755", info.Mode().Perm())
	}
}
