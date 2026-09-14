package volume

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestCreateArgsUseLiteralSourceAndDoNotOverwrite(t *testing.T) {
	args := createArgs("/tmp/source dir", "Delivery Disk", "/tmp/out.dmg")
	joined := strings.Join(args, "\n")
	for _, want := range []string{"-srcfolder\n/tmp/source dir", "-volname\nDelivery Disk", "-format\nUDZO", "/tmp/out.dmg"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	if strings.Contains(joined, "-ov") {
		t.Fatalf("create args permit overwrite: %v", args)
	}
}

func TestOwnedImageCleanupRefusesChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.dmg")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	owned, err := captureOwnedImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := owned.remove(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("remove = %v, want changed-file conflict", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("changed image was removed: %v", err)
	}
}

func TestVolumeCreateCleanupIsNoOpBeforeCreation(t *testing.T) {
	if err := (&volumeCreate{}).Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestVolumeCreateRejectsPathHdiutilWouldRename(t *testing.T) {
	err := (&volumeCreate{}).ValidateParams(map[string]any{"image_path": "/tmp/image"})
	if err == nil || !strings.Contains(err.Error(), ".dmg") {
		t.Fatalf("ValidateParams = %v, want .dmg error", err)
	}
}

func TestDefaultImagePathsAreIndependent(t *testing.T) {
	ctx := module.ContextWithWorkspace(context.Background(), t.TempDir())
	first, err := defaultImagePath(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := defaultImagePath(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("default image paths collided at %s", first)
	}
}

func TestVolumeCreateRefusesExistingImageBeforeExecution(t *testing.T) {
	dir := t.TempDir()
	imagePath := filepath.Join(dir, "existing.dmg")
	if err := os.WriteFile(imagePath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := (&volumeCreate{}).Generate(context.Background(), module.Params{
		"source_dir":  dir,
		"image_path":  imagePath,
		"volume_name": defaultVolumeName,
	}, func(module.TelemetryEvent) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("Generate = %v, want overwrite refusal", err)
	}
	content, readErr := os.ReadFile(imagePath)
	if readErr != nil || string(content) != "keep" {
		t.Fatalf("existing image changed: %q, %v", content, readErr)
	}
}
