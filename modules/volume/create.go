// Package volume provides native macOS disk-image operations.
package volume

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/internal/subprocess"
	"github.com/0xv1n/macnoise/pkg/module"
)

const defaultVolumeName = "MacNoiseDelivery"

type ownedImage struct {
	path string
	hash [sha256.Size]byte
}

type volumeCreate struct {
	image ownedImage
}

func (v *volumeCreate) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "volume_create",
		EventTypes:  []string{"volume_image_create"},
		Description: "Creates a read-only disk image from one literal source directory",
		Category:    module.CategoryVolume,
		Tags:        []string{"volume", "disk-image", "dmg", "create"},
		Privileges:  module.PrivilegeNone,
		Author:      "0xv1n",
		MinMacOS:    "12.0",
	}
}

func (v *volumeCreate) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "source_dir", Description: "Literal directory whose contents populate the image", Type: module.ParamPath, Required: true, Example: "/tmp/macnoise_volume_source"},
		{Name: "image_path", Description: "Literal output path (defaults to the private scenario workspace)", Type: module.ParamPath, Default: "", Example: "/tmp/macnoise_delivery.dmg"},
		{Name: "volume_name", Description: "Mounted volume label", Type: module.ParamString, Required: true, Default: defaultVolumeName, Example: "Installer"},
	}
}

func (v *volumeCreate) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{{Name: "path", Description: "Concrete disk-image path created", Type: module.ParamPath}}
}

func (v *volumeCreate) CheckPrereqs(ctx context.Context, params module.Params) error {
	if err := v.ValidateParams(params); err != nil {
		return err
	}
	return prereqs.CheckCommand("hdiutil")
}

func (v *volumeCreate) ValidateParams(params module.Params) error {
	imagePath := params.String("image_path", "")
	if imagePath != "" && !strings.EqualFold(filepath.Ext(imagePath), ".dmg") {
		return fmt.Errorf("image_path must end in .dmg")
	}
	return nil
}

func createArgs(sourceDir, volumeName, imagePath string) []string {
	return []string{"create", "-srcfolder", sourceDir, "-volname", volumeName, "-format", "UDZO", imagePath}
}

func defaultImagePath(ctx context.Context) (string, error) {
	dir := module.WorkspaceFromContext(ctx)
	if dir == "" {
		dir = os.TempDir()
	}
	prefix := "macnoise_volume_"
	if runID := module.RunIDFromContext(ctx); runID != "" {
		prefix += runID + "_"
	}
	f, err := os.CreateTemp(dir, prefix+"*.dmg")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if err := errors.Join(f.Close(), os.Remove(path)); err != nil {
		return "", err
	}
	return path, nil
}

func captureOwnedImage(path string) (ownedImage, error) {
	f, err := os.Open(path)
	if err != nil {
		return ownedImage{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return ownedImage{}, err
	}
	if !info.Mode().IsRegular() {
		return ownedImage{}, fmt.Errorf("%s is not a regular file", path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return ownedImage{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return ownedImage{path: path, hash: digest}, nil
}

func (o ownedImage) remove() error {
	if o.path == "" {
		return nil
	}
	current, err := captureOwnedImage(o.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect owned image %s: %w", o.path, err)
	}
	if current.hash != o.hash {
		return fmt.Errorf("refusing to remove %s: image changed since creation", o.path)
	}
	if err := os.Remove(o.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (v *volumeCreate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := v.ValidateParams(params); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sourceDir := params.String("source_dir", "")
	info, err := os.Stat(sourceDir)
	if err != nil {
		return fmt.Errorf("inspect volume source %s: %w", sourceDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("volume source %s is not a directory", sourceDir)
	}
	imagePath := params.String("image_path", "")
	if imagePath == "" {
		imagePath, err = defaultImagePath(ctx)
		if err != nil {
			return fmt.Errorf("allocate disk-image path: %w", err)
		}
	}
	if _, err := os.Lstat(imagePath); err == nil {
		return fmt.Errorf("refusing to overwrite existing image %s", imagePath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect image path %s: %w", imagePath, err)
	}

	moduleInfo := v.Info()
	ev := output.NewEvent(moduleInfo, "volume_image_create", module.OutcomeError, module.File(imagePath), fmt.Sprintf("creating disk image %s from %s", imagePath, sourceDir))
	result, runErr := subprocess.Run(ctx, "hdiutil", createArgs(sourceDir, params.String("volume_name", defaultVolumeName), imagePath)...)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runErr != nil {
		runErr = fmt.Errorf("hdiutil create: %w: %s", runErr, strings.TrimSpace(string(result.Output)))
		ev = output.WithError(ev, runErr)
		return errors.Join(runErr, emit(ev))
	}
	v.image, err = captureOwnedImage(imagePath)
	if err != nil {
		return errors.Join(fmt.Errorf("capture created image %s: %w", imagePath, err), os.Remove(imagePath))
	}
	ev.Outcome = module.OutcomeExecuted
	ev.Message = fmt.Sprintf("created disk image %s from %s", imagePath, sourceDir)
	ev = output.WithDetails(ev, map[string]any{
		"path":        imagePath,
		"source_dir":  sourceDir,
		"volume_name": params.String("volume_name", defaultVolumeName),
	})
	return errors.Join(emit(ev), module.PublishOutput(ctx, "path", imagePath))
}

func (v *volumeCreate) DryRun(params module.Params) []string {
	imagePath := params.String("image_path", "")
	if imagePath == "" {
		imagePath = "<private workspace image>"
	}
	return []string{"hdiutil " + strings.Join(createArgs(params.String("source_dir", ""), params.String("volume_name", defaultVolumeName), imagePath), " ")}
}

func (v *volumeCreate) Cleanup(ctx context.Context) error {
	err := v.image.remove()
	if err == nil {
		v.image = ownedImage{}
	}
	return err
}

func init() {
	module.Register(func() module.Generator { return &volumeCreate{} })
}
