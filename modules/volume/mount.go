package volume

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/internal/subprocess"
	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

type attachResult struct {
	device     string
	mountPoint string
}

type volumeMount struct {
	device     string
	mountPoint string
}

func (v *volumeMount) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "volume_mount",
		EventTypes:  []string{"volume_mount"},
		Description: "Mounts one literal disk image read-only and publishes the observed mount point",
		Category:    module.CategoryVolume,
		Tags:        []string{"volume", "disk-image", "dmg", "mount"},
		Privileges:  module.PrivilegeNone,
		Author:      "0xv1n",
		MinMacOS:    "12.0",
	}
}

func (v *volumeMount) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{{Name: "image_path", Description: "Literal disk-image path to mount", Type: module.ParamPath, Required: true, Example: "/tmp/macnoise_delivery.dmg"}}
}

func (v *volumeMount) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{
		{Name: "mount_point", Description: "Observed mounted-volume path", Type: module.ParamPath},
		{Name: "device", Description: "Observed whole-disk device node", Type: module.ParamPath},
	}
}

func (v *volumeMount) CheckPrereqs(ctx context.Context, params module.Params) error {
	return prereqs.CheckCommand("hdiutil")
}

func attachArgs(imagePath string) []string {
	return []string{"attach", "-plist", "-nobrowse", "-readonly", imagePath}
}

func detachArgs(device string) []string {
	return []string{"detach", device, "-force"}
}

func parseAttachPlist(data []byte) (attachResult, error) {
	var response struct {
		Entities []struct {
			Device     string `plist:"dev-entry"`
			MountPoint string `plist:"mount-point"`
		} `plist:"system-entities"`
	}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&response); err != nil {
		return attachResult{}, err
	}
	var result attachResult
	var mountedDevice string
	for _, entity := range response.Entities {
		if result.device == "" && entity.Device != "" && entity.MountPoint == "" {
			result.device = entity.Device
		}
		if result.mountPoint == "" && entity.MountPoint != "" {
			result.mountPoint = entity.MountPoint
			mountedDevice = entity.Device
		}
	}
	if result.device == "" {
		result.device = wholeDiskDevice(mountedDevice)
	}
	if result.device == "" || result.mountPoint == "" {
		return attachResult{}, fmt.Errorf("attach response did not contain a device and mount point")
	}
	return result, nil
}

func wholeDiskDevice(device string) string {
	const prefix = "/dev/disk"
	if !strings.HasPrefix(device, prefix) {
		return device
	}
	end := len(prefix)
	for end < len(device) && device[end] >= '0' && device[end] <= '9' {
		end++
	}
	if end == len(prefix) {
		return device
	}
	return device[:end]
}

func (v *volumeMount) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	imagePath := params.String("image_path", "")
	info, err := os.Stat(imagePath)
	if err != nil {
		return fmt.Errorf("inspect disk image %s: %w", imagePath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("disk image %s is not a regular file", imagePath)
	}

	result, runErr := subprocess.Run(ctx, "hdiutil", attachArgs(imagePath)...)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runErr != nil {
		runErr = fmt.Errorf("hdiutil attach: %w: %s", runErr, strings.TrimSpace(string(result.Output)))
		ev := output.NewEvent(v.Info(), "volume_mount", module.OutcomeError, module.File(imagePath), fmt.Sprintf("mounting disk image %s", imagePath))
		ev = output.WithError(ev, runErr)
		return errors.Join(runErr, emit(ev))
	}
	attached, err := parseAttachPlist(result.Output)
	if err != nil {
		return fmt.Errorf("parse hdiutil attach result: %w", err)
	}
	v.device, v.mountPoint = attached.device, attached.mountPoint
	ev := output.NewEvent(v.Info(), "volume_mount", module.OutcomeExecuted, module.Resource("volume", attached.mountPoint, attached.mountPoint), fmt.Sprintf("mounted %s at %s", imagePath, attached.mountPoint))
	ev = output.WithDetails(ev, map[string]any{"image_path": imagePath, "device": attached.device, "mount_point": attached.mountPoint})
	return errors.Join(
		emit(ev),
		module.PublishOutput(ctx, "mount_point", attached.mountPoint),
		module.PublishOutput(ctx, "device", attached.device),
	)
}

func (v *volumeMount) DryRun(params module.Params) []string {
	return []string{"hdiutil " + strings.Join(attachArgs(params.String("image_path", "")), " ")}
}

func (v *volumeMount) Cleanup(ctx context.Context) error {
	if v.device == "" {
		return nil
	}
	result, err := subprocess.Run(ctx, "hdiutil", detachArgs(v.device)...)
	if err != nil {
		return fmt.Errorf("hdiutil detach %s: %w: %s", v.device, err, strings.TrimSpace(string(result.Output)))
	}
	v.device, v.mountPoint = "", ""
	return nil
}

func init() {
	module.Register(func() module.Generator { return &volumeMount{} })
}
