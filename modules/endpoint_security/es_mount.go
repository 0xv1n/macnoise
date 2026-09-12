package endpointsecurity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

// volumeName is the label the disk image mounts under. macOS appends a suffix
// when a volume of the same name is already mounted, which is why the real
// mount point is read back from hdiutil rather than assumed to be
// /Volumes/<volumeName>.
const volumeName = "MacNoiseDelivery"

// payloadName is the file executed from inside the mounted volume. AMOS-style
// delivery ships a bash wrapper alongside a hidden Mach-O; the wrapper is the
// half that matters here, because the detection signal is a process launched
// from a mounted image rather than what that process goes on to do.
const payloadName = "install.sh"

type esMount struct {
	dmgPath    string
	mountPoint string
	device     string
}

func (e *esMount) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "es_mount",
		EventTypes:  []string{"es_dmg_create", "es_notify_mount", "es_volume_exec", "es_notify_unmount"},
		Description: "Mounts a disk image and executes a payload from it, triggering ES_EVENT_TYPE_NOTIFY_MOUNT/EXEC/UNMOUNT",
		Category:    module.CategoryEndpointSecurity,
		Tags:        []string{"endpoint-security", "mount", "dmg", "disk-image", "delivery"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1204", SubTech: ".002", Name: "User Execution: Malicious File"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (e *esMount) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "work_dir", Description: "Directory to build the disk image in", Type: module.ParamPath, Default: "/tmp/macnoise_es", Example: "/var/tmp/es_test"},
	}
}

func (e *esMount) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

// attachResult is what hdiutil attach reports back about the image it mounted.
type attachResult struct {
	Device     string
	MountPoint string
}

// parseAttachOutput reads the device node and mount point out of hdiutil
// attach's output, which is tab-separated with a variable number of lines
// depending on the image's partition scheme:
//
//	/dev/disk4          \tGUID_partition_scheme\t
//	/dev/disk4s1        \tApple_HFS            \t/Volumes/MacNoiseDelivery
//
// Splitting on whitespace rather than tabs would truncate any mount point
// containing a space, so the fields are split on tab only. The device returned
// is the whole-disk node from the first line, since that is what detaches the
// image as a whole rather than one of its slices.
func parseAttachOutput(out string) attachResult {
	var res attachResult
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if len(fields) == 0 || fields[0] == "" {
			continue
		}
		if res.Device == "" && strings.HasPrefix(fields[0], "/dev/") {
			res.Device = fields[0]
		}
		if last := fields[len(fields)-1]; res.MountPoint == "" && strings.HasPrefix(last, "/") && !strings.HasPrefix(last, "/dev/") {
			res.MountPoint = last
		}
	}
	return res
}

// The argv builders are shared by Generate and DryRun so the advertised
// commands cannot drift from the executed ones.

func createArgs(dmgPath string) []string {
	return []string{"create", "-size", "10m", "-fs", "HFS+", "-volname", volumeName, "-ov", dmgPath}
}

func attachArgs(dmgPath string) []string {
	return []string{"attach", dmgPath}
}

func detachArgs(target string) []string {
	return []string{"detach", target, "-force"}
}

func (e *esMount) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	runID := module.RunIDFromContext(ctx)
	workDir := module.TagPath(params.String("work_dir", "/tmp/macnoise_es"), runID)
	info := e.Info()

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", workDir, err)
	}
	dmgPath := path.Join(workDir, "macnoise_delivery.dmg")

	createEv := output.NewEvent(info, "es_dmg_create", module.OutcomeError, module.File(dmgPath), fmt.Sprintf("building disk image %s", dmgPath))
	if out, err := exec.CommandContext(ctx, "hdiutil", createArgs(dmgPath)...).CombinedOutput(); err != nil {
		createEv = output.WithError(createEv, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out))))
		return errors.Join(fmt.Errorf("es_mount: hdiutil create: %w", err), emit(createEv))
	}
	e.dmgPath = dmgPath
	createEv.Outcome = module.OutcomeExecuted
	createEv.Message = fmt.Sprintf("built disk image %s", dmgPath)
	if err := emit(output.WithDetails(createEv, map[string]any{"path": dmgPath, "volume_name": volumeName})); err != nil {
		return err
	}

	mountEv := output.NewEvent(info, "es_notify_mount", module.OutcomeError, module.File(dmgPath), fmt.Sprintf("mounting %s (triggers ES_EVENT_TYPE_NOTIFY_MOUNT)", dmgPath))
	attachOut, err := exec.CommandContext(ctx, "hdiutil", attachArgs(dmgPath)...).CombinedOutput()
	if err != nil {
		mountEv = output.WithError(mountEv, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(attachOut))))
		return errors.Join(fmt.Errorf("es_mount: hdiutil attach: %w", err), emit(mountEv))
	}
	res := parseAttachOutput(string(attachOut))
	e.device, e.mountPoint = res.Device, res.MountPoint

	mountDetails := map[string]any{
		"path":        dmgPath,
		"device":      res.Device,
		"mount_point": res.MountPoint,
		"es_event":    "ES_EVENT_TYPE_NOTIFY_MOUNT",
	}
	if res.MountPoint == "" {
		// hdiutil succeeded but nothing is mounted, so there is no volume to
		// execute from and no mount point to report. Claiming a MOUNT event
		// here would be asserting telemetry that was never produced.
		mountEv.Message = fmt.Sprintf("attached %s but no volume was mounted", dmgPath)
		mountEv = output.WithOutcome(mountEv, module.OutcomeIndeterminate, nil)
		return emit(output.WithDetails(mountEv, mountDetails))
	}
	mountEv.Outcome = module.OutcomeExecuted
	mountEv.Message = fmt.Sprintf("mounted %s at %s (ES_EVENT_TYPE_NOTIFY_MOUNT)", dmgPath, res.MountPoint)
	if err := emit(output.WithDetails(mountEv, mountDetails)); err != nil {
		return err
	}

	if err := e.emitVolumeExec(ctx, info, emit, runID); err != nil {
		return err
	}

	unmountEv := output.NewEvent(info, "es_notify_unmount", module.OutcomeError, module.File(res.MountPoint), fmt.Sprintf("unmounting %s (triggers ES_EVENT_TYPE_NOTIFY_UNMOUNT)", res.MountPoint))
	if out, err := exec.CommandContext(ctx, "hdiutil", detachArgs(e.detachTarget())...).CombinedOutput(); err != nil {
		unmountEv = output.WithError(unmountEv, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out))))
		return emit(unmountEv)
	}
	e.mountPoint, e.device = "", ""
	unmountEv.Outcome = module.OutcomeExecuted
	unmountEv.Message = fmt.Sprintf("unmounted %s (ES_EVENT_TYPE_NOTIFY_UNMOUNT)", res.MountPoint)
	return emit(output.WithDetails(unmountEv, map[string]any{
		"mount_point": res.MountPoint,
		"es_event":    "ES_EVENT_TYPE_NOTIFY_UNMOUNT",
	}))
}

// emitVolumeExec writes a payload into the mounted volume and runs it. This is
// the half that makes T1204.002 accurate: a bare mount is weak signal, while a
// process launched from a /Volumes path is what AMOS-style delivery actually
// looks like on an endpoint.
func (e *esMount) emitVolumeExec(ctx context.Context, info module.ModuleInfo, emit module.EventEmitter, runID string) error {
	payload := path.Join(e.mountPoint, payloadName)
	ev := output.NewEvent(info, "es_volume_exec", module.OutcomeError, module.Process(path.Base(payload), payload, payload, 0), fmt.Sprintf("executing %s (triggers ES_EVENT_TYPE_NOTIFY_EXEC)", payload))
	details := map[string]any{"payload": payload, "mount_point": e.mountPoint, "es_event": "ES_EVENT_TYPE_NOTIFY_EXEC"}

	echoArg := "macnoise_dmg_payload"
	if runID != "" {
		echoArg += "_" + runID
	}
	script := "#!/bin/sh\necho " + echoArg + "\n"
	if err := os.WriteFile(payload, []byte(script), 0o755); err != nil {
		ev = output.WithError(ev, err)
		return emit(output.WithDetails(ev, details))
	}

	out, err := exec.CommandContext(ctx, payload).CombinedOutput()
	if err != nil {
		// A disk image mounted noexec refuses the launch. That is the volume
		// declining, not macnoise breaking, and it is worth reporting plainly
		// because it means no EXEC event was generated to detect on.
		ev.Message = fmt.Sprintf("%s could not be executed from the mounted volume", payload)
		ev = output.WithOutcome(ev, module.OutcomeDenied, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out))))
		return emit(output.WithDetails(ev, details))
	}

	ev.Outcome = module.OutcomeExecuted
	ev.Message = fmt.Sprintf("executed %s from mounted volume (ES_EVENT_TYPE_NOTIFY_EXEC)", payload)
	details["stdout"] = strings.TrimSpace(string(out))
	return emit(output.WithDetails(ev, details))
}

func (e *esMount) DryRun(params module.Params) []string {
	workDir := params.String("work_dir", "/tmp/macnoise_es")
	dmgPath := path.Join(workDir, "macnoise_delivery.dmg")
	mountPoint := path.Join("/Volumes", volumeName)
	return []string{
		fmt.Sprintf("hdiutil %s", strings.Join(createArgs(dmgPath), " ")),
		fmt.Sprintf("hdiutil %s → ES_EVENT_TYPE_NOTIFY_MOUNT", strings.Join(attachArgs(dmgPath), " ")),
		fmt.Sprintf("execute %s → ES_EVENT_TYPE_NOTIFY_EXEC", path.Join(mountPoint, payloadName)),
		fmt.Sprintf("hdiutil %s → ES_EVENT_TYPE_NOTIFY_UNMOUNT", strings.Join(detachArgs(mountPoint), " ")),
	}
}

// Cleanup detaches the image only if Generate actually mounted one, so a run
// that never got that far does not report a detach failure for a volume that
// was never there.
func (e *esMount) Cleanup(ctx context.Context) error {
	var errs []error

	if target := e.detachTarget(); target != "" {
		if out, err := exec.CommandContext(ctx, "hdiutil", detachArgs(target)...).CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("detach %s: %v: %s", target, err, strings.TrimSpace(string(out))))
		} else {
			e.mountPoint, e.device = "", ""
		}
	}

	if e.dmgPath != "" {
		if err := os.Remove(e.dmgPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", e.dmgPath, err))
		} else {
			e.dmgPath = ""
		}
	}

	return errors.Join(errs...)
}

// detachTarget uses the whole-disk node so every slice is detached. The mount
// point is a fallback for unusual attach output that omits the device.
func (e *esMount) detachTarget() string {
	if e.device != "" {
		return e.device
	}
	return e.mountPoint
}

func init() {
	module.Register(func() module.Generator { return &esMount{} })
}
