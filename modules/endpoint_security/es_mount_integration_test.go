//go:build integration && darwin

package endpointsecurity

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func runMount(t *testing.T, e *esMount, workDir string) []module.TelemetryEvent {
	t.Helper()

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	// Registered before Generate so a panic or an assertion failure part-way
	// through still detaches the image, rather than leaving a mounted volume
	// behind for every subsequent run on the same machine.
	t.Cleanup(func() { _ = e.Cleanup() })

	if err := e.Generate(context.Background(), module.Params{"work_dir": workDir}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return events
}

func TestESMount_GenerateEmitsFullMountExecUnmountCycle(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "es")
	events := runMount(t, &esMount{}, workDir)

	want := []string{"es_dmg_create", "es_notify_mount", "es_volume_exec", "es_notify_unmount"}
	if len(events) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(events))
	}
	for i, evType := range want {
		if events[i].EventType != evType {
			t.Fatalf("event[%d] = %q, want %q", i, events[i].EventType, evType)
		}
		if !events[i].Success {
			t.Errorf("event %q did not succeed: %s", evType, events[i].Error)
		}
	}
}

// The mount point has to be read back from hdiutil, not assumed. A machine that
// already has a MacNoiseDelivery volume mounted gets "/Volumes/MacNoiseDelivery 1"
// instead, and every later step would target the wrong path.
func TestESMount_ReportsRealMountPoint(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "es")
	events := runMount(t, &esMount{}, workDir)

	mountEv := events[1]
	mountPoint, _ := mountEv.Details["mount_point"].(string)
	if !strings.HasPrefix(mountPoint, "/Volumes/") {
		t.Fatalf("mount_point = %q, want a path under /Volumes", mountPoint)
	}
	if device, _ := mountEv.Details["device"].(string); !strings.HasPrefix(device, "/dev/disk") {
		t.Errorf("device = %q, want a /dev/disk node", device)
	}
}

// The payload must actually run from the mounted volume. If the image were
// mounted noexec this reports denied instead, which is a real result but not
// the telemetry the module claims to generate.
func TestESMount_PayloadExecutesFromVolume(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "es")
	events := runMount(t, &esMount{}, workDir)

	execEv := events[2]
	if execEv.Outcome == module.OutcomeDenied {
		t.Fatalf("volume refused execution, no EXEC event was generated: %s", execEv.Error)
	}
	if got, _ := execEv.Details["stdout"].(string); got != "macnoise_dmg_payload" {
		t.Errorf("payload stdout = %q, want %q", got, "macnoise_dmg_payload")
	}
	payload, _ := execEv.Details["payload"].(string)
	if !strings.HasPrefix(payload, "/Volumes/") {
		t.Errorf("payload = %q, want it executed from the mounted volume", payload)
	}
}

// Generate detaches as part of the telemetry cycle, so nothing should still be
// mounted even before Cleanup runs.
func TestESMount_GenerateLeavesNothingMounted(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "es")
	events := runMount(t, &esMount{}, workDir)

	mountPoint, _ := events[1].Details["mount_point"].(string)
	if _, err := os.Stat(mountPoint); !os.IsNotExist(err) {
		t.Errorf("expected %s to be unmounted by Generate, stat err = %v", mountPoint, err)
	}

	out, err := exec.Command("hdiutil", "info").CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil info: %v", err)
	}
	if strings.Contains(string(out), "macnoise_delivery.dmg") {
		t.Errorf("disk image still attached after Generate:\n%s", out)
	}
}

func TestESMount_CleanupRemovesTheDiskImage(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "es")
	e := &esMount{}
	runMount(t, e, workDir)

	dmgPath := filepath.Join(workDir, "macnoise_delivery.dmg")
	if _, err := os.Stat(dmgPath); err != nil {
		t.Fatalf("expected %s to exist before Cleanup: %v", dmgPath, err)
	}
	if err := e.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(dmgPath); !os.IsNotExist(err) {
		t.Errorf("Cleanup left %s in place, stat err = %v", dmgPath, err)
	}
}
