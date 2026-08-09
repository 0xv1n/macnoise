package endpointsecurity

import (
	"strings"
	"testing"
)

// hdiutil attach output is tab-separated with a variable number of lines and a
// trailing empty column on the lines that mount nothing. The xpc parser shipped
// broken for exactly this shape of input by assuming a fixed column, so each
// real layout gets a case here.
func TestParseAttachOutput(t *testing.T) {
	tests := []struct {
		name       string
		out        string
		device     string
		mountPoint string
	}{
		{
			name:       "guid scheme with one mounted slice",
			out:        "/dev/disk4          \tGUID_partition_scheme          \t\n/dev/disk4s1        \tApple_HFS                      \t/Volumes/MacNoiseDelivery\n",
			device:     "/dev/disk4",
			mountPoint: "/Volumes/MacNoiseDelivery",
		},
		{
			name:       "apple partition scheme with three lines",
			out:        "/dev/disk6          \tApple_partition_scheme         \t\n/dev/disk6s1        \tApple_partition_map            \t\n/dev/disk6s2        \tApple_HFS                      \t/Volumes/MacNoiseDelivery\n",
			device:     "/dev/disk6",
			mountPoint: "/Volumes/MacNoiseDelivery",
		},
		{
			// Splitting on whitespace instead of tab truncates this to
			// "/Volumes/MacNoise", which would then fail to detach.
			name:       "mount point containing a space is not truncated",
			out:        "/dev/disk4          \tGUID_partition_scheme          \t\n/dev/disk4s1        \tApple_HFS                      \t/Volumes/MacNoise Delivery 1\n",
			device:     "/dev/disk4",
			mountPoint: "/Volumes/MacNoise Delivery 1",
		},
		{
			name:       "attached with no filesystem mounted",
			out:        "/dev/disk4          \tGUID_partition_scheme          \t\n",
			device:     "/dev/disk4",
			mountPoint: "",
		},
		{
			name:       "empty output yields nothing",
			out:        "",
			device:     "",
			mountPoint: "",
		},
		{
			name:       "carriage returns are stripped",
			out:        "/dev/disk4          \tGUID_partition_scheme          \t\r\n/dev/disk4s1        \tApple_HFS                      \t/Volumes/MacNoiseDelivery\r\n",
			device:     "/dev/disk4",
			mountPoint: "/Volumes/MacNoiseDelivery",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAttachOutput(tt.out)
			if got.Device != tt.device {
				t.Errorf("device = %q, want %q", got.Device, tt.device)
			}
			if got.MountPoint != tt.mountPoint {
				t.Errorf("mount point = %q, want %q", got.MountPoint, tt.mountPoint)
			}
		})
	}
}

// The device must be the whole-disk node. Detaching a slice leaves the image
// attached, so a parser that returned /dev/disk4s1 would leak a mounted volume
// on every run.
func TestParseAttachOutputReturnsWholeDiskNode(t *testing.T) {
	out := "/dev/disk4          \tGUID_partition_scheme          \t\n/dev/disk4s1        \tApple_HFS                      \t/Volumes/MacNoiseDelivery\n"

	if got := parseAttachOutput(out).Device; got != "/dev/disk4" {
		t.Errorf("device = %q, want the whole-disk node /dev/disk4", got)
	}
}

// DryRun must render the commands the module actually runs. The launchctl
// modules drifted here because the two were built independently.
func TestDryRunMatchesExecutedArgv(t *testing.T) {
	lines := (&esMount{}).DryRun(nil)
	joined := strings.Join(lines, "\n")

	dmgPath := "/tmp/macnoise_es/macnoise_delivery.dmg"
	for _, want := range []string{
		"hdiutil " + strings.Join(createArgs(dmgPath), " "),
		"hdiutil " + strings.Join(attachArgs(dmgPath), " "),
		"hdiutil " + strings.Join(detachArgs("/Volumes/"+volumeName), " "),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("dry run does not advertise %q\ngot:\n%s", want, joined)
		}
	}
}

// Cleanup must not shell out for an image that was never mounted, or a run that
// failed before attaching reports a detach error for a volume that never
// existed.
func TestCleanupIsNoOpWhenNothingWasMounted(t *testing.T) {
	if target := (&esMount{}).detachTarget(); target != "" {
		t.Errorf("detach target = %q, want empty when nothing was mounted", target)
	}
	if err := (&esMount{}).Cleanup(); err != nil {
		t.Errorf("Cleanup on an untouched module returned %v", err)
	}
}

func TestDetachTargetPrefersMountPoint(t *testing.T) {
	e := &esMount{device: "/dev/disk4", mountPoint: "/Volumes/MacNoiseDelivery"}
	if got := e.detachTarget(); got != "/Volumes/MacNoiseDelivery" {
		t.Errorf("detach target = %q, want the mount point", got)
	}

	e = &esMount{device: "/dev/disk4"}
	if got := e.detachTarget(); got != "/dev/disk4" {
		t.Errorf("detach target = %q, want the device node as fallback", got)
	}
}
