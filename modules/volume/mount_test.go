package volume

import (
	"context"
	"strings"
	"testing"
)

func TestParseAttachPlist(t *testing.T) {
	data := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>system-entities</key><array>
<dict><key>dev-entry</key><string>/dev/disk4</string></dict>
<dict><key>dev-entry</key><string>/dev/disk4s1</string><key>mount-point</key><string>/Volumes/MacNoise Delivery 1</string></dict>
</array></dict></plist>`
	got, err := parseAttachPlist([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.device != "/dev/disk4" || got.mountPoint != "/Volumes/MacNoise Delivery 1" {
		t.Fatalf("result = %+v", got)
	}
}

func TestMountArgvAndCleanupContract(t *testing.T) {
	if got := strings.Join(attachArgs("/tmp/image.dmg"), " "); got != "attach -plist -nobrowse -readonly /tmp/image.dmg" {
		t.Fatalf("attach args = %q", got)
	}
	if got := strings.Join(detachArgs("/dev/disk4"), " "); got != "detach /dev/disk4 -force" {
		t.Fatalf("detach args = %q", got)
	}
	if err := (&volumeMount{}).Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestParseAttachPlistDerivesWholeDiskFromMountedSlice(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk7s2</string><key>mount-point</key><string>/Volumes/Test</string></dict></array></dict></plist>`)
	got, err := parseAttachPlist(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.device != "/dev/disk7" {
		t.Fatalf("device = %q, want whole disk", got.device)
	}
}
