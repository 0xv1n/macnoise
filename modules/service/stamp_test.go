package service

import (
	"strings"
	"testing"
)

func TestStampLabel_WithRunID(t *testing.T) {
	label := stampLabel("com.macnoise.testagent", "deadbeef01234567")
	if label != "com.macnoise.testagent.deadbeef01234567" {
		t.Errorf("stamped label = %q, want com.macnoise.testagent.deadbeef01234567", label)
	}
}

func TestStampLabel_WithoutRunID(t *testing.T) {
	label := stampLabel("com.macnoise.testagent", "")
	if label != "com.macnoise.testagent" {
		t.Errorf("unstamped label = %q, want com.macnoise.testagent", label)
	}
}

func TestCronMarker_WithRunID(t *testing.T) {
	marker := cronMarker("deadbeef01234567")
	if !strings.HasPrefix(marker, "# macnoise") {
		t.Errorf("marker lost its macnoise tag: %s", marker)
	}
	if !strings.Contains(marker, "deadbeef01234567") {
		t.Errorf("run ID missing from marker: %s", marker)
	}
}

func TestCronMarker_WithoutRunID(t *testing.T) {
	if marker := cronMarker(""); marker != "# macnoise" {
		t.Errorf("unstamped marker = %q, want # macnoise", marker)
	}
}
