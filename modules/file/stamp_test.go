package file

import (
	"strings"
	"testing"
)

func TestStampedFileName_WithRunID(t *testing.T) {
	name := stampedFileName("mnfile_", "deadbeef01234567", "20060102_150405", 2)
	if !strings.Contains(name, "deadbeef01234567") {
		t.Errorf("run ID missing from file name: %s", name)
	}
	if !strings.HasPrefix(name, "mnfile_") {
		t.Errorf("prefix not preserved: %s", name)
	}
	if !strings.HasSuffix(name, ".txt") {
		t.Errorf("extension not preserved: %s", name)
	}
}

func TestStampedFileName_WithoutRunID(t *testing.T) {
	name := stampedFileName("mnfile_", "", "20060102_150405", 2)
	if name != "mnfile_20060102_1504052.txt" {
		t.Errorf("unstamped name = %q, want mnfile_20060102_1504052.txt", name)
	}
}
