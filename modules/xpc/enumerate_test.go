package xpc

import (
	"strconv"
	"strings"
	"testing"
)

// Shape of a `launchctl print <domain>` services block: PID (or "-"), last
// exit status, then the label. The label is the final field, which is the
// whole point of the fix - the previous parser took the first field and so
// recorded PIDs as service names.
// Property lines outside the services block carry dotted values (plist paths,
// executable paths) whose final field looks exactly like a service label, so
// they are the realistic false positive the block tracking has to exclude.
const sampleOutput = `com.apple.xpc.launchd.domain.system = {
	type = system
	handle = 0
	active count = 673
	path = /System/Library/LaunchDaemons/com.apple.decoy.plist
	program = /usr/libexec/com.apple.notaservice
	services = {
		    1234     0	com.apple.mdworker
		       -     0	com.apple.securityd
		       -    78	com.apple.diagnosticd
		     999     0	com.example.thirdparty
	}
	endpoints = {
		"com.apple.system.notification_center" = {
	}
}
`

func TestParseServices_TakesLabelNotPID(t *testing.T) {
	got := parseServices(sampleOutput, "", 100)
	want := []string{
		"com.apple.mdworker",
		"com.apple.securityd",
		"com.apple.diagnosticd",
		"com.example.thirdparty",
	}

	if len(got) != len(want) {
		t.Fatalf("parsed %d services %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("services[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	for _, svc := range got {
		if _, err := strconv.Atoi(svc); err == nil {
			t.Errorf("parsed %q as a service name, but it is a PID", svc)
		}
	}
}

func TestParseServices_Filter(t *testing.T) {
	got := parseServices(sampleOutput, "com.apple", 100)
	if len(got) != 3 {
		t.Fatalf("parsed %v, want only the 3 com.apple services", got)
	}
	for _, svc := range got {
		if !strings.HasPrefix(svc, "com.apple") {
			t.Errorf("service %q does not match the com.apple filter", svc)
		}
	}
}

func TestParseServices_MaxResults(t *testing.T) {
	got := parseServices(sampleOutput, "", 2)
	if len(got) != 2 {
		t.Errorf("parsed %d services, want max_results of 2 to be honoured", len(got))
	}
}

// Content outside the services block, notably the endpoints section, must not
// be mistaken for services.
func TestParseServices_IgnoresNonServiceLines(t *testing.T) {
	got := parseServices(sampleOutput, "", 100)
	for _, svc := range got {
		if strings.Contains(svc, "notification_center") {
			t.Errorf("parsed endpoint %q as a service", svc)
		}
		if strings.Contains(svc, "=") || strings.Contains(svc, "{") {
			t.Errorf("parsed structural line fragment %q as a service", svc)
		}
		if strings.Contains(svc, "/") {
			t.Errorf("parsed path value %q as a service; property lines outside the services block are leaking in", svc)
		}
		if strings.Contains(svc, "decoy") || strings.Contains(svc, "notaservice") {
			t.Errorf("parsed %q, which sits outside the services block", svc)
		}
	}
}

func TestParseServices_EmptyOutput(t *testing.T) {
	if got := parseServices("", "", 10); len(got) != 0 {
		t.Errorf("parsed %v from empty output, want none", got)
	}
}
