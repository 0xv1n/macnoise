//go:build integration && darwin

package xpc

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// The parser is written against the documented shape of a launchctl print
// services block. This runs it against the real thing, so a format that does
// not match what parseServices expects fails here rather than silently
// producing empty telemetry on a user's machine.
// Uses the system domain rather than gui/<uid>: the GUI domain only exists
// inside an Aqua session, so it is unavailable over SSH and this test would
// fail for reasons that have nothing to do with the parser. The system domain
// is readable unprivileged in both environments.
func TestParseServices_AgainstRealLaunchctlOutput(t *testing.T) {
	out, err := exec.Command("launchctl", "print", "system").CombinedOutput()
	if err != nil {
		t.Fatalf("launchctl print system failed as uid %d: %v\n%s", os.Getuid(), err, out)
	}

	services := parseServices(string(out), "", 500)
	if len(services) == 0 {
		t.Fatalf("parsed no services from real launchctl output; the services block format does not match what parseServices expects.\nFirst 1500 bytes:\n%s", head(string(out), 1500))
	}

	t.Logf("parsed %d services from the system domain", len(services))

	// Diagnostic only. The GUI domain is absent outside an Aqua session, which
	// the module reports as inaccessible rather than treating as an error.
	if _, guiErr := exec.Command("launchctl", "print", guiDomain()).CombinedOutput(); guiErr != nil {
		t.Logf("gui domain %s unavailable (expected without an Aqua session): %v", guiDomain(), guiErr)
	} else {
		t.Logf("gui domain %s is available", guiDomain())
	}

	for i, svc := range services {
		if i >= 5 {
			break
		}
		t.Logf("  service[%d] = %q", i, svc)
		if _, err := strconv.Atoi(svc); err == nil {
			t.Errorf("service[%d] = %q is a PID, not a label", i, svc)
		}
		if strings.ContainsAny(svc, "={}\"") {
			t.Errorf("service[%d] = %q contains structural characters, parser is picking up non-service lines", i, svc)
		}
	}
}

// Records whether the system domain is readable unprivileged. The roadmap
// flagged this as unverified and the documentation only states that root is
// needed to modify the system domain, not to print it. This does not assert
// an outcome, it reports the one this machine gives.
func TestSystemDomain_PrivilegeRequirement(t *testing.T) {
	out, err := exec.Command("launchctl", "print", "system").CombinedOutput()
	t.Logf("launchctl print system as uid=%d euid=%d: err=%v", os.Getuid(), os.Geteuid(), err)
	if err != nil {
		t.Logf("  output: %s", head(string(out), 300))
		return
	}
	t.Logf("  succeeded, parsed %d services", len(parseServices(string(out), "", 500)))
}

func TestXPCEnumerate_EmitsPerDomain(t *testing.T) {
	x := &xpcEnumerate{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := x.Generate(context.Background(), module.Params{"filter": ""}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("emitted %d events, want 2 (one each for the gui and system domains)", len(events))
	}

	for _, ev := range events {
		if ev.EventType != "xpc_enumerate" {
			t.Errorf("EventType = %q, want xpc_enumerate", ev.EventType)
		}
		if !ev.Success {
			t.Errorf("Success = false for domain %v; an unreadable domain is still valid telemetry", ev.Details["domain"])
		}
		if ev.Details["domain"] == "" {
			t.Error("event is missing the domain it enumerated")
		}
	}
	if got := events[0].Details["domain"]; got != guiDomain() {
		t.Errorf("first event domain = %v, want %s", got, guiDomain())
	}
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
