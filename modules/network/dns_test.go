package network

import (
	"context"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestDNSGenerate_EmitsOnePerDomain(t *testing.T) {
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	err := (&netDNS{}).Generate(context.Background(), module.Params{"domains": "localhost,macnoise.invalid"}, emit)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("emitted %d events, want 2", len(events))
	}
	for _, ev := range events {
		if ev.EventType != "dns_lookup" {
			t.Errorf("event type = %q, want dns_lookup", ev.EventType)
		}
	}
}

func TestDNSGenerate_SkipsEmptyDomains(t *testing.T) {
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	// Leading/trailing commas and whitespace-only entries must not produce a lookup.
	err := (&netDNS{}).Generate(context.Background(), module.Params{"domains": "localhost, ,,macnoise.invalid,"}, emit)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("emitted %d events, want 2 (empties skipped)", len(events))
	}
}

func TestDNSGenerate_FailedLookupIsDeniedNotError(t *testing.T) {
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	// A .invalid name (RFC 6761) never resolves, but a failed resolution is
	// valid telemetry — the query still went out — not a macnoise error.
	err := (&netDNS{}).Generate(context.Background(), module.Params{"domains": "does-not-exist.macnoise.invalid"}, emit)
	if err != nil {
		t.Fatalf("Generate should not return an error for a failed lookup: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	if events[0].ResolvedOutcome() != module.OutcomeDenied {
		t.Errorf("outcome = %q, want denied", events[0].ResolvedOutcome())
	}
}

func TestDNSGenerate_SuccessCarriesAddresses(t *testing.T) {
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	// localhost resolves on every platform without a network round-trip.
	if err := (&netDNS{}).Generate(context.Background(), module.Params{"domains": "localhost"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 || !events[0].Success {
		t.Fatalf("expected 1 successful event, got %+v", events)
	}
	addrs, ok := events[0].Details["addresses"].([]string)
	if !ok || len(addrs) == 0 {
		t.Errorf("expected resolved addresses in details, got %v", events[0].Details["addresses"])
	}
}

func TestDNSDryRunListsDomains(t *testing.T) {
	steps := (&netDNS{}).DryRun(module.Params{"domains": "a.invalid,b.invalid"})
	if len(steps) != 1 || !strings.Contains(steps[0], "a.invalid,b.invalid") {
		t.Errorf("dry run = %v, want one line naming the domains", steps)
	}
}
