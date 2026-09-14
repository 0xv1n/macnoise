//go:build integration && darwin

package service

import (
	"context"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestSvcEnumerate_RealSystemDomain(t *testing.T) {
	s := &svcEnumerate{}
	var events []module.TelemetryEvent
	err := s.Generate(context.Background(), module.Params{
		"scope":       "system",
		"filter":      "",
		"max_results": 500,
	}, func(ev module.TelemetryEvent) error {
		events = append(events, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].EventType != "service_enumerate" || events[0].Outcome != module.OutcomeExecuted {
		t.Fatalf("event = %+v, want executed service_enumerate", events[0])
	}
	if count, ok := events[0].Details["service_count"].(int); !ok || count == 0 {
		t.Errorf("service_count = %#v, want a positive integer", events[0].Details["service_count"])
	}
}
