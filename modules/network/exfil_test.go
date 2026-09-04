package network

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestExfilGenerate_PostsToLiveServer(t *testing.T) {
	var gotBytes int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBytes = r.ContentLength
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	if err := (&netExfil{}).Generate(context.Background(), module.Params{"target": ts.URL, "payload_size": "2048"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(events) != 1 || events[0].EventType != "http_post_exfil" {
		t.Fatalf("expected 1 http_post_exfil event, got %+v", events)
	}
	if !events[0].Success {
		t.Errorf("POST to a live server should succeed: %s", events[0].Message)
	}
	if events[0].Details["status"] != http.StatusOK {
		t.Errorf("status detail = %v, want 200", events[0].Details["status"])
	}
	if gotBytes != 2048 {
		t.Errorf("server received %d bytes, want the requested 2048", gotBytes)
	}
}

func TestExfilGenerate_NoListenerStillSucceeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + ln.Addr().String() + "/upload"
	_ = ln.Close()

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	if err := (&netExfil{}).Generate(context.Background(), module.Params{"target": target}, emit); err != nil {
		t.Fatalf("Generate should not error with no listener: %v", err)
	}
	// The outbound POST is the telemetry; a refused connection does not make it a failure.
	if len(events) != 1 || !events[0].Success {
		t.Fatalf("expected 1 successful event even with no listener, got %+v", events)
	}
	if events[0].Details["error"] == nil {
		t.Error("expected the connection error to be recorded in details")
	}
}

func TestExfilGenerate_RunIDInRequestURL(t *testing.T) {
	var gotMN string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMN = r.URL.Query().Get("mn")
	}))
	defer ts.Close()

	emit := func(module.TelemetryEvent) {}
	ctx := module.ContextWithRunID(context.Background(), "exfilrun99")
	if err := (&netExfil{}).Generate(ctx, module.Params{"target": ts.URL}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gotMN != "exfilrun99" {
		t.Errorf("server saw mn=%q, want exfilrun99", gotMN)
	}
}

func TestExfilDryRun(t *testing.T) {
	steps := (&netExfil{}).DryRun(module.Params{"target": "http://10.0.0.1/x", "payload_size": "512"})
	if len(steps) != 1 {
		t.Fatalf("dry run = %v, want 1 line", steps)
	}
}
