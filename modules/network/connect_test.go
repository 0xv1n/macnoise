package network

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// hostPort splits an httptest server URL (http://127.0.0.1:PORT) into its host
// and port for use as net_connect params.
func hostPort(t *testing.T, rawURL string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(rawURL, "http://"))
	if err != nil {
		t.Fatalf("split %s: %v", rawURL, err)
	}
	return host, port
}

func TestConnectGenerate_EmitsConnectThenGet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	host, port := hostPort(t, ts.URL)

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	if err := (&netConnect{}).Generate(context.Background(), module.Params{"target": host, "port": port}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("emitted %d events, want 2 (tcp_connect, http_get)", len(events))
	}
	if events[0].EventType != "tcp_connect" || events[1].EventType != "http_get" {
		t.Errorf("event types = %q,%q; want tcp_connect,http_get", events[0].EventType, events[1].EventType)
	}
	if !events[0].Success || !events[1].Success {
		t.Errorf("both events should succeed against a live server: %+v", events)
	}
}

func TestConnectGenerate_RefusedIsDenied(t *testing.T) {
	// Bind then immediately close to obtain a port nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port := hostPort(t, "http://"+ln.Addr().String())
	_ = ln.Close()

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	if err := (&netConnect{}).Generate(context.Background(), module.Params{"target": host, "port": port}, emit); err != nil {
		t.Fatalf("Generate should not error on a refused connection: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("emitted %d events, want 2 even when refused", len(events))
	}
	if events[0].ResolvedOutcome() != module.OutcomeDenied {
		t.Errorf("refused tcp_connect outcome = %q, want denied", events[0].ResolvedOutcome())
	}
}

func TestConnectGenerate_RunIDInHTTPURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	host, port := hostPort(t, ts.URL)

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	ctx := module.ContextWithRunID(context.Background(), "runid1234")
	if err := (&netConnect{}).Generate(ctx, module.Params{"target": host, "port": port}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	url, _ := events[1].Details["url"].(string)
	if !strings.Contains(url, "mn=runid1234") {
		t.Errorf("http_get url = %q, want it to carry mn=runid1234", url)
	}
}

func TestConnectDryRun(t *testing.T) {
	steps := (&netConnect{}).DryRun(module.Params{"target": "10.0.0.1", "port": "443"})
	if len(steps) != 2 {
		t.Fatalf("dry run = %v, want 2 lines", steps)
	}
	if !strings.Contains(steps[0], "10.0.0.1:443") {
		t.Errorf("first dry-run line %q should name the address", steps[0])
	}
}
