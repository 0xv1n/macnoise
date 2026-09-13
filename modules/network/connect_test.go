package network

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestConnectGenerate_OnlyDialsTCP(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer ts.Close()
	host, port := hostPort(t, ts.URL)

	var events []module.TelemetryEvent
	emit := captureNetworkEvents(&events)
	if err := (&netConnect{}).Generate(context.Background(), module.Params{"target": host, "port": port}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1 tcp_connect", len(events))
	}
	if events[0].EventType != "tcp_connect" || events[0].Outcome != module.OutcomeExecuted {
		t.Errorf("event = %+v, want executed tcp_connect", events[0])
	}
	if requests.Load() != 0 {
		t.Errorf("net_connect sent %d HTTP request(s), want TCP only", requests.Load())
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
	emit := captureNetworkEvents(&events)
	if err := (&netConnect{}).Generate(context.Background(), module.Params{"target": host, "port": port}, emit); err != nil {
		t.Fatalf("Generate should not error on a refused connection: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("emitted %d events, want 1", len(events))
	}
	if events[0].Outcome != module.OutcomeDenied {
		t.Errorf("refused tcp_connect outcome = %q, want denied", events[0].Outcome)
	}
}

func TestConnectGenerate_AlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (&netConnect{}).Generate(ctx, module.Params{"target": "127.0.0.1", "port": "1"}, func(ev module.TelemetryEvent) error {
		t.Errorf("canceled connect emitted %+v", ev)
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate = %v, want context.Canceled", err)
	}
}

func TestConnectDryRun(t *testing.T) {
	steps := (&netConnect{}).DryRun(module.Params{"target": "10.0.0.1", "port": "443"})
	if len(steps) != 1 {
		t.Fatalf("dry run = %v, want 1 line", steps)
	}
	if !strings.Contains(steps[0], "10.0.0.1:443") {
		t.Errorf("first dry-run line %q should name the address", steps[0])
	}
	if strings.Contains(steps[0], "HTTP") {
		t.Errorf("dry-run line %q includes HTTP behavior", steps[0])
	}
}
