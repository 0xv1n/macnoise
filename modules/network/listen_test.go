package network

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestNetListen_AcceptsSelfConnection(t *testing.T) {
	n := &netListen{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := n.Generate(ctx, module.Params{"port": "18081"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer n.Cleanup() //nolint:errcheck

	if len(events) != 2 {
		t.Fatalf("expected 2 events (tcp_listen, tcp_accept), got %d", len(events))
	}
	if events[0].EventType != "tcp_listen" || !events[0].Success {
		t.Errorf("event[0] = %+v, want successful tcp_listen", events[0])
	}
	if events[1].EventType != "tcp_accept" || !events[1].Success {
		t.Errorf("event[1] = %+v, want successful tcp_accept", events[1])
	}
}

// Before the fix, ctx was never wired into l.Accept(), so an expired context
// had no effect and Generate only returned once the self-dial goroutine
// connected (~200ms) or hung forever if it didn't. An already-cancelled
// context must now short-circuit Accept() immediately.
func TestNetListen_RespectsContextCancellation(t *testing.T) {
	n := &netListen{}
	emit := func(module.TelemetryEvent) {}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := n.Generate(ctx, module.Params{"port": "18082"}, emit)
	elapsed := time.Since(start)
	defer n.Cleanup() //nolint:errcheck

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("Generate took %v to return after cancellation, want well under the 200ms self-dial delay", elapsed)
	}
}

func TestNetListen_DefaultBindsLoopback(t *testing.T) {
	n := &netListen{}
	emit := func(module.TelemetryEvent) {}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := n.Generate(ctx, module.Params{"port": "18083"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer n.Cleanup() //nolint:errcheck

	addr, ok := n.listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener.Addr() is %T, want *net.TCPAddr", n.listener.Addr())
	}
	if !addr.IP.IsLoopback() {
		t.Errorf("bound IP = %s, want loopback (127.0.0.1) by default", addr.IP)
	}
}

func TestNetListen_CustomBindAddr(t *testing.T) {
	n := &netListen{}
	emit := func(module.TelemetryEvent) {}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	params := module.Params{"port": "18084", "bind_addr": "0.0.0.0"}
	if err := n.Generate(ctx, params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer n.Cleanup() //nolint:errcheck

	addr, ok := n.listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener.Addr() is %T, want *net.TCPAddr", n.listener.Addr())
	}
	if !addr.IP.IsUnspecified() {
		t.Errorf("bound IP = %s, want 0.0.0.0 when bind_addr is set explicitly", addr.IP)
	}
}
