package network

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestNetListen_AcceptsSelfConnection(t *testing.T) {
	n := &netListen{}
	var events []module.TelemetryEvent
	emit := captureNetworkEvents(&events)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := n.Generate(ctx, module.Params{"port": "18081"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events (tcp_listen, tcp_accept), got %d", len(events))
	}
	if events[0].EventType != "tcp_listen" || events[0].Outcome != module.OutcomeExecuted {
		t.Errorf("event[0] = %+v, want successful tcp_listen", events[0])
	}
	if events[1].EventType != "tcp_accept" || events[1].Outcome != module.OutcomeExecuted {
		t.Errorf("event[1] = %+v, want successful tcp_accept", events[1])
	}
	if err := n.Cleanup(context.Background()); err != nil {
		t.Fatalf("first Cleanup: %v", err)
	}
	if err := n.Cleanup(context.Background()); err != nil {
		t.Fatalf("second Cleanup: %v", err)
	}
}

// Before the fix, ctx was never wired into l.Accept(), so an expired context
// had no effect and Generate only returned once the self-dial goroutine
// connected (~200ms) or hung forever if it didn't. An already-cancelled
// context must now short-circuit Accept() immediately.
func TestNetListen_RespectsContextCancellation(t *testing.T) {
	n := &netListen{}
	emit := discardNetworkEvent

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := n.Generate(ctx, module.Params{"port": "18082"}, emit)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("Generate took %v to return after cancellation, want well under the 200ms self-dial delay", elapsed)
	}
	if err := n.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup after cancellation: %v", err)
	}
	if err := n.Cleanup(context.Background()); err != nil {
		t.Fatalf("second Cleanup after cancellation: %v", err)
	}
}

func TestNetListen_CustomBindAcceptsSelfConnection(t *testing.T) {
	bindAddr, port := reserveNonLoopbackIPv4(t)
	n := &netListen{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := n.Generate(ctx, module.Params{
		"port":      strconv.Itoa(port),
		"bind_addr": bindAddr,
	}, discardNetworkEvent)
	defer func() { _ = n.Cleanup(context.Background()) }()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
}

func reserveNonLoopbackIPv4(t *testing.T) (string, int) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		listener, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
		if err != nil {
			continue
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		return ip.String(), port
	}
	t.Skip("no bindable non-loopback IPv4 address")
	return "", 0
}

func TestSelfDialAddress(t *testing.T) {
	tests := []struct {
		name string
		addr *net.TCPAddr
		want string
	}{
		{name: "IPv4 wildcard", addr: &net.TCPAddr{IP: net.IPv4zero, Port: 8080}, want: "127.0.0.1:8080"},
		{name: "IPv6 wildcard", addr: &net.TCPAddr{IP: net.IPv6zero, Port: 8080}, want: "[::1]:8080"},
		{name: "specific IPv4", addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8080}, want: "192.0.2.10:8080"},
		{name: "zoned IPv6", addr: &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 8080, Zone: "en0"}, want: "[fe80::1%en0]:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selfDialAddress(tt.addr)
			if got != tt.want {
				t.Fatalf("selfDialAddress = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNetListen_DefaultBindsLoopback(t *testing.T) {
	n := &netListen{}
	emit := discardNetworkEvent

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := n.Generate(ctx, module.Params{"port": "18083"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer n.Cleanup(context.Background()) //nolint:errcheck

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
	emit := discardNetworkEvent

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	params := module.Params{"port": "18084", "bind_addr": "0.0.0.0"}
	if err := n.Generate(ctx, params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer n.Cleanup(context.Background()) //nolint:errcheck

	addr, ok := n.listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener.Addr() is %T, want *net.TCPAddr", n.listener.Addr())
	}
	if !addr.IP.IsUnspecified() {
		t.Errorf("bound IP = %s, want 0.0.0.0 when bind_addr is set explicitly", addr.IP)
	}
}
