//go:build !windows

package network

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestRevShellGenerate_ConnectedExecution(t *testing.T) {
	for _, cancelShell := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelShell), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			host, port, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			var events []module.TelemetryEvent
			g := &netRevShell{}
			go func() {
				finished <- g.Generate(ctx, module.Params{"target": host, "port": port}, func(ev module.TelemetryEvent) error {
					events = append(events, ev)
					return nil
				})
			}()
			if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			defer func() {
				cancel()
				_ = conn.Close()
			}()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			command := "printf 'macnoise-connected-shell\\n'; exit 0\n"
			if cancelShell {
				command = "printf 'macnoise-connected-shell\\n'; exec /bin/sleep 30\n"
			}
			if _, err := fmt.Fprint(conn, command); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil || line != "macnoise-connected-shell\n" {
				t.Fatalf("shell output = %q, %v", line, err)
			}
			if cancelShell {
				cancel()
			}
			// Keep the peer socket open. Shell exit or cancellation must not wait
			// for a remote peer to close its side of the connection.
			select {
			case err := <-finished:
				if cancelShell && !errors.Is(err, context.Canceled) {
					t.Errorf("Generate = %v, want cancellation", err)
				} else if !cancelShell && err != nil {
					t.Errorf("Generate: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Generate did not finish while the peer remained connected")
			}
			if len(events) != 1 || events[0].EventType != "reverse_shell_attempt" || events[0].Outcome != module.OutcomeExecuted {
				t.Fatalf("events = %+v", events)
			}
			if events[0].Details["address"] != listener.Addr().String() {
				t.Errorf("address = %v", events[0].Details["address"])
			}
			if err := g.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
