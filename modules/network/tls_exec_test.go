package network

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestTLSGenerate_Handshakes(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "insecure"}[insecure], func(t *testing.T) {
			hellos := make(chan string, 2)
			ts := httptest.NewUnstartedServer(nil)
			ts.Config.ErrorLog = log.New(io.Discard, "", 0)
			ts.TLS = &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					hellos <- hello.ServerName
					return nil, nil
				},
			}
			ts.StartTLS()
			defer ts.Close()
			_, port, err := net.SplitHostPort(ts.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			target := net.JoinHostPort("localhost", port)
			params := module.Params{"targets": " , " + target + ",, " + target + " , "}
			if insecure {
				params["insecure"] = "true"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var events []module.TelemetryEvent
			mod := &netTLS{}
			if err := mod.Generate(ctx, params, captureNetworkEvents(&events)); err != nil {
				t.Fatal(err)
			}
			if len(events) != 2 || len(hellos) != 2 {
				t.Fatalf("got %d events and %d ClientHellos, want 2 each", len(events), len(hellos))
			}
			for _, ev := range events {
				if sni := <-hellos; sni != "localhost" {
					t.Errorf("server received SNI %q", sni)
				}
				if ev.Module != "net_tls" || ev.EventType != "tls_connect" || ev.Outcome == module.OutcomeError {
					t.Errorf("event = %+v", ev)
				}
				if ev.Details["target"] != target || ev.Details["sni"] != "localhost" || ev.Details["insecure"] != insecure {
					t.Errorf("details = %+v", ev.Details)
				}
				if insecure {
					if ev.Outcome != module.OutcomeExecuted || ev.Error != "" || ev.Details["tls_version"] != "TLS 1.2" {
						t.Errorf("handshake result = %+v", ev)
					}
					cipher, _ := ev.Details["cipher_suite"].(string)
					if !strings.HasPrefix(cipher, "TLS_") || ev.Details["cert_subject"] != ts.Certificate().Subject.String() || ev.Details["cert_issuer"] != ts.Certificate().Issuer.String() {
						t.Errorf("handshake metadata = %+v", ev.Details)
					}
				} else if ev.Outcome != module.OutcomeDenied || ev.Error == "" || ev.Details["tls_version"] != nil {
					t.Errorf("untrusted certificate result = %+v", ev)
				}
			}
			if err := mod.Cleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSGenerate_CancelInFlight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
		var first [1]byte
		if _, err := io.ReadFull(conn, first[:]); err != nil {
			closed <- err
			return
		}
		// Cancel only after the client starts its handshake. Never answer it.
		cancel()
		_, err = io.Copy(io.Discard, conn)
		closed <- err
	}()
	var events []module.TelemetryEvent
	start := time.Now()
	err = (&netTLS{}).Generate(ctx, module.Params{"targets": ln.Addr().String()}, captureNetworkEvents(&events))
	if !errors.Is(err, context.Canceled) || len(events) != 0 {
		t.Errorf("Generate = %v, events = %+v; want canceled with no completed event", err, events)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("cancellation took %v, want less than 2s", elapsed)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("server connection did not close cleanly: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("server connection did not close")
	}
}

func TestTLSGenerate_CancelBetweenTargets(t *testing.T) {
	addr := selfSignedTLSListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []module.TelemetryEvent
	err := (&netTLS{}).Generate(ctx, module.Params{"targets": addr + "," + addr, "insecure": "true"}, func(ev module.TelemetryEvent) error {
		events = append(events, ev)
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || len(events) != 1 || events[0].Outcome != module.OutcomeExecuted {
		t.Fatalf("Generate = %v, events = %+v; want canceled after one handshake", err, events)
	}
}

func TestTLSGenerate_RefusedIsDenied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	var events []module.TelemetryEvent
	if err := (&netTLS{}).Generate(context.Background(), module.Params{"targets": target}, captureNetworkEvents(&events)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	ev := events[0]
	if ev.Outcome != module.OutcomeDenied || ev.Error == "" || ev.Details["target"] != target || ev.Details["tls_version"] != nil {
		t.Errorf("refused connection = %+v", ev)
	}
}

func TestTLSGenerate_AlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (&netTLS{}).Generate(ctx, module.Params{"targets": "127.0.0.1:1"}, func(ev module.TelemetryEvent) error {
		t.Errorf("already canceled run emitted %+v", ev)
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate = %v, want context.Canceled", err)
	}
}
