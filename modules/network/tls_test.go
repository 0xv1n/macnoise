package network

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

// selfSignedTLSListener starts a TLS listener on localhost with a fresh
// self-signed certificate and returns its address. The listener accepts
// one connection (enough for a single test dial) and then closes.
func selfSignedTLSListener(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

func TestTLSConnect_Handshake(t *testing.T) {
	addr := selfSignedTLSListener(t)
	info := (&netTLS{}).Info()

	ev := tlsConnect(context.Background(), info, addr, true)
	if ev.EventType != "tls_connect" {
		t.Fatalf("event type = %q, want tls_connect", ev.EventType)
	}
	if !ev.Success {
		t.Fatalf("handshake failed: %s", ev.Message)
	}
	details := ev.Details
	if details == nil {
		t.Fatal("event has no details")
	}
	if v, ok := details["tls_version"].(string); !ok || v == "" {
		t.Error("tls_version missing or empty")
	}
	if v, ok := details["cipher_suite"].(string); !ok || v == "" {
		t.Error("cipher_suite missing or empty")
	}
	if v, ok := details["sni"].(string); !ok || v == "" {
		t.Error("sni missing or empty")
	}
}

func TestTLSConnect_RefusedIsTelemetry(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	info := (&netTLS{}).Info()
	ev := tlsConnect(context.Background(), info, addr, true)
	if !ev.Success {
		t.Error("refused connection should still report success=true")
	}
	if ev.Details["tls_version"] != nil {
		t.Error("refused connection should not have tls_version")
	}
}

func TestTLSConnect_CertDetails(t *testing.T) {
	addr := selfSignedTLSListener(t)
	info := (&netTLS{}).Info()

	ev := tlsConnect(context.Background(), info, addr, true)
	if ev.Details["cert_subject"] == nil {
		t.Error("expected cert_subject in details")
	}
}

func TestTLSDryRunMatchesTargets(t *testing.T) {
	mod := &netTLS{}
	steps := mod.DryRun(module.Params{})
	targets := strings.Split("example.com:443,github.com:443", ",")
	if len(steps) != len(targets) {
		t.Errorf("dry run listed %d steps, want %d", len(steps), len(targets))
	}
}

func TestTLSDryRunInsecureLabel(t *testing.T) {
	mod := &netTLS{}
	steps := mod.DryRun(module.Params{"insecure": "true"})
	for _, s := range steps {
		if !strings.Contains(s, "insecure") {
			t.Errorf("insecure mode not reflected in dry run: %s", s)
		}
	}
}
