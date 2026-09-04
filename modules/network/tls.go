package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netTLS struct{}

func (n *netTLS) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_tls",
		EventTypes:  []string{"tls_connect"},
		Description: "Performs TLS handshakes to configurable endpoints and reports negotiated version, cipher suite, and certificate subject",
		Category:    module.CategoryNetwork,
		Tags:        []string{"tls", "encrypted", "handshake", "sni", "ja3"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1573", SubTech: ".002", Name: "Encrypted Channel: Asymmetric Cryptography"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netTLS) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "targets",
			Description:  "Comma-separated host:port pairs to connect to",
			Required:     false,
			DefaultValue: "example.com:443,github.com:443",
			Example:      "10.0.0.1:8443,c2.attacker.invalid:443",
		},
		{
			Name:         "insecure",
			Description:  "Skip certificate verification (true/false)",
			Required:     false,
			DefaultValue: "false",
			Example:      "true",
		},
	}
}

func (n *netTLS) CheckPrereqs() error { return nil }

// tlsConnect dials one target and returns the event. Extracted so the
// handshake metadata parsing is testable against a local TLS server.
func tlsConnect(ctx context.Context, info module.ModuleInfo, target string, insecure bool) module.TelemetryEvent {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure,
	}

	ev := output.NewEvent(info, "tls_connect", false,
		fmt.Sprintf("TLS handshake %s (SNI: %s)", target, host))

	conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
	if err != nil {
		ev.Success = true
		ev.Message = fmt.Sprintf("TLS handshake %s failed (telemetry generated)", target)
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		return output.WithDetails(ev, map[string]any{
			"target":   target,
			"sni":      host,
			"insecure": insecure,
		})
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	details := map[string]any{
		"target":       target,
		"sni":          host,
		"insecure":     insecure,
		"tls_version":  tls.VersionName(state.Version),
		"cipher_suite": tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		details["cert_subject"] = leaf.Subject.String()
		details["cert_issuer"] = leaf.Issuer.String()
	}

	ev.Success = true
	ev.Message = fmt.Sprintf("TLS %s to %s, cipher %s",
		tls.VersionName(state.Version), target, tls.CipherSuiteName(state.CipherSuite))
	return output.WithDetails(ev, details)
}

func (n *netTLS) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	targetsStr := params.Get("targets", "example.com:443,github.com:443")
	insecure := params.Get("insecure", "false") == "true"
	info := n.Info()

	for _, raw := range strings.Split(targetsStr, ",") {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		emit(tlsConnect(ctx, info, target, insecure))
	}
	return nil
}

func (n *netTLS) DryRun(params module.Params) []string {
	targetsStr := params.Get("targets", "example.com:443,github.com:443")
	insecure := params.Get("insecure", "false") == "true"
	var steps []string
	for _, raw := range strings.Split(targetsStr, ",") {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		mode := "verify"
		if insecure {
			mode = "insecure"
		}
		steps = append(steps, fmt.Sprintf("TLS dial %s (%s)", target, mode))
	}
	return steps
}

func (n *netTLS) Cleanup() error { return nil }

func init() {
	module.Register(&netTLS{})
}
