package network

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netDNS struct{}

func (n *netDNS) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_dns",
		Description: "Performs DNS resolution of configurable domains to generate DNS telemetry",
		Category:    module.CategoryNetwork,
		Tags:        []string{"dns", "lookup", "outbound"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1071", SubTech: ".004", Name: "Application Layer Protocol: DNS"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netDNS) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "domains",
			Description:  "Comma-separated list of domains to resolve",
			Required:     false,
			DefaultValue: "example.com,google.com,github.com",
			Example:      "internal.corp,10.0.0.1.xip.io",
		},
	}
}

func (n *netDNS) CheckPrereqs() error { return nil }

func (n *netDNS) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	domainsStr := params.Get("domains", "example.com,google.com,github.com")
	domains := strings.Split(domainsStr, ",")
	info := n.Info()

	resolver := net.DefaultResolver
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		ev := output.NewEvent(info, "dns_lookup", false, fmt.Sprintf("resolving %s", domain))
		addrs, err := resolver.LookupHost(ctx, domain)
		if err != nil {
			ev = output.WithError(ev, err)
			ev.Success = true
			ev.Message = fmt.Sprintf("DNS lookup %s failed (telemetry generated)", domain)
		} else {
			ev.Success = true
			ev.Message = fmt.Sprintf("DNS lookup %s resolved to %s", domain, strings.Join(addrs, ", "))
			ev = output.WithDetails(ev, map[string]any{"domain": domain, "addresses": addrs})
		}
		emit(ev)
	}
	return nil
}

func (n *netDNS) DryRun(params module.Params) []string {
	domains := params.Get("domains", "example.com,google.com,github.com")
	return []string{
		fmt.Sprintf("DNS resolve: %s", domains),
	}
}

func (n *netDNS) Cleanup() error { return nil }

func init() {
	module.Register(&netDNS{})
}
