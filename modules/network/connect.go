// Package network provides telemetry modules for network activity simulation,
// covering TCP connections, listening sockets, HTTP beaconing, DNS resolution,
// and reverse shell patterns used for EDR and detection engineering validation.
package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netConnect struct{}

func (n *netConnect) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_connect",
		EventTypes:  []string{"tcp_connect"},
		Description: "Initiates a TCP connection to a target host",
		Category:    module.CategoryNetwork,
		Tags:        []string{"tcp", "outbound"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1095", Name: "Non-Application Layer Protocol"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netConnect) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target", Description: "Target IP or hostname", Type: module.ParamString, Default: "127.0.0.1", Example: "10.0.0.1"},
		{Name: "port", Description: "Target TCP port", Type: module.ParamInteger, Default: 8080, Example: 443, Range: &module.IntegerRange{Min: 1, Max: 65535}},
	}
}

func (n *netConnect) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (n *netConnect) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	target := params.String("target", "127.0.0.1")
	port := strconv.Itoa(params.Int("port", 8080))
	address := net.JoinHostPort(target, port)

	info := n.Info()

	ev := output.NewEvent(info, "tcp_connect", module.OutcomeError, module.Network(address, "", ""), fmt.Sprintf("dialing TCP %s", address))
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A refused dial is the environment declining, not macnoise breaking,
		// and the SYN that went out is the telemetry this module exists for.
		// net_revshell already treats the identical case this way.
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
	} else {
		_ = conn.Close()
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("TCP connection established to %s", address)
		ev = output.WithDetails(ev, map[string]any{"address": address, "protocol": "tcp"})
	}
	return emit(ev)
}

func (n *netConnect) DryRun(params module.Params) []string {
	target := params.String("target", "127.0.0.1")
	port := strconv.Itoa(params.Int("port", 8080))
	address := net.JoinHostPort(target, port)
	return []string{fmt.Sprintf("TCP dial %s with 3s timeout", address)}
}

func (n *netConnect) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &netConnect{} })
}
