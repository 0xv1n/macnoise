// Package network provides telemetry modules for network activity simulation,
// covering TCP connections, listening sockets, HTTP beaconing, DNS resolution,
// and reverse shell patterns used for EDR and detection engineering validation.
package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netConnect struct{}

func (n *netConnect) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_connect",
		EventTypes:  []string{"tcp_connect", "http_get"},
		Description: "Initiates a TCP connection and HTTP GET to a target host",
		Category:    module.CategoryNetwork,
		Tags:        []string{"tcp", "http", "outbound"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1071", SubTech: ".001", Name: "Application Layer Protocol: Web Protocols"},
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
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
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
	if err := emit(ev); err != nil {
		return err
	}

	url := tagURL(fmt.Sprintf("http://%s", address), module.RunIDFromContext(ctx))
	httpEv := output.NewEvent(info, "http_get", module.OutcomeError, module.Network("", url, ""), fmt.Sprintf("HTTP GET %s", url))
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		httpEv = output.WithOutcome(httpEv, module.OutcomeDenied, err)
		httpEv.Message = fmt.Sprintf("HTTP GET %s generated telemetry (connection refused expected)", url)
	} else {
		_ = resp.Body.Close()
		httpEv.Outcome = module.OutcomeExecuted
		httpEv.Message = fmt.Sprintf("HTTP GET %s returned %d", url, resp.StatusCode)
		httpEv = output.WithDetails(httpEv, map[string]any{"url": url, "status_code": resp.StatusCode})
	}
	return emit(httpEv)
}

func (n *netConnect) DryRun(params module.Params) []string {
	target := params.String("target", "127.0.0.1")
	port := strconv.Itoa(params.Int("port", 8080))
	address := net.JoinHostPort(target, port)
	return []string{
		fmt.Sprintf("TCP dial %s with 3s timeout", address),
		fmt.Sprintf("HTTP GET http://%s with 3s timeout", address),
	}
}

func (n *netConnect) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &netConnect{} })
}
