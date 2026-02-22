// Package network provides telemetry modules for network activity simulation,
// covering TCP connections, listening sockets, HTTP beaconing, DNS resolution,
// and reverse shell patterns used for EDR and detection engineering validation.
package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netConnect struct{}

func (n *netConnect) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_connect",
		Description: "Initiates a TCP connection and HTTP GET to a target host",
		Category:    module.CategoryNetwork,
		Tags:        []string{"tcp", "http", "outbound"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1071", SubTech: ".001", Name: "Application Layer Protocol: Web Protocols"},
			{Technique: "T1043", Name: "Commonly Used Port"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netConnect) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target", Description: "Target IP or hostname", Required: false, DefaultValue: "127.0.0.1", Example: "10.0.0.1"},
		{Name: "port", Description: "Target TCP port", Required: false, DefaultValue: "8080", Example: "443"},
	}
}

func (n *netConnect) CheckPrereqs() error { return nil }

func (n *netConnect) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	target := params.Get("target", "127.0.0.1")
	port := params.Get("port", "8080")
	address := net.JoinHostPort(target, port)

	info := n.Info()

	ev := output.NewEvent(info, "tcp_connect", false, fmt.Sprintf("dialing TCP %s", address))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		ev = output.WithError(ev, err)
		emit(ev)
	} else {
		_ = conn.Close()
		ev.Success = true
		ev.Message = fmt.Sprintf("TCP connection established to %s", address)
		ev = output.WithDetails(ev, map[string]any{"address": address, "protocol": "tcp"})
		emit(ev)
	}

	url := fmt.Sprintf("http://%s", address)
	httpEv := output.NewEvent(info, "http_get", false, fmt.Sprintf("HTTP GET %s", url))
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		httpEv = output.WithError(httpEv, err)
		httpEv.Success = true
		httpEv.Message = fmt.Sprintf("HTTP GET %s generated telemetry (connection refused expected)", url)
	} else {
		_ = resp.Body.Close()
		httpEv.Success = true
		httpEv.Message = fmt.Sprintf("HTTP GET %s returned %d", url, resp.StatusCode)
		httpEv = output.WithDetails(httpEv, map[string]any{"url": url, "status_code": resp.StatusCode})
	}
	emit(httpEv)

	return nil
}

func (n *netConnect) DryRun(params module.Params) []string {
	target := params.Get("target", "127.0.0.1")
	port := params.Get("port", "8080")
	address := net.JoinHostPort(target, port)
	return []string{
		fmt.Sprintf("TCP dial %s with 3s timeout", address),
		fmt.Sprintf("HTTP GET http://%s with 3s timeout", address),
	}
}

func (n *netConnect) Cleanup() error { return nil }

func init() {
	module.Register(&netConnect{})
}
