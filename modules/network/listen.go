package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netListen struct {
	listener net.Listener
}

func (n *netListen) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_listen",
		Description: "Opens a local TCP listener and simulates an inbound connection",
		Category:    module.CategoryNetwork,
		Tags:        []string{"tcp", "listen", "inbound"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1571", Name: "Non-Standard Port"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netListen) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "port", Description: "Local port to bind", Required: false, DefaultValue: "8080", Example: "9999"},
	}
}

func (n *netListen) CheckPrereqs() error { return nil }

func (n *netListen) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	port := params.Get("port", "8080")
	address := net.JoinHostPort("0.0.0.0", port)
	info := n.Info()

	l, err := net.Listen("tcp", address)
	if err != nil {
		ev := output.NewEvent(info, "tcp_listen", false, fmt.Sprintf("failed to bind %s", address))
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	n.listener = l

	ev := output.NewEvent(info, "tcp_listen", true, fmt.Sprintf("listening on %s", address))
	ev = output.WithDetails(ev, map[string]any{"address": address})
	emit(ev)

	go func() {
		time.Sleep(200 * time.Millisecond)
		target := net.JoinHostPort("127.0.0.1", port)
		conn, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		conn.Write([]byte("TELEMETRY_PING")) //nolint:errcheck
		_ = conn.Close()
	}()

	conn, err := l.Accept()
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	accepted := output.NewEvent(info, "tcp_accept", true, fmt.Sprintf("accepted connection from %s", conn.RemoteAddr()))
	accepted = output.WithDetails(accepted, map[string]any{"remote_addr": conn.RemoteAddr().String()})
	emit(accepted)

	return nil
}

func (n *netListen) DryRun(params module.Params) []string {
	port := params.Get("port", "8080")
	return []string{
		fmt.Sprintf("bind TCP 0.0.0.0:%s", port),
		"accept one connection from self (127.0.0.1)",
	}
}

func (n *netListen) Cleanup() error {
	if n.listener != nil {
		return n.listener.Close()
	}
	return nil
}

func init() {
	module.Register(&netListen{})
}
