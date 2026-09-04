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
		EventTypes:  []string{"tcp_listen", "tcp_accept"},
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
		{Name: "bind_addr", Description: "Address to bind", Required: false, DefaultValue: "127.0.0.1", Example: "0.0.0.0"},
	}
}

func (n *netListen) CheckPrereqs() error { return nil }

func (n *netListen) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	port := params.Get("port", "8080")
	bindAddr := params.Get("bind_addr", "127.0.0.1")
	address := net.JoinHostPort(bindAddr, port)
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

	payload := "TELEMETRY_PING"
	if runID := module.RunIDFromContext(ctx); runID != "" {
		payload += " mn:" + runID
	}

	go func() {
		time.Sleep(200 * time.Millisecond)
		target := net.JoinHostPort("127.0.0.1", port)
		conn, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		conn.Write([]byte(payload)) //nolint:errcheck
		_ = conn.Close()
	}()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := l.Accept()
		acceptCh <- acceptResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		_ = l.Close()
		return ctx.Err()
	case res := <-acceptCh:
		if res.err != nil {
			return nil
		}
		defer func() { _ = res.conn.Close() }()

		accepted := output.NewEvent(info, "tcp_accept", true, fmt.Sprintf("accepted connection from %s", res.conn.RemoteAddr()))
		accepted = output.WithDetails(accepted, map[string]any{"remote_addr": res.conn.RemoteAddr().String()})
		emit(accepted)
		return nil
	}
}

func (n *netListen) DryRun(params module.Params) []string {
	port := params.Get("port", "8080")
	bindAddr := params.Get("bind_addr", "127.0.0.1")
	return []string{
		fmt.Sprintf("bind TCP %s:%s", bindAddr, port),
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
