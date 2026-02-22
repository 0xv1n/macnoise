//go:build darwin

package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procSignal struct{}

func (p *procSignal) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_signal",
		Description: "Forks a process then sends signals (SIGTERM, SIGSTOP, SIGCONT) to generate signal telemetry",
		Category:    module.CategoryProcess,
		Tags:        []string{"signal", "process", "fork"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1106", Name: "Native API"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (p *procSignal) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target_command", Description: "Command to spawn as signal target", Required: false, DefaultValue: "sleep 30", Example: "sleep 60"},
	}
}

func (p *procSignal) CheckPrereqs() error { return nil }

func (p *procSignal) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	targetCmd := params.Get("target_command", "sleep 30")
	info := p.Info()

	cmd := exec.CommandContext(ctx, "sh", "-c", targetCmd)
	if err := cmd.Start(); err != nil {
		ev := output.NewEvent(info, "process_fork", false, "failed to fork target process")
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}

	pid := cmd.Process.Pid
	forkEv := output.NewEvent(info, "process_fork", true, fmt.Sprintf("forked %q as PID %d", targetCmd, pid))
	forkEv = output.WithDetails(forkEv, map[string]any{"pid": pid, "command": targetCmd})
	emit(forkEv)

	time.Sleep(100 * time.Millisecond)

	signals := []struct {
		name string
		sig  os.Signal
	}{
		{"SIGSTOP", syscall.SIGSTOP},
		{"SIGCONT", syscall.SIGCONT},
		{"SIGTERM", syscall.SIGTERM},
	}

	for _, s := range signals {
		sigEv := output.NewEvent(info, "signal_send", false, fmt.Sprintf("sending %s to PID %d", s.name, pid))
		if err := cmd.Process.Signal(s.sig); err != nil {
			sigEv = output.WithError(sigEv, err)
		} else {
			sigEv.Success = true
			sigEv = output.WithDetails(sigEv, map[string]any{"signal": s.name, "pid": pid})
		}
		emit(sigEv)
		time.Sleep(50 * time.Millisecond)
	}

	cmd.Wait() //nolint:errcheck
	return nil
}

func (p *procSignal) DryRun(params module.Params) []string {
	targetCmd := params.Get("target_command", "sleep 30")
	return []string{
		fmt.Sprintf("fork: sh -c %q", targetCmd),
		"send SIGSTOP, SIGCONT, SIGTERM to forked PID",
	}
}

func (p *procSignal) Cleanup() error { return nil }

func init() {
	module.Register(&procSignal{})
}
