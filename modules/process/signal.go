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

func (p *procSignal) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	targetCmd := stampCommand(params.String("target_command", "sleep 30"), module.RunIDFromContext(ctx))
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
