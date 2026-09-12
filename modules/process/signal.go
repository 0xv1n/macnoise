//go:build darwin

package process

import (
	"context"
	"errors"
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
		ev := output.NewEvent(info, "process_fork", module.OutcomeError, module.Process("sh", "/bin/sh", targetCmd, 0), "failed to fork target process")
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	pid := cmd.Process.Pid
	forkEv := output.NewEvent(info, "process_fork", module.OutcomeExecuted, module.Process("sh", "/bin/sh", targetCmd, pid), fmt.Sprintf("forked %q as PID %d", targetCmd, pid))
	forkEv = output.WithDetails(forkEv, map[string]any{"pid": pid, "command": targetCmd})
	if err := emit(forkEv); err != nil {
		return err
	}

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
		sigEv := output.NewEvent(info, "signal_send", module.OutcomeError, module.Process("sh", "/bin/sh", targetCmd, pid), fmt.Sprintf("sending %s to PID %d", s.name, pid))
		if err := cmd.Process.Signal(s.sig); err != nil {
			sigEv = output.WithError(sigEv, err)
		} else {
			sigEv.Outcome = module.OutcomeExecuted
			sigEv = output.WithDetails(sigEv, map[string]any{"signal": s.name, "pid": pid})
		}
		if err := emit(sigEv); err != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}

	cmd.Wait() //nolint:errcheck
	return nil
}
