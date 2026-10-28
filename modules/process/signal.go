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

func (p *procSignal) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	targetCmd := stampCommand(params.String("target_command", "sleep 30"), module.RunIDFromContext(ctx))
	info := p.Info()

	cmd := exec.Command("sh", "-c", targetCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		ev := output.NewEvent(info, "process_fork", module.OutcomeError, module.Process("sh", "/bin/sh", targetCmd, 0), "failed to fork target process")
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}
	pid := cmd.Process.Pid
	defer func() {
		killErr := syscall.Kill(-pid, syscall.SIGKILL)
		var processErr error
		if killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
			processErr = cmd.Process.Kill()
			if errors.Is(processErr, os.ErrProcessDone) {
				processErr = nil
			}
		}
		if waitErr := cmd.Wait(); waitErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) {
				resultErr = errors.Join(resultErr, fmt.Errorf("wait for target process: %w", waitErr))
			}
		}
		// macOS may return EPERM while the dead group leader is unreaped.
		// Retry after Wait to clean descendants or observe that the group is gone.
		if errors.Is(killErr, syscall.EPERM) {
			killErr = syscall.Kill(-pid, syscall.SIGKILL)
			processErr = nil
		}
		if errors.Is(killErr, syscall.ESRCH) {
			killErr = nil
		}
		if err := errors.Join(killErr, processErr); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("clean up process group: %w", err))
		}
	}()

	forkEv := output.NewEvent(info, "process_fork", module.OutcomeExecuted, module.Process("sh", "/bin/sh", targetCmd, pid), fmt.Sprintf("forked %q as PID %d", targetCmd, pid))
	forkEv = output.WithDetails(forkEv, map[string]any{"pid": pid, "command": targetCmd})
	if err := emit(forkEv); err != nil {
		return err
	}

	if err := waitForSignalDelay(ctx, 100*time.Millisecond); err != nil {
		return err
	}

	signals := []struct {
		name string
		sig  os.Signal
	}{
		{"SIGSTOP", syscall.SIGSTOP},
		{"SIGCONT", syscall.SIGCONT},
		{"SIGTERM", syscall.SIGTERM},
	}

	for _, s := range signals {
		if err := ctx.Err(); err != nil {
			return err
		}
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
		if err := waitForSignalDelay(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}

	return nil
}

func waitForSignalDelay(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
