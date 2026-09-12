// Package subprocess provides the shared lifecycle for synchronous child processes.
package subprocess

import (
	"context"
	"errors"
	"os/exec"
)

// Result records the observable result of a completed process invocation.
type Result struct {
	Output   []byte
	ExitCode int
}

// Run executes one process, captures its combined output, and waits for it to exit.
func Run(ctx context.Context, executable string, args ...string) (Result, error) {
	result := Result{ExitCode: -1}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	cmd := exec.CommandContext(ctx, executable, args...)
	configureCancellation(cmd)
	output, err := cmd.CombinedOutput()
	result.Output = output
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return result, errors.Join(ctxErr, err)
	}
	return result, err
}
