//go:build unix

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// signalContext must cancel on SIGTERM so the runner's Cleanup step still runs
// when an operator interrupts a module that installed persistence.
//
// Unix-only: the test delivers a real signal to itself, which has no portable
// equivalent on Windows. CI runs unit tests on Linux, so this is covered there.
func TestSignalContextCancelsOnSignal(t *testing.T) {
	ctx, stop := signalContext()
	defer stop()

	select {
	case <-ctx.Done():
		t.Fatal("context cancelled before any signal was delivered")
	default:
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("failed to signal self: %v", err)
	}

	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("context was not cancelled within 2s of SIGTERM")
	}
}

// signalContext's stop function must be safe to call more than once, so the
// deferred cleanup path in every command is harmless on a normal run.
func TestSignalContextStopIsIdempotent(t *testing.T) {
	ctx, stop := signalContext()
	stop()
	stop()

	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Errorf("expected context cancelled after stop, got %v", ctx.Err())
	}
}

func TestConfigZeroTimeoutOverridesDefault(t *testing.T) {
	preserveCommandGlobals(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("default_timeout: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := buildRoot()
	root.SetOut(io.Discard)
	root.SetArgs([]string{"--config", path, "--format", "jsonl", "list"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if globalTimeout != 0 {
		t.Fatalf("configured timeout = %d, want 0", globalTimeout)
	}
}

func TestNegativeTimeoutFlagRejected(t *testing.T) {
	preserveCommandGlobals(t)
	root := buildRoot()
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.SetArgs([]string{"--timeout", "-1", "version"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "--timeout must be 0 or greater") {
		t.Fatalf("Execute error = %v, want negative timeout error", err)
	}
}

func preserveCommandGlobals(t *testing.T) {
	t.Helper()
	format := globalFormat
	output := globalOutput
	verbose := globalVerbose
	dryRun := globalDryRun
	noCleanup := globalNoCleanup
	timeout := globalTimeout
	auditLog := globalAuditLog
	configPath := globalConfig
	runID := globalRunID
	cfg := loadedConfig
	t.Cleanup(func() {
		globalFormat = format
		globalOutput = output
		globalVerbose = verbose
		globalDryRun = dryRun
		globalNoCleanup = noCleanup
		globalTimeout = timeout
		globalAuditLog = auditLog
		globalConfig = configPath
		globalRunID = runID
		loadedConfig = cfg
	})
}
