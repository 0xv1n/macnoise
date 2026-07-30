//go:build unix

package main

import (
	"context"
	"errors"
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
