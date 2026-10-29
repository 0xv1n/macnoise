//go:build unix

package subprocess

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunCancellationTerminatesProcessGroup(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	release := filepath.Join(dir, "release")
	marker := filepath.Join(dir, "survived")
	script := `(touch "$1"; while [ ! -e "$2" ]; do sleep 0.01; done; touch "$3") & wait`

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	runDone := false
	go func() {
		_, err := Run(ctx, "sh", "-c", script, "sh", ready, release, marker)
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		if err := os.WriteFile(release, []byte("release\n"), 0o600); err != nil {
			t.Errorf("release blocked child: %v", err)
		}
		if !runDone {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("Run goroutine did not exit after releasing child")
			}
		}
	})

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		runDone = true
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("descendant survived process-group cancellation: %v", err)
	}
}
