//go:build unix

package file

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileModulesRejectFIFOsPromptly(t *testing.T) {
	for _, operation := range []string{"read", "copy"} {
		for _, linked := range []bool{false, true} {
			name := operation + "/fifo"
			if linked {
				name = operation + "/symlink-to-fifo"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				fifo := filepath.Join(dir, "pipe")
				if err := syscall.Mkfifo(fifo, 0o600); err != nil {
					t.Fatal(err)
				}
				path := fifo
				if linked {
					path = filepath.Join(dir, "link")
					if err := os.Symlink(fifo, path); err != nil {
						t.Fatal(err)
					}
				}

				ctx, outputs := outputContext()
				var events []module.TelemetryEvent
				f := &fileCopy{}
				if operation == "copy" {
					t.Cleanup(func() {
						if err := f.Cleanup(context.Background()); err != nil {
							t.Error(err)
						}
					})
				}
				generate := func() error {
					if operation == "read" {
						return (&fileRead{}).Generate(ctx, module.Params{"paths": []string{path}}, func(ev module.TelemetryEvent) error {
							events = append(events, ev)
							return nil
						})
					}
					return f.Generate(ctx, module.Params{"source_paths": []string{path}, "destination_dir": filepath.Join(dir, "stage")}, func(ev module.TelemetryEvent) error {
						events = append(events, ev)
						return nil
					})
				}
				done := make(chan error, 1)
				go func() { done <- generate() }()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					unblockFIFOOpen(t, fifo)
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Fatal("module did not return after FIFO open was released")
					}
					t.Fatal("module blocked while opening a FIFO")
				}

				if len(events) != 1 || events[0].Outcome != module.OutcomeIndeterminate {
					t.Fatalf("events = %+v, want one indeterminate event", events)
				}
				if paths, ok := outputs["paths"].([]string); !ok || len(paths) != 0 {
					t.Fatalf("published paths = %#v, want none", outputs["paths"])
				}
			})
		}
	}
}

func TestFileModulesFollowSymlinksToRegularFiles(t *testing.T) {
	for _, operation := range []string{"read", "copy"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}

			ctx, outputs := outputContext()
			var events []module.TelemetryEvent
			emit := func(ev module.TelemetryEvent) error {
				events = append(events, ev)
				return nil
			}
			if operation == "read" {
				if err := (&fileRead{}).Generate(ctx, module.Params{"paths": []string{link}}, emit); err != nil {
					t.Fatal(err)
				}
			} else {
				f := &fileCopy{}
				if err := f.Generate(ctx, module.Params{"source_paths": []string{link}, "destination_dir": filepath.Join(dir, "stage")}, emit); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := f.Cleanup(context.Background()); err != nil {
						t.Error(err)
					}
				}()
			}

			if len(events) == 0 || events[0].Outcome != module.OutcomeExecuted {
				t.Fatalf("events = %+v, want an executed event", events)
			}
			paths, ok := outputs["paths"].([]string)
			if !ok || len(paths) != 1 {
				t.Fatalf("published paths = %#v, want one path", outputs["paths"])
			}
		})
	}
}

func unblockFIFOOpen(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("release blocked FIFO open: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
