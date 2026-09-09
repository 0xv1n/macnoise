//go:build darwin

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestOsascriptGenerate_Execution(t *testing.T) {
	for _, tt := range []struct {
		name, language, script, output, diagnostic string
	}{
		{"AppleScript", "AppleScript", `return "executed"`, "executed\n", ""},
		{"JXA", "JavaScript", `"executed"`, "executed\n", ""},
		{"AppleScript redaction", "AppleScript", "-- with hidden answer\nreturn \"private-result\"", redactedOutput, ""},
		{"JXA redaction", "JavaScript", "// hiddenAnswer: true\n\"private-result\"", redactedOutput, ""},
		{"AppleScript error redaction", "AppleScript", "-- with hidden answer\nerror \"private-result\"", redactedOutput, ""},
		{"JXA error redaction", "JavaScript", "// hiddenAnswer: true\nthrow new Error(\"private-result\")", redactedOutput, ""},
		{"AppleScript error", "AppleScript", `error "expected-failure" number 42`, "", "expected-failure"},
		{"JXA error", "JavaScript", `throw new Error("expected-failure")`, "", "expected-failure"},
		{"syntax error", "AppleScript", `return (`, "", "syntax error"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ctx = module.ContextWithRunID(ctx, "osascript-test")
			var events []module.TelemetryEvent
			p := &procOsascript{}
			err := p.Generate(ctx, module.Params{"language": tt.language, "script": tt.script}, func(ev module.TelemetryEvent) {
				events = append(events, ev)
			})
			if err != nil || len(events) != 1 {
				t.Fatalf("Generate = %v, events: %+v", err, events)
			}
			ev := events[0]
			if ev.Module != "proc_osascript" || ev.EventType != "osascript_exec" || !ev.Success || ev.Details["language"] != tt.language {
				t.Errorf("unexpected event: %+v", ev)
			}
			comment := "-- mn:osascript-test"
			if tt.language == "JavaScript" {
				comment = "// mn:osascript-test"
			}
			if ev.Details["script"] != tt.script+"\n"+comment {
				t.Errorf("stamped script = %q", ev.Details["script"])
			}
			out, ok := ev.Details["output"].(string)
			if !ok || (tt.diagnostic == "" && out != tt.output) || (tt.diagnostic != "" && !strings.Contains(out, tt.diagnostic)) {
				t.Errorf("output = %q, want %q / diagnostic %q", out, tt.output, tt.diagnostic)
			}
			_, hasError := ev.Details["error"]
			if wantError := strings.Contains(tt.name, "error"); hasError != wantError {
				t.Errorf("error detail present = %t, want %t: %+v", hasError, wantError, ev)
			}
			if err := p.Cleanup(); err != nil {
				t.Fatalf("Cleanup: %v", err)
			}
		})
	}
}

func TestOsascriptGenerate_CanceledBeforeExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (&procOsascript{}).Generate(ctx, module.Params{"script": `return "unexpected"`}, func(ev module.TelemetryEvent) {
		t.Errorf("canceled script emitted result: %+v", ev)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate = %v, want context.Canceled", err)
	}
}

func TestOsascriptGenerate_CanceledDuringExecution(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
				want = context.DeadlineExceeded
			}
			defer cancel()
			marker := filepath.Join(t.TempDir(), "started")
			// The shell exits before delay begins, leaving no child holding output pipes.
			script := fmt.Sprintf("do shell script %q\ndelay 30", "printf started > '"+marker+"'")
			var events []module.TelemetryEvent
			done := make(chan error, 1)
			go func() {
				done <- (&procOsascript{}).Generate(ctx, module.Params{"script": script}, func(ev module.TelemetryEvent) {
					events = append(events, ev)
				})
			}()
			defer func() { cancel(); <-done }()
			startLimit := time.After(5 * time.Second)
			for {
				if data, err := os.ReadFile(marker); err == nil && string(data) == "started" {
					break
				}
				select {
				case <-startLimit:
					t.Fatal("script did not write its startup marker")
				case <-time.After(10 * time.Millisecond):
				}
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				close(done)
				if !errors.Is(err, want) || len(events) != 0 {
					t.Errorf("Generate = %v, want %v without events; got %+v", err, want, events)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Generate did not stop promptly")
			}
		})
	}
}
