//go:build darwin

package plistmod

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Each test owns a unique domain. Independent deletion still runs if Generate
// or Cleanup fails, so a regression cannot leave preferences behind.
func newModifyDomain(t *testing.T) string {
	t.Helper()
	domain := fmt.Sprintf("com.macnoise.execution.%d.%d", os.Getpid(), time.Now().UnixNano())
	defaultsCommand(t, "write", domain, "Unrelated", "-string", "keep me")
	t.Cleanup(func() { defaultsCommand(t, "delete", domain) })
	return domain
}

func defaultsCommand(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/defaults", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("defaults %q: %v: %s", args, err, out)
	}
	return strings.TrimSuffix(string(out), "\n")
}

func TestPlistModifyGenerate_WriteAndCleanup(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%v", existing), func(t *testing.T) {
			domain := newModifyDomain(t)
			const key = "Test Key"
			const prior = "original 'quoted' value with spaces"
			const value = "replacement \"quoted\" value; $(echo literal)"
			if existing {
				defaultsCommand(t, "write", domain, key, "-string", prior)
			}
			p := &plistModify{}
			var events []module.TelemetryEvent
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := p.Generate(ctx, module.Params{"domain": domain, "key": key, "value": value}, func(ev module.TelemetryEvent) {
				events = append(events, ev)
			})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if got := defaultsCommand(t, "read", domain, key); got != value {
				t.Errorf("written value = %q, want %q", got, value)
			}
			if len(events) != 2 || events[0].EventType != "plist_read_prior" || !events[0].Success ||
				events[1].EventType != "plist_modify" || !events[1].Success {
				t.Fatalf("events = %+v, want successful read then write", events)
			}
			for k, want := range map[string]string{"domain": domain, "key": key, "value": value} {
				if got := events[1].Details[k]; got != want {
					t.Errorf("write details[%s] = %v, want %q", k, got, want)
				}
			}
			if err := p.Cleanup(); err != nil {
				t.Fatalf("Cleanup: %v", err)
			}
			if existing {
				if got := defaultsCommand(t, "read", domain, key); got != prior {
					t.Errorf("restored value = %q, want %q", got, prior)
				}
				if got := defaultsCommand(t, "read-type", domain, key); got != "Type is string" {
					t.Errorf("restored type = %q, want string", got)
				}
			} else {
				out, err := exec.CommandContext(ctx, "/usr/bin/defaults", "read", domain, key).CombinedOutput()
				if err == nil || !strings.Contains(string(out), "does not exist") {
					t.Errorf("deleted key read = %q, %v; want missing key", out, err)
				}
			}
			if got := defaultsCommand(t, "read", domain, "Unrelated"); got != "keep me" {
				t.Errorf("unrelated preference = %q", got)
			}
		})
	}
}

func TestPlistModifyGenerate_RunID(t *testing.T) {
	domain := newModifyDomain(t)
	const runID = "run-123"
	stamped := domain + "." + runID
	defaultsCommand(t, "write", stamped, "Unrelated", "-string", "keep me")
	t.Cleanup(func() { defaultsCommand(t, "delete", stamped) })
	defaultsCommand(t, "write", domain, "MacnoiseTest", "-string", "base untouched")
	p := &plistModify{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var events []module.TelemetryEvent
	if err := p.Generate(module.ContextWithRunID(ctx, runID), module.Params{"domain": domain}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got := defaultsCommand(t, "read", stamped, "MacnoiseTest"); got != "true" {
		t.Errorf("stamped default value = %q, want true", got)
	}
	if len(events) != 2 || events[1].Details["domain"] != stamped || !events[1].Success {
		t.Errorf("events = %+v, want successful write to stamped domain", events)
	}
	if err := p.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if got := defaultsCommand(t, "read", domain, "MacnoiseTest"); got != "base untouched" {
		t.Errorf("base domain value = %q", got)
	}
	if got := defaultsCommand(t, "read", stamped); strings.Contains(got, "MacnoiseTest") {
		t.Errorf("stamped key remains after cleanup: %s", got)
	}
}

func TestPlistModifyGenerate_RefusesComplexValues(t *testing.T) {
	for _, kind := range []string{"array", "dict"} {
		t.Run(kind, func(t *testing.T) {
			domain := newModifyDomain(t)
			defaultsCommand(t, "write", domain, "Target", "-"+kind, "first", "second")
			before := defaultsCommand(t, "export", domain, "-")
			p := &plistModify{}
			var events []module.TelemetryEvent
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := p.Generate(ctx, module.Params{"domain": domain, "key": "Target"}, func(ev module.TelemetryEvent) {
				events = append(events, ev)
			})
			if err == nil {
				t.Error("Generate succeeded, want refusal")
			}
			if len(events) != 1 || events[0].EventType != "plist_read_prior" || events[0].Success || events[0].Error == "" {
				t.Errorf("events = %+v, want failed prior read only", events)
			}
			if err := p.Cleanup(); err != nil {
				t.Fatalf("Cleanup after refusal: %v", err)
			}
			if after := defaultsCommand(t, "export", domain, "-"); after != before {
				t.Errorf("refused preference changed:\nbefore: %s\nafter: %s", before, after)
			}
		})
	}
}
