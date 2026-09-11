//go:build integration && darwin

package service

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

// These tests mutate the account's real crontab. Run on a dedicated test
// account, without concurrent crontab writers or other copies of this suite.
// Restoration is independent of svcCron so it also runs after a regression.
func cronSnapshot(t *testing.T) (string, bool) {
	t.Helper()
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("LC_ALL", "C")
	original, present := cronRead(t)
	t.Cleanup(func() {
		if present {
			cronInstall(t, original)
		} else {
			// Cleanup may already have removed the crontab.
			if _, exists := cronRead(t); exists {
				out, err := cronCommand("", "-r")
				if err != nil {
					t.Fatalf("restore absent crontab: %v: %s", err, out)
				}
			}
		}
		if got, exists := cronRead(t); got != original || exists != present {
			t.Errorf("independent crontab restoration failed")
		}
	})
	return original, present
}

func cronCommand(input string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/crontab", args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func cronRead(t *testing.T) (string, bool) {
	t.Helper()
	out, err := cronCommand("", "-l")
	if err != nil {
		if strings.Contains(out, "no crontab for") {
			return "", false
		}
		t.Fatalf("crontab -l: %v: %s", err, out)
	}
	return out, true
}

func cronInstall(t *testing.T, contents string) {
	t.Helper()
	if out, err := cronCommand(contents, "-"); err != nil {
		t.Fatalf("crontab install: %v: %s", err, out)
	}
}

func TestCronGenerate_InstallAndCleanup(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%v", existing), func(t *testing.T) {
			original, present := cronSnapshot(t)
			if !existing && present {
				t.Skip("absent-crontab case requires an account without a crontab")
			}
			runID := fmt.Sprintf("cron-exec-%d-%d", os.Getpid(), time.Now().UnixNano())
			baseline := original
			if existing {
				baseline += "# preserve this comment\n0 0 1 1 * /usr/bin/true # macnoise another-run\n"
				cronInstall(t, baseline)
			}
			s := &svcCron{}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ctx = module.ContextWithRunID(ctx, runID)
			var events []module.TelemetryEvent
			params := module.Params{"schedule": "0 0 1 1 *", "command": "/usr/bin/true"}
			if err := s.Generate(ctx, params, func(ev module.TelemetryEvent) {
				events = append(events, ev)
			}); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			entry := "0 0 1 1 * /usr/bin/true # macnoise " + runID
			installed, exists := cronRead(t)
			want := strings.TrimRight(baseline, "\n") + "\n" + entry + "\n"
			if !exists || installed != want {
				t.Fatalf("installed crontab = %q, want %q", installed, want)
			}
			if len(events) != 2 || events[0].EventType != "cron_job_list" || !events[0].Success ||
				events[1].EventType != "cron_job_create" || !events[1].Success {
				t.Fatalf("events = %+v, want successful list then create", events)
			}
			if got := events[0].Details["entries"]; got != baseline {
				t.Errorf("listed entries = %q, want %q", got, baseline)
			}
			for key, want := range map[string]string{"schedule": "0 0 1 1 *", "command": "/usr/bin/true", "entry": entry} {
				if got := events[1].Details[key]; got != want {
					t.Errorf("create details[%s] = %v, want %q", key, got, want)
				}
			}
			// A later writer's entry must survive cleanup too.
			const later = "0 0 2 1 * /usr/bin/true # keep later entry\n"
			cronInstall(t, installed+later)
			if err := s.Cleanup(); err != nil {
				t.Fatalf("Cleanup: %v", err)
			}
			want = strings.TrimRight(baseline, "\n") + "\n" + later
			if got, _ := cronRead(t); got != want {
				t.Errorf("crontab after cleanup = %q, want %q", got, want)
			}
			if err := s.Cleanup(); err != nil {
				t.Fatalf("second Cleanup: %v", err)
			}
			if got, _ := cronRead(t); got != want {
				t.Errorf("second cleanup changed crontab: %q", got)
			}
		})
	}
}

func TestCronGenerate_InvalidSchedule(t *testing.T) {
	original, _ := cronSnapshot(t)
	baseline := original + "# preserve on failed install\n0 0 1 1 * /usr/bin/true\n"
	cronInstall(t, baseline)
	s := &svcCron{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var events []module.TelemetryEvent
	err := s.Generate(ctx, module.Params{"schedule": "invalid", "command": "/usr/bin/true"}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 2 || events[0].EventType != "cron_job_list" || !events[0].Success ||
		events[1].EventType != "cron_job_create" || events[1].Success ||
		events[1].Outcome != module.OutcomeError || events[1].Error == "" {
		t.Fatalf("events = %+v, want successful list then install error", events)
	}
	if got, _ := cronRead(t); got != baseline {
		t.Errorf("failed install changed crontab: %q", got)
	}
	if err := s.Cleanup(); err != nil {
		t.Fatalf("Cleanup after failed install: %v", err)
	}
	if got, _ := cronRead(t); got != baseline {
		t.Errorf("cleanup after failed install changed crontab: %q", got)
	}
}
