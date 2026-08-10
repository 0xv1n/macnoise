//go:build integration && darwin

package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// A chmod-000 credential file exists but cannot be opened. That refusal is the
// detection signal, and it must read as a denied access rather than a macnoise
// failure or an absent file. os.Stat would succeed here where os.Open does not,
// which is exactly why the module reads rather than stats.
func TestCredFiles_UnreadableFileIsDeniedRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, mode bits do not deny access")
	}

	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	ev := credEvent(credInfo(), credTarget{kind: "aws_credentials", path: path})
	if ev.Outcome != module.OutcomeDenied {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
	if !ev.Success {
		t.Error("Success = false: a permission denial is expected telemetry, not a macnoise fault")
	}
	if ev.Details["accessible"] != false {
		t.Errorf("accessible = %v, want false", ev.Details["accessible"])
	}
}

// End to end through a temp HOME: a planted AWS credentials file is read, an
// absent kube config is a probe, and the run never fails.
func TestCredFiles_GenerateOverTempHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	awsDir := filepath.Join(home, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	awsCreds := filepath.Join(awsDir, "credentials")
	if err := os.WriteFile(awsCreds, []byte("[default]\naws_access_key_id = AKIA\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	if err := (&fileCredFiles{}).Generate(context.Background(), module.Params{}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var sawAWSRead, sawKubeProbe bool
	for _, ev := range events {
		kind, _ := ev.Details["kind"].(string)
		path, _ := ev.Details["path"].(string)
		switch {
		case kind == "aws_credentials" && path == awsCreds:
			if ev.EventType != "cred_file_read" || ev.ResolvedOutcome() != module.OutcomeExecuted {
				t.Errorf("aws credentials: type %q outcome %q, want cred_file_read/executed", ev.EventType, ev.ResolvedOutcome())
			}
			sawAWSRead = true
		case kind == "kube_config":
			if ev.EventType != "cred_file_probe" || ev.Outcome != module.OutcomeIndeterminate {
				t.Errorf("kube config: type %q outcome %q, want cred_file_probe/indeterminate", ev.EventType, ev.Outcome)
			}
			sawKubeProbe = true
		}
		if ev.Outcome == module.OutcomeError {
			t.Errorf("event for %s reported a macnoise failure: %s", path, ev.Error)
		}
	}
	if !sawAWSRead {
		t.Error("no read event for the planted AWS credentials file")
	}
	if !sawKubeProbe {
		t.Error("no probe event for the absent kube config")
	}
}
