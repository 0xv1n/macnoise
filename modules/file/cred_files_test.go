package file

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func credInfo() module.ModuleInfo {
	return (&fileCredFiles{}).Info()
}

// A public key is not a secret. Reading one and reporting it as credential
// access would be misleading telemetry, so id_*.pub must be excluded while the
// matching private key is still probed.
func TestSSHKeyPathsSkipsPublicKeys(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_rsa", "id_rsa.pub", "id_custom", "id_custom.pub", "known_hosts"} {
		if err := os.WriteFile(filepath.Join(sshDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	paths := sshKeyPaths(home)
	for _, p := range paths {
		if strings.HasSuffix(p, ".pub") {
			t.Errorf("public key was included: %s", p)
		}
		if strings.HasSuffix(p, "known_hosts") {
			t.Errorf("non key file was included: %s", p)
		}
	}
	// id_custom (present, non-standard) must be picked up by the glob.
	if !containsPath(paths, filepath.Join(sshDir, "id_custom")) {
		t.Errorf("non-standard private key id_custom was not probed: %v", paths)
	}
}

// The well-known key names are probed even when absent, so a host with no keys
// still emits credential-access telemetry rather than nothing.
func TestSSHKeyPathsAlwaysProbesWellKnownNames(t *testing.T) {
	home := t.TempDir() // no .ssh directory at all
	paths := sshKeyPaths(home)

	for _, name := range []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"} {
		if !containsPath(paths, filepath.Join(home, ".ssh", name)) {
			t.Errorf("well-known key %s not probed when absent: %v", name, paths)
		}
	}
}

// A present standard key must not be probed twice: the explicit list and the
// glob both name it, and a duplicate would double-count the read.
func TestSSHKeyPathsDeduplicates(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	paths := sshKeyPaths(home)
	seen := map[string]int{}
	for _, p := range paths {
		seen[p]++
	}
	if seen[filepath.Join(sshDir, "id_rsa")] != 1 {
		t.Errorf("id_rsa probed %d times, want 1", seen[filepath.Join(sshDir, "id_rsa")])
	}
}

func TestDefaultCredTargetsCoversEachKind(t *testing.T) {
	home := t.TempDir()
	targets := defaultCredTargets(home)

	kinds := map[string]bool{}
	for _, tg := range targets {
		kinds[tg.kind] = true
	}
	for _, want := range []string{"ssh_private_key", "aws_credentials", "kube_config", "docker_config", "dotenv"} {
		if !kinds[want] {
			t.Errorf("kind %q missing from default targets", want)
		}
	}
}

func TestParseExtraPaths(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"/a/.env", []string{"/a/.env"}},
		{"/a/.env, /b/.netrc", []string{"/a/.env", "/b/.netrc"}},
		{"/a,,  ,/b", []string{"/a", "/b"}},
	}
	for _, tt := range tests {
		got := parseExtraPaths(tt.in)
		if len(got) != len(tt.want) {
			t.Fatalf("parseExtraPaths(%q) = %v, want %v", tt.in, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseExtraPaths(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

// The read path: a present, readable credential file is reported as an executed
// read with a byte count. Works on any OS, no chmod needed.
func TestCredEventReadsPresentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	content := "[default]\naws_secret_access_key = AKIAEXAMPLE\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	ev := credEvent(credInfo(), credTarget{kind: "aws_credentials", path: path})
	if ev.EventType != "cred_file_read" {
		t.Errorf("event type = %q, want cred_file_read", ev.EventType)
	}
	// The read path leaves Outcome unset by design; it resolves to executed at
	// the emitter boundary from Success, the same as browser_creds.
	if got := ev.ResolvedOutcome(); got != module.OutcomeExecuted {
		t.Errorf("resolved outcome = %q, want executed", got)
	}
	if ev.Details["bytes_read"] != int64(len(content)) {
		t.Errorf("bytes_read = %v, want %d", ev.Details["bytes_read"], len(content))
	}
	if ev.Details["accessible"] != true {
		t.Errorf("accessible = %v, want true", ev.Details["accessible"])
	}
}

// The absent path: a missing target is indeterminate, not a denial and not a
// tool failure. No read was attempted, so no access decision was made.
func TestCredEventAbsentTargetIsIndeterminate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does_not_exist", "config")

	ev := credEvent(credInfo(), credTarget{kind: "kube_config", path: path})
	if ev.EventType != "cred_file_probe" {
		t.Errorf("event type = %q, want cred_file_probe", ev.EventType)
	}
	if ev.Outcome != module.OutcomeIndeterminate {
		t.Errorf("outcome = %q, want indeterminate", ev.Outcome)
	}
	if !ev.Success {
		t.Error("Success = false; an absent target is a valid observation")
	}
	if ev.Details["exists"] != false {
		t.Errorf("exists = %v, want false", ev.Details["exists"])
	}
}

func containsPath(paths []string, want string) bool {
	return slices.Contains(paths, want)
}

// A directory at the target path is not a credential file. It exists but holds
// nothing to read, so it is a probe rather than a denied read.
func TestCredEventDirectoryIsProbe(t *testing.T) {
	dir := t.TempDir()

	ev := credEvent(credInfo(), credTarget{kind: "dotenv", path: dir})
	if ev.Outcome != module.OutcomeIndeterminate {
		t.Errorf("outcome = %q, want indeterminate for a directory", ev.Outcome)
	}
}

func TestDryRunListsExtraPaths(t *testing.T) {
	lines := (&fileCredFiles{}).DryRun(module.Params{"paths": "/proj/.env"})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "/proj/.env") {
		t.Errorf("dry run does not mention the extra path\ngot:\n%s", joined)
	}
}
