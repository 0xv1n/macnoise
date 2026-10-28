package evasion

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestCopyExecutable_CopiesContentAndIsExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("#!/bin/sh\ntrue\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := copyExecutable(src, dst); err != nil {
		t.Fatalf("copyExecutable: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "#!/bin/sh\ntrue\n" {
		t.Errorf("copied content = %q, want the source content", got)
	}
	// The copy must be executable, otherwise the masquerading exec cannot launch.
	// Mode bits are a Unix concept; on Windows the exec bit is not represented.
	if fi, _ := os.Stat(dst); fi.Mode().Perm()&0o111 == 0 && os.PathSeparator == '/' {
		t.Errorf("copied file mode = %v, want executable", fi.Mode().Perm())
	}
}

func TestCopyExecutable_MissingSourceErrors(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "dst")
	if _, err := copyExecutable(filepath.Join(t.TempDir(), "does-not-exist"), dst); err == nil {
		t.Error("expected an error copying a missing source")
	}
}

func TestCopyExecutable_RefusesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("keep"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := copyExecutable(src, dst); err == nil {
		t.Fatal("copyExecutable overwrote an existing destination")
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "keep" {
		t.Fatalf("existing destination changed: data=%q err=%v", data, err)
	}
}

func TestMasqueradeDryRun(t *testing.T) {
	steps := (&evadeMasquerade{}).DryRun(module.Params{
		"stage_dir":       "/tmp/mq",
		"source_binary":   "/usr/bin/true",
		"masquerade_name": "com.apple.WindowServer",
	})
	if len(steps) != 2 {
		t.Fatalf("dry run = %v, want 2 steps", steps)
	}
	joined := strings.Join(steps, "\n")
	// The dest path is built with filepath.Join, so match the OS separator the
	// module actually produces rather than assuming forward slashes.
	dest := filepath.Join("/tmp/mq", "com.apple.WindowServer")
	for _, want := range []string{"/usr/bin/true", "com.apple.WindowServer", dest} {
		if !strings.Contains(joined, want) {
			t.Errorf("dry run missing %q:\n%s", want, joined)
		}
	}
}

func TestMasqueradeGenerateRejectsEscapingName(t *testing.T) {
	requireExecutableScripts(t)
	dir := t.TempDir()
	stage := filepath.Join(dir, "stage")
	source := writeMasqueradeSource(t, dir)
	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := (&evadeMasquerade{}).Generate(context.Background(), module.Params{
		"stage_dir":       stage,
		"source_binary":   source,
		"masquerade_name": "../outside",
	}, discardEvasionEvent)
	if err == nil {
		t.Fatal("Generate accepted a masquerade name outside the staging directory")
	}
	if data, readErr := os.ReadFile(outside); readErr != nil || string(data) != "keep" {
		t.Fatalf("outside file changed: data=%q err=%v", data, readErr)
	}
}

func TestMasqueradeCleanupRemovesOwnedStageDir(t *testing.T) {
	requireExecutableScripts(t)
	stage := filepath.Join(t.TempDir(), "stage")
	e, _ := generateMasquerade(t, stage)
	if err := e.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Errorf("stage dir should be removed, stat err = %v", err)
	}
}

func TestMasqueradeCleanupPreservesPreexistingStageDir(t *testing.T) {
	requireExecutableScripts(t)
	stage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(stage, "unrelated")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, destination := generateMasquerade(t, stage)
	if err := e.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if data, err := os.ReadFile(unrelated); err != nil || string(data) != "keep" {
		t.Fatalf("pre-existing stage content changed: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("owned destination survived cleanup: %v", err)
	}
}

func TestMasqueradeCleanupRefusesChangedDestination(t *testing.T) {
	requireExecutableScripts(t)
	stage := filepath.Join(t.TempDir(), "stage")
	e, destination := generateMasquerade(t, stage)
	if err := os.WriteFile(destination, []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := e.Cleanup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cleanup conflict") {
		t.Fatalf("Cleanup = %v, want conflict", err)
	}
	if data, readErr := os.ReadFile(destination); readErr != nil || string(data) != "changed" {
		t.Fatalf("changed destination was not preserved: data=%q err=%v", data, readErr)
	}
}

func TestMasqueradeInfo_HasMasqueradingMITRE(t *testing.T) {
	mitre := (&evadeMasquerade{}).Info().MITRE
	if len(mitre) != 2 {
		t.Fatalf("expected 2 MITRE entries, got %d", len(mitre))
	}
	for _, m := range mitre {
		if m.Technique != "T1036" {
			t.Errorf("technique = %q, want T1036", m.Technique)
		}
	}
}

func generateMasquerade(t *testing.T, stage string) (*evadeMasquerade, string) {
	t.Helper()
	source := writeMasqueradeSource(t, t.TempDir())
	const name = "com.apple.WindowServer"
	e := &evadeMasquerade{}
	if err := e.Generate(context.Background(), module.Params{
		"stage_dir":       stage,
		"source_binary":   source,
		"masquerade_name": name,
	}, discardEvasionEvent); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return e, filepath.Join(stage, name)
}

func writeMasqueradeSource(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "source.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireExecutableScripts(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("executable shell scripts are not supported on Windows")
	}
}

func discardEvasionEvent(module.TelemetryEvent) error { return nil }
