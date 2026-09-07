package evasion

import (
	"os"
	"path/filepath"
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

	if err := copyExecutable(src, dst); err != nil {
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
	if err := copyExecutable(filepath.Join(t.TempDir(), "does-not-exist"), dst); err == nil {
		t.Error("expected an error copying a missing source")
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

func TestMasqueradeCleanup_RemovesStageDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "stage")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "com.apple.WindowServer"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	e := &evadeMasquerade{stageDir: dir}
	if err := e.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("stage dir should be removed, stat err = %v", err)
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
