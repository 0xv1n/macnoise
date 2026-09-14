package service

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRemoveOwnedBlock(t *testing.T) {
	owned := "\n# macnoise-marker-start mn:owned\nexport OWNED=1\n# macnoise-marker-end\n"
	other := "\n# macnoise-marker-start mn:other\nexport OTHER=1\n# macnoise-marker-end\n"
	content := "# user config\n" + other + owned + "# later user edit\n"

	got, err := removeOwnedBlock(content, owned)
	if err != nil {
		t.Fatalf("removeOwnedBlock: %v", err)
	}
	want := "# user config\n" + other + "# later user edit\n"
	if got != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestRemoveOwnedBlock_ReportsConflict(t *testing.T) {
	block := "\n# macnoise-marker-start mn:owned\npayload\n# macnoise-marker-end\n"
	for _, content := range []string{
		"# user removed it\n",
		block + block,
		"\n# macnoise-marker-start mn:owned\nchanged\n# macnoise-marker-end\n",
	} {
		if _, err := removeOwnedBlock(content, block); err == nil {
			t.Errorf("removeOwnedBlock(%q) succeeded, want ownership conflict", content)
		}
	}
}

func TestSvcShellProfileCleanup_ReportsMissingTarget(t *testing.T) {
	s := &svcShellProfile{
		targetFile: filepath.Join(t.TempDir(), "missing"),
		block:      "owned block",
	}
	if err := s.Cleanup(context.Background()); err == nil {
		t.Fatal("Cleanup succeeded, want ownership conflict")
	}
}
