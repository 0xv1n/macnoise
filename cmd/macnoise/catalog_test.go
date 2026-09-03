package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// list --format jsonl must emit one valid CatalogEntry per registered module,
// so a consumer can enumerate the module set programmatically.
func TestListJSONLCatalog(t *testing.T) {
	globalFormat = "jsonl"
	t.Cleanup(func() { globalFormat = "human" })

	cmd := buildList()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("list --format jsonl: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != len(module.All()) {
		t.Fatalf("emitted %d catalog lines, want %d registered modules", len(lines), len(module.All()))
	}

	for i, line := range lines {
		var e module.CatalogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d is not valid JSON: %v\n%s", i, err, line)
			continue
		}
		if e.Name == "" || e.Category == "" {
			t.Errorf("line %d missing name/category: %s", i, line)
		}
	}
}

// A bad --format must be rejected rather than silently falling back to the
// human table.
func TestListRejectsBadFormat(t *testing.T) {
	globalFormat = "garbage"
	t.Cleanup(func() { globalFormat = "human" })

	cmd := buildList()
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Error("expected an error for an invalid --format, got nil")
	}
}
