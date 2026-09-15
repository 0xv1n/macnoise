package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/internal/catalogdoc"
	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"
)

// readRepoFile reads a path relative to the repository root. Tests run in their
// own package directory, so the two levels up are cmd/macnoise.
func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestGeneratedCatalogIsCurrent(t *testing.T) {
	want := readRepoFile(t, "docs", "module-catalog.md")
	got, err := catalogdoc.Render(module.All())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Fatal("docs/module-catalog.md is stale; run make generate-catalog")
	}
}

// Stock scenarios must parse strictly and provide valid parameters for every
// module they invoke.
func TestStockScenariosHaveValidInputs(t *testing.T) {
	dir := filepath.Join("..", "..", "configs", "scenarios")
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			return nil
		}
		if err := runner.ValidateScenario(path, nil, &module.DefaultRegistry); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

func TestScenarioTemplateIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "templates", "scenario.yaml")
	if err := runner.ValidateScenario(path, nil, &module.DefaultRegistry); err != nil {
		t.Fatal(err)
	}
}

func TestPortableRegistryIncludesNativeModules(t *testing.T) {
	for _, name := range []string{"proc_osascript", "proc_signal"} {
		if _, ok := module.Get(name); !ok {
			t.Errorf("portable registry is missing %s", name)
		}
	}
}
