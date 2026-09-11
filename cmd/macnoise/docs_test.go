package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// Every registered module must appear in the top-level README table and in its
// category README.
//
// This gate exists because the drift recurs rather than because it is severe:
// each of es_mount, svc_login_item, tcc_accessibility, tcc_screen_recording,
// and file_cred_files shipped without being added to the table, and nothing
// failed. A hand-maintained list of generated facts needs a check or it goes
// stale silently, the same reason a gofmt linter was added rather than
// reformatting the three files that had drifted at the time.
//
// This package blank-imports every module package, so module.All() here is the
// same set the binary exposes.
func TestDocsListEveryRegisteredModule(t *testing.T) {
	readme := readRepoFile(t, "README.md")

	categoryDocs := map[module.Category]string{}
	for _, g := range module.All() {
		info := g.Info()

		if !strings.Contains(readme, info.Name) {
			t.Errorf("%s is registered but missing from the README module table", info.Name)
		}

		// Category values match the directory names under modules/.
		doc, ok := categoryDocs[info.Category]
		if !ok {
			doc = readRepoFile(t, "modules", string(info.Category), "README.md")
			categoryDocs[info.Category] = doc
		}
		if !strings.Contains(doc, info.Name) {
			t.Errorf("%s is missing from modules/%s/README.md", info.Name, info.Category)
		}
	}
}

// Stock scenarios must parse strictly and provide valid parameters for every
// module they invoke.
func TestStockScenariosHaveValidInputs(t *testing.T) {
	dir := filepath.Join("..", "..", "configs", "scenarios")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		scenario, err := runner.LoadScenario(path)
		if err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}
		for i, step := range scenario.Steps {
			var generators []module.Generator
			switch {
			case step.Module != "":
				gen, found := module.Get(step.Module)
				if !found {
					t.Errorf("%s step %d references unregistered module %q", e.Name(), i+1, step.Module)
					continue
				}
				generators = []module.Generator{gen}
			case step.Category != "":
				generators = module.ByCategory(module.Category(step.Category))
				if len(generators) == 0 {
					t.Errorf("%s step %d references empty category %q", e.Name(), i+1, step.Category)
					continue
				}
			default:
				t.Errorf("%s step %d has neither module nor category", e.Name(), i+1)
				continue
			}
			for _, gen := range generators {
				if _, err := module.NormalizeParams(gen.ParamSpecs(), step.Params); err != nil {
					t.Errorf("%s step %d (%s): %v", e.Name(), i+1, gen.Info().Name, err)
				}
			}
		}
	}
}

func TestPortableRegistryIncludesNativeModules(t *testing.T) {
	for _, name := range []string{"proc_osascript", "proc_signal"} {
		if _, ok := module.Get(name); !ok {
			t.Errorf("portable registry is missing %s", name)
		}
	}
}
