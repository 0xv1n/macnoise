package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// requireFullRegistry skips a check that needs every module registered.
// proc_osascript and proc_signal carry //go:build darwin, so off a Mac they are
// not compiled in and the registry is a subset. A completeness check run
// against that subset either misses modules or, worse, reports a scenario's
// valid reference as unregistered.
func requireFullRegistry(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("registry is incomplete off darwin; this runs in the macOS job")
	}
}

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
	requireFullRegistry(t)

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

// Scenario files must only reference modules that exist. A typo or a module
// renamed out from under a scenario fails at run time partway through the
// chain, after earlier steps have already made changes on the host.
func TestScenariosReferenceRegisteredModules(t *testing.T) {
	requireFullRegistry(t)

	dir := filepath.Join("..", "..", "configs", "scenarios")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		body := readRepoFile(t, "configs", "scenarios", e.Name())
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			name, ok := strings.CutPrefix(line, "- module:")
			if !ok {
				continue
			}
			name = strings.TrimSpace(name)
			if _, found := module.Get(name); !found {
				t.Errorf("%s references unregistered module %q", e.Name(), name)
			}
		}
	}
}
