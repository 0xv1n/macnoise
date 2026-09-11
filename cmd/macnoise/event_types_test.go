package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

var (
	eventTypesLiteralRe = regexp.MustCompile(`EventTypes:\s*\[\]string\{([^}]*)\}`)
	newEventLiteralRe   = regexp.MustCompile(`NewEvent\(\w+,\s*"([a-z_0-9]+)"`)
	quotedStringRe      = regexp.MustCompile(`"([a-z_0-9]+)"`)
)

// Every event_type a module emits via NewEvent must appear in its declared
// EventTypes, so the catalog never advertises a stale or incomplete set. This
// is the drift guard the ModuleInfo.EventTypes doc references: it scans source
// rather than running modules, so it holds on any OS and needs no privileges.
//
// Direction is emitted-is-subset-of-declared. plist_create builds its event
// type from a variable rather than a literal, so nothing is scanned there and
// its declaration is taken on trust (the same blind spot classify_test notes).
func TestModuleEventTypesMatchEmitted(t *testing.T) {
	root := filepath.Join("..", "..", "modules")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(src)

		emitted := map[string]bool{}
		for _, m := range newEventLiteralRe.FindAllStringSubmatch(text, -1) {
			emitted[m[1]] = true
		}
		if len(emitted) == 0 {
			return nil // helper file, or event type built from a variable
		}

		declared := declaredEventTypes(text)
		if len(declared) == 0 {
			commonPath := strings.TrimSuffix(path, ".go") + "_common.go"
			commonSrc, readErr := os.ReadFile(commonPath)
			if readErr == nil {
				declared = declaredEventTypes(string(commonSrc))
			} else if !os.IsNotExist(readErr) {
				return readErr
			}
		}

		for et := range emitted {
			if !declared[et] {
				t.Errorf("%s emits %q via NewEvent but does not declare it in EventTypes", path, et)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk modules: %v", err)
	}
}

func declaredEventTypes(src string) map[string]bool {
	declared := map[string]bool{}
	if m := eventTypesLiteralRe.FindStringSubmatch(src); m != nil {
		for _, q := range quotedStringRe.FindAllStringSubmatch(m[1], -1) {
			declared[q[1]] = true
		}
	}
	return declared
}

// Every registered module must declare at least one event type, since every
// module emits telemetry. The registry is portable, so this covers the complete
// catalog on every supported development platform.
func TestAllModulesDeclareEventTypes(t *testing.T) {
	for _, g := range module.All() {
		if len(g.Info().EventTypes) == 0 {
			t.Errorf("%s declares no EventTypes", g.Info().Name)
		}
	}
}
