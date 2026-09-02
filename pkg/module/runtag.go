package module

import (
	"path"
	"strings"
)

// TagPath folds the run ID into the base name of a filesystem path, before the
// extension, so a consumer can correlate the created artifact back to the run.
// Returns p unchanged when id is empty. Paths are treated as slash-separated
// (macnoise's artifact paths always are), so results are stable across OSes.
//
// Examples:
//
//	TagPath("/tmp/macnoise_test.plist", "abc") -> "/tmp/macnoise_test_abc.plist"
//	TagPath("/tmp/macnoise_es", "abc")         -> "/tmp/macnoise_es_abc"
func TagPath(p, id string) string {
	if id == "" {
		return p
	}
	dir, base := path.Split(p)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return dir + stem + "_" + id + ext
}
