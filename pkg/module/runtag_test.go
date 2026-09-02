package module

import "testing"

func TestTagPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		id   string
		want string
	}{
		{"file with extension", "/tmp/macnoise_test.plist", "abc", "/tmp/macnoise_test_abc.plist"},
		{"directory no extension", "/tmp/macnoise_es", "abc", "/tmp/macnoise_es_abc"},
		{"empty id unchanged", "/tmp/macnoise_test.plist", "", "/tmp/macnoise_test.plist"},
		{"bare filename", "report.zip", "xyz", "report_xyz.zip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TagPath(tt.path, tt.id); got != tt.want {
				t.Errorf("TagPath(%q, %q) = %q, want %q", tt.path, tt.id, got, tt.want)
			}
		})
	}
}
