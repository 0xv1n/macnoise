package audit

import (
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestExtractFile(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		details   map[string]any
		wantName  string
		wantPath  string
		wantType  int
	}{
		{
			name:      "path key",
			eventType: "file_create",
			details:   map[string]any{"path": "/tmp/macnoise_test/file1.txt"},
			wantName:  "file1.txt",
			wantPath:  "/tmp/macnoise_test/file1.txt",
			wantType:  1,
		},
		{
			name:      "output_path key (file_archive)",
			eventType: "archive_create",
			details:   map[string]any{"output_path": "/tmp/macnoise_archive.zip", "source_dir": "/tmp/src"},
			wantName:  "macnoise_archive.zip",
			wantPath:  "/tmp/macnoise_archive.zip",
			wantType:  1,
		},
		{
			name:      "dir_create gets Folder type_id",
			eventType: "dir_create",
			details:   map[string]any{"path": "/tmp/macnoise_test"},
			wantName:  "macnoise_test",
			wantPath:  "/tmp/macnoise_test",
			wantType:  2,
		},
		{
			name:      "no known path key still returns a non-nil File",
			eventType: "plist_modify",
			details:   map[string]any{"domain": "com.macnoise.test", "key": "MacnoiseTest"},
			wantName:  "plist_modify",
			wantPath:  "",
			wantType:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := extractFile(tt.eventType, tt.details)
			if f == nil {
				t.Fatal("extractFile returned nil, OCSF requires file to be present for file_activity records")
			}
			if f.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", f.Name, tt.wantName)
			}
			if f.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", f.Path, tt.wantPath)
			}
			if f.TypeID != tt.wantType {
				t.Errorf("TypeID = %d, want %d", f.TypeID, tt.wantType)
			}
		})
	}
}

func TestExtractProcess(t *testing.T) {
	fallback := &OCSFProcess{PID: 999, Name: "MacNoise"}

	tests := []struct {
		name     string
		details  map[string]any
		wantPID  int
		wantName string
	}{
		{
			name:     "pid and command (process_fork)",
			details:  map[string]any{"pid": 4242, "command": "sleep 30"},
			wantPID:  4242,
			wantName: "sleep 30",
		},
		{
			name:     "command only, no pid (process_spawn)",
			details:  map[string]any{"command": "echo hi"},
			wantPID:  0,
			wantName: "echo hi",
		},
		{
			name:     "target only (dylib_inject_attempt)",
			details:  map[string]any{"target": "/usr/bin/true", "dyld_insert_libs": "/tmp/x.dylib"},
			wantPID:  0,
			wantName: "/usr/bin/true",
		},
		{
			name:     "neither key present falls back to macnoise's own process",
			details:  map[string]any{"language": "AppleScript", "script": "display notification"},
			wantPID:  fallback.PID,
			wantName: fallback.Name,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := extractProcess(tt.details, fallback)
			if p == nil {
				t.Fatal("extractProcess returned nil, OCSF requires process to be present for process_activity records")
			}
			if p.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", p.PID, tt.wantPID)
			}
			if p.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", p.Name, tt.wantName)
			}
		})
	}
}

// LogEvent must populate device on every record, and file/process only for
// the classes that actually require them (1001/1007) - not spuriously on
// classes where OCSF doesn't ask for them.
func TestLogEvent_RequiredFieldsByClass(t *testing.T) {
	tests := []struct {
		name        string
		category    string
		eventType   string
		details     map[string]any
		wantFile    bool
		wantProcess bool
	}{
		{"file_activity gets file, no process", "file", "file_create", map[string]any{"path": "/tmp/x.txt"}, true, false},
		{"process_activity gets process, no file", "process", "process_spawn", map[string]any{"command": "id"}, false, true},
		{"network_activity gets neither", "network", "tcp_connect", nil, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, path := newTestLogger(t)
			defer l.Close()

			info := module.ModuleInfo{Name: "test_mod", Category: module.Category(tt.category), Privileges: module.PrivilegeNone}
			ev := module.TelemetryEvent{Category: tt.category, EventType: tt.eventType, Success: true, Details: tt.details}
			l.LogEvent(ev, info, module.Params{})
			l.Close()

			records := readRecords(t, path)
			if len(records) != 1 {
				t.Fatalf("expected 1 record, got %d", len(records))
			}
			rec := records[0]

			if rec.Device == nil {
				t.Error("device must be populated on every record")
			}
			if (rec.File != nil) != tt.wantFile {
				t.Errorf("file present = %v, want %v", rec.File != nil, tt.wantFile)
			}
			if (rec.Process != nil) != tt.wantProcess {
				t.Errorf("process present = %v, want %v", rec.Process != nil, tt.wantProcess)
			}
		})
	}
}
