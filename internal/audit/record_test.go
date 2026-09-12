package audit

import (
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestExtractFile(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		subject   module.Subject
		wantName  string
		wantPath  string
		wantType  int
	}{
		{
			name:      "path key",
			eventType: "file_create",
			subject:   module.File("/tmp/macnoise_test/file1.txt"),
			wantName:  "file1.txt",
			wantPath:  "/tmp/macnoise_test/file1.txt",
			wantType:  1,
		},
		{
			name:      "output_path key (file_archive)",
			eventType: "archive_create",
			subject:   module.File("/tmp/macnoise_archive.zip"),
			wantName:  "macnoise_archive.zip",
			wantPath:  "/tmp/macnoise_archive.zip",
			wantType:  1,
		},
		{
			name:      "dir_create gets Folder type_id",
			eventType: "dir_create",
			subject:   module.File("/tmp/macnoise_test"),
			wantName:  "macnoise_test",
			wantPath:  "/tmp/macnoise_test",
			wantType:  2,
		},
		{
			name:      "no known path key still returns a non-nil File",
			eventType: "plist_modify",
			subject:   module.Resource("preference", "com.macnoise.test:MacnoiseTest", ""),
			wantName:  "com.macnoise.test:MacnoiseTest",
			wantPath:  "",
			wantType:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := extractFile(tt.eventType, tt.subject)
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
		subject  module.Subject
		wantPID  int
		wantName string
	}{
		{
			name:     "pid and command (process_fork)",
			subject:  module.Process("sleep", "/bin/sleep", "sleep 30", 4242),
			wantPID:  4242,
			wantName: "sleep",
		},
		{
			name:     "command only, no pid (process_spawn)",
			subject:  module.Process("sh", "/bin/sh", "echo hi", 0),
			wantPID:  0,
			wantName: "sh",
		},
		{
			name:     "target only (dylib_inject_attempt)",
			subject:  module.Process("true", "/usr/bin/true", "/usr/bin/true", 0),
			wantPID:  0,
			wantName: "true",
		},
		{
			name:     "neither key present falls back to macnoise's own process",
			subject:  module.Resource("script", "AppleScript", ""),
			wantPID:  fallback.PID,
			wantName: fallback.Name,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := extractProcess(tt.subject, fallback)
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
		subject     module.Subject
		wantFile    bool
		wantProcess bool
	}{
		{"file_activity gets file, no process", "file", "file_create", module.File("/tmp/x.txt"), true, false},
		{"process_activity gets process, no file", "process", "process_spawn", module.Process("sh", "/bin/sh", "id", 0), false, true},
		{"network_activity gets neither", "network", "tcp_connect", module.Network("127.0.0.1:1", "", ""), false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, path := newTestLogger(t)
			defer l.Close()

			info := module.ModuleInfo{Name: "test_mod", Category: module.Category(tt.category), Privileges: module.PrivilegeNone}
			ev := module.TelemetryEvent{Category: tt.category, EventType: tt.eventType, Outcome: module.OutcomeExecuted, Subject: tt.subject}
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
