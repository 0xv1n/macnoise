package module

import "testing"

func TestSubjectValidate(t *testing.T) {
	tests := []struct {
		name    string
		subject Subject
		wantErr bool
	}{
		{name: "file", subject: File("/tmp/example")},
		{name: "process", subject: Process("sh", "/bin/sh", "sh -c true", 42)},
		{name: "network", subject: Network("127.0.0.1:443", "", "")},
		{name: "service", subject: Service("com.example.agent", "gui/501", "")},
		{name: "resource", subject: Resource("tcc", "contacts", "~/Library/Application Support/AddressBook")},
		{name: "missing", wantErr: true},
		{name: "multiple", subject: Subject{File: &FileSubject{Path: "/tmp/x"}, Process: &ProcessSubject{PID: 1}}, wantErr: true},
		{name: "empty file", subject: Subject{File: &FileSubject{}}, wantErr: true},
		{name: "empty resource kind", subject: Subject{Resource: &ResourceSubject{Name: "x"}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.subject.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOutcomeValid(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeExecuted, OutcomeDenied, OutcomeIndeterminate, OutcomeError} {
		if !outcome.Valid() {
			t.Errorf("outcome %q is not valid", outcome)
		}
	}
	if Outcome("").Valid() || Outcome("success").Valid() {
		t.Error("unknown outcomes must be invalid")
	}
}
