package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func newTestLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewLogger(path, "test-version")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	return l, path
}

func readRecords(t *testing.T, path string) []Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer f.Close()

	var records []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal record: %v\nline: %s", err, line)
		}
		records = append(records, rec)
	}
	return records
}

func TestNewLogger_CreatesFile(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("audit file not created: %v", err)
	}
}

func TestLogEvent_WritesValidOCSFRecord(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	info := module.ModuleInfo{
		Name:       "net_connect",
		Category:   "network",
		Privileges: module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1071", SubTech: ".001", Name: "Application Layer Protocol: Web Protocols"},
		},
	}
	params := module.Params{"target": "127.0.0.1", "port": "8080"}

	ev := module.TelemetryEvent{
		Module:    "net_connect",
		Category:  "network",
		EventType: "tcp_connect",
		Success:   true,
		Message:   "TCP connection established",
	}
	l.LogEvent(ev, info, params)
	l.Close()

	records := readRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]

	// OCSF required fields
	if rec.ClassUID != 4001 {
		t.Errorf("class_uid: expected 4001, got %d", rec.ClassUID)
	}
	if rec.CategoryUID != 4 {
		t.Errorf("category_uid: expected 4, got %d", rec.CategoryUID)
	}
	if rec.ActivityID != 1 {
		t.Errorf("activity_id: expected 1, got %d", rec.ActivityID)
	}
	if rec.TypeUID != 400101 {
		t.Errorf("type_uid: expected 400101, got %d", rec.TypeUID)
	}
	if rec.SeverityID != 1 {
		t.Errorf("severity_id: expected 1, got %d", rec.SeverityID)
	}
	if rec.Time == 0 {
		t.Error("time should be non-zero")
	}
	if rec.Metadata.Version != "1.7.0" {
		t.Errorf("metadata.version: expected 1.7.0, got %q", rec.Metadata.Version)
	}
	if rec.Metadata.Product.Name != "MacNoise" {
		t.Errorf("metadata.product.name: expected MacNoise, got %q", rec.Metadata.Product.Name)
	}
	if rec.Metadata.Product.Version != "test-version" {
		t.Errorf("metadata.product.version: expected test-version, got %q", rec.Metadata.Product.Version)
	}
	if rec.Metadata.Product.VendorName != "0xv1n" {
		t.Errorf("metadata.product.vendor_name: expected 0xv1n, got %q", rec.Metadata.Product.VendorName)
	}
	if rec.Metadata.CorrelationUID == "" {
		t.Error("correlation_uid should be non-empty")
	}
	if rec.StatusID != 1 {
		t.Errorf("status_id: expected 1, got %d", rec.StatusID)
	}

	// Attacks / MITRE mapping
	if len(rec.Attacks) != 1 {
		t.Fatalf("expected 1 attack, got %d", len(rec.Attacks))
	}
	if rec.Attacks[0].Technique.UID != "T1071" {
		t.Errorf("technique uid: expected T1071, got %q", rec.Attacks[0].Technique.UID)
	}
	if rec.Attacks[0].SubTechnique == nil {
		t.Fatal("sub_technique should not be nil")
	}
	if rec.Attacks[0].SubTechnique.UID != "T1071.001" {
		t.Errorf("sub_technique uid: expected T1071.001, got %q", rec.Attacks[0].SubTechnique.UID)
	}
}

func TestLogEvent_FailureEvent(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	info := module.ModuleInfo{Name: "test_mod", Category: "network", Privileges: module.PrivilegeNone}
	params := module.Params{}
	ev := module.TelemetryEvent{
		Category:  "network",
		EventType: "tcp_connect",
		Success:   false,
		Message:   "connection refused",
	}

	l.LogEvent(ev, info, params)
	l.Close()

	records := readRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].SeverityID != 3 {
		t.Errorf("expected severity_id 3 (Medium) for failure, got %d", records[0].SeverityID)
	}
	if records[0].StatusID != 2 {
		t.Errorf("expected status_id 2 (Failure) for failed event, got %d", records[0].StatusID)
	}
}

func TestLogLifecycle_ModuleRun(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	info := module.ModuleInfo{Name: "net_connect", Category: "network", Privileges: module.PrivilegeNone}
	params := module.Params{"target": "1.2.3.4"}
	now := time.Now()
	data := LifecycleData{
		StartTime:     now.Add(-500 * time.Millisecond),
		EndTime:       now,
		PrereqResult:  "pass",
		EventsEmitted: 3,
		CleanupResult: "ok",
	}

	l.LogLifecycle("module_run", info, params, data)
	l.Close()

	records := readRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.ClassUID != 6003 {
		t.Errorf("lifecycle class_uid: expected 6003, got %d", rec.ClassUID)
	}
	if rec.StartTime == 0 {
		t.Error("start_time should be set")
	}
	if rec.EndTime == 0 {
		t.Error("end_time should be set")
	}
	if rec.Duration <= 0 {
		t.Error("duration should be positive")
	}
	if rec.StatusID != 1 {
		t.Errorf("expected status_id 1 (Success), got %d", rec.StatusID)
	}
}

func TestLogLifecycle_PrereqFail(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	info := module.ModuleInfo{Name: "some_mod", Category: "process", Privileges: module.PrivilegeRoot}
	params := module.Params{}
	data := LifecycleData{
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		PrereqResult: "fail",
		PrereqError:  "requires root",
	}

	l.LogLifecycle("module_prereq_fail", info, params, data)
	l.Close()

	records := readRecords(t, path)
	if records[0].SeverityID != 2 {
		t.Errorf("expected severity_id 2 (Low) for prereq fail, got %d", records[0].SeverityID)
	}
	if records[0].StatusID != 2 {
		t.Errorf("expected status_id 2 (Failure) for prereq fail, got %d", records[0].StatusID)
	}
}

func TestWrapEmitter_DelegatesAndCounts(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	info := module.ModuleInfo{Name: "net_connect", Category: "network", Privileges: module.PrivilegeNone}
	params := module.Params{}

	var received []module.TelemetryEvent
	original := func(ev module.TelemetryEvent) {
		received = append(received, ev)
	}

	var count int
	wrapped := l.WrapEmitter(original, info, params, &count)

	ev1 := module.TelemetryEvent{Category: "network", EventType: "tcp_connect", Success: true, Message: "ok1"}
	ev2 := module.TelemetryEvent{Category: "network", EventType: "tcp_connect", Success: true, Message: "ok2"}
	wrapped(ev1)
	wrapped(ev2)
	l.Close()

	// Original emitter received both events.
	if len(received) != 2 {
		t.Errorf("expected 2 delegated events, got %d", len(received))
	}
	// Counter incremented.
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
	// Audit log received 2 records.
	records := readRecords(t, path)
	if len(records) != 2 {
		t.Errorf("expected 2 audit records from WrapEmitter, got %d", len(records))
	}
}

func TestLogScenario_WritesRecord(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	now := time.Now()
	data := LifecycleData{
		StartTime:   now.Add(-2 * time.Second),
		EndTime:     now,
		StepsPassed: 3,
		StepsFailed: 0,
		TotalSteps:  3,
	}
	l.LogScenario("edr_validation", "/tmp/edr.yaml", data)
	l.Close()

	records := readRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("expected 1 scenario record, got %d", len(records))
	}
	if records[0].ClassUID != 6003 {
		t.Errorf("expected class_uid 6003, got %d", records[0].ClassUID)
	}
	if records[0].StatusID != 1 {
		t.Errorf("expected status_id 1 (Success), got %d", records[0].StatusID)
	}
}

func TestCorrelationUID_SameAcrossRecords(t *testing.T) {
	l, path := newTestLogger(t)
	defer l.Close()

	info := module.ModuleInfo{Name: "mod_a", Category: "network", Privileges: module.PrivilegeNone}
	params := module.Params{}

	ev := module.TelemetryEvent{Category: "network", EventType: "tcp_connect", Success: true}
	l.LogEvent(ev, info, params)
	l.LogEvent(ev, info, params)
	l.Close()

	records := readRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("expected 2 records")
	}
	if records[0].Metadata.CorrelationUID != records[1].Metadata.CorrelationUID {
		t.Error("correlation_uid must be the same across records in one run")
	}
	if records[0].Metadata.CorrelationUID == "" {
		t.Error("correlation_uid must not be empty")
	}
}

func TestMITREMapping_NoSubTech(t *testing.T) {
	mitre := []module.MITRE{
		{Technique: "T1059", Name: "Command and Scripting Interpreter"},
	}
	attacks := mitreToAttacks(mitre)
	if len(attacks) != 1 {
		t.Fatalf("expected 1 attack")
	}
	if attacks[0].SubTechnique != nil {
		t.Error("sub_technique should be nil when SubTech is empty")
	}
	if attacks[0].Technique.UID != "T1059" {
		t.Errorf("expected T1059, got %q", attacks[0].Technique.UID)
	}
}
