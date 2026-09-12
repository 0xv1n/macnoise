package output_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

func sampleEvent() module.TelemetryEvent {
	return module.TelemetryEvent{
		SchemaVersion: "1.0",
		Timestamp:     time.Now().UTC(),
		Module:        "test_module",
		Category:      "network",
		EventType:     "tcp_connect",
		Outcome:       module.OutcomeExecuted,
		Subject:       module.Network("127.0.0.1:443", "", ""),
		Message:       "test message",
	}
}

func TestJSONLOutputIsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatJSONL, &buf)
	if err := em.Emit(sampleEvent()); err != nil {
		t.Fatal(err)
	}

	line := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(line, "{") {
		t.Fatalf("expected JSON line, got: %q", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("invalid JSON: %v\nline: %s", err, line)
	}
}

func TestJSONLContainsRequiredFields(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatJSONL, &buf)
	if err := em.Emit(sampleEvent()); err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)

	required := []string{"schema_version", "timestamp", "module", "category", "event_type", "outcome", "subject", "message"}
	for _, field := range required {
		if _, ok := m[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}
	if got := m["schema_version"]; got != output.SchemaVersion {
		t.Errorf("schema_version = %v, want %s", got, output.SchemaVersion)
	}
	if _, ok := m["success"]; ok {
		t.Error("success must not be emitted alongside authoritative outcome")
	}
}

func TestHumanOutputContainsMessage(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatHuman, &buf)
	if err := em.Emit(sampleEvent()); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "test message") {
		t.Errorf("human output missing message: %q", out)
	}
	if !strings.Contains(out, "network") {
		t.Errorf("human output missing category: %q", out)
	}
}

func TestHumanOutcomePrefix(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatHuman, &buf)

	ev := sampleEvent()
	ev.Outcome = module.OutcomeExecuted
	if err := em.Emit(ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "[+]") {
		t.Error("expected [+] prefix for success event")
	}

	buf.Reset()
	ev.Outcome = module.OutcomeError
	if err := em.Emit(ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "[!]") {
		t.Error("expected [!] prefix for failure event")
	}
}

func TestMultiWriter(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	em := output.NewEmitter(output.FormatHuman, &buf1, &buf2)
	if err := em.Emit(sampleEvent()); err != nil {
		t.Fatal(err)
	}

	if buf1.Len() == 0 {
		t.Error("writer 1 received no output")
	}
	if buf2.Len() == 0 {
		t.Error("writer 2 received no output")
	}
}

func TestThreadSafety(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatJSONL, &buf)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := em.Emit(sampleEvent()); err != nil {
				t.Errorf("Emit: %v", err)
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 50 {
		t.Errorf("expected 50 JSONL lines, got %d", len(lines))
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %q", i, line)
		}
	}
}

func TestEmitFuncTimestamp(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatJSONL, &buf)

	ev := sampleEvent()
	ev.Timestamp = time.Time{}
	if err := em.Emit(ev); err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)
	ts, ok := m["timestamp"].(string)
	if !ok || ts == "" {
		t.Error("expected non-empty timestamp in output")
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestEmitReturnsWriterFailureAndContinuesOtherWriters(t *testing.T) {
	wantErr := errors.New("disk full")
	var good bytes.Buffer
	em := output.NewEmitter(output.FormatJSONL, errorWriter{err: wantErr}, &good)

	err := em.Emit(sampleEvent())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Emit() error = %v, want disk full", err)
	}
	if good.Len() == 0 {
		t.Error("healthy writer did not receive the event")
	}
}

func TestNormalizeEventUsesAuthoritativeIdentityAndOneTimestamp(t *testing.T) {
	info := module.ModuleInfo{Name: "real_module", Category: module.CategoryFile, MITRE: []module.MITRE{{Technique: "T1000"}}}
	ev := sampleEvent()
	ev.SchemaVersion = "old"
	ev.Module = "wrong"
	ev.Category = "wrong"
	ev.Timestamp = time.Time{}

	got, err := output.NormalizeEvent(info, ev)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != output.SchemaVersion || got.Module != info.Name || got.Category != string(info.Category) {
		t.Errorf("identity was not normalized: %+v", got)
	}
	if got.Timestamp.IsZero() || got.Timestamp.Location() != time.UTC {
		t.Errorf("timestamp = %v, want non-zero UTC", got.Timestamp)
	}
}
