package output_test

import (
	"bytes"
	"encoding/json"
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
		Success:       true,
		Message:       "test message",
	}
}

func TestJSONLOutputIsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatJSONL, &buf)
	em.Emit(sampleEvent())

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
	em.Emit(sampleEvent())

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)

	required := []string{"schema_version", "timestamp", "module", "category", "event_type", "success", "message"}
	for _, field := range required {
		if _, ok := m[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}
}

func TestHumanOutputContainsMessage(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatHuman, &buf)
	em.Emit(sampleEvent())

	out := buf.String()
	if !strings.Contains(out, "test message") {
		t.Errorf("human output missing message: %q", out)
	}
	if !strings.Contains(out, "network") {
		t.Errorf("human output missing category: %q", out)
	}
}

func TestHumanSuccessPrefix(t *testing.T) {
	var buf bytes.Buffer
	em := output.NewEmitter(output.FormatHuman, &buf)

	ev := sampleEvent()
	ev.Success = true
	em.Emit(ev)
	if !strings.Contains(buf.String(), "[+]") {
		t.Error("expected [+] prefix for success event")
	}

	buf.Reset()
	ev.Success = false
	em.Emit(ev)
	if !strings.Contains(buf.String(), "[!]") {
		t.Error("expected [!] prefix for failure event")
	}
}

func TestMultiWriter(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	em := output.NewEmitter(output.FormatHuman, &buf1, &buf2)
	em.Emit(sampleEvent())

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
			em.Emit(sampleEvent())
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
	em.Emit(ev)

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)
	ts, ok := m["timestamp"].(string)
	if !ok || ts == "" {
		t.Error("expected non-empty timestamp in output")
	}
}
