// Package output handles structured telemetry event formatting and emission.
// Events are written in either human-readable or JSONL format to one or more
// io.Writer destinations. The Emitter is safe for concurrent use.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Format controls how telemetry events are serialised when written to a destination.
type Format string

// Output format constants passed to NewEmitter.
const (
	FormatHuman Format = "human"
	FormatJSONL Format = "jsonl"
)

// Emitter writes telemetry events to one or more io.Writer destinations, safe for concurrent use.
type Emitter struct {
	mu      sync.Mutex
	writers []io.Writer
	format  Format
}

// NewEmitter constructs an Emitter that writes events in the given format to all provided writers.
func NewEmitter(format Format, writers ...io.Writer) *Emitter {
	return &Emitter{
		writers: writers,
		format:  format,
	}
}

// Emit serialises ev and writes it to every configured writer.
func (e *Emitter) Emit(ev module.TelemetryEvent) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, w := range e.writers {
		switch e.format {
		case FormatJSONL:
			e.writeJSONL(w, ev)
		default:
			e.writeHuman(w, ev)
		}
	}
}

func (e *Emitter) writeJSONL(w io.Writer, ev module.TelemetryEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		_, _ = fmt.Fprintf(w, `{"error":"failed to marshal event: %s"}`+"\n", err)
		return
	}
	_, _ = fmt.Fprintln(w, string(b))
}

func (e *Emitter) writeHuman(w io.Writer, ev module.TelemetryEvent) {
	status := "+"
	if !ev.Success {
		status = "!"
	}
	ts := ev.Timestamp.Format("15:04:05")
	_, _ = fmt.Fprintf(w, "[%s] [%s] [%s/%s] %s\n", status, ts, ev.Category, ev.Module, ev.Message)
	if ev.Error != "" {
		_, _ = fmt.Fprintf(w, "    error: %s\n", ev.Error)
	}
	for k, v := range ev.Details {
		_, _ = fmt.Fprintf(w, "    %s: %v\n", k, v)
	}
}

// EmitFunc returns an EventEmitter function backed by this Emitter.
func (e *Emitter) EmitFunc() module.EventEmitter {
	return func(ev module.TelemetryEvent) {
		e.Emit(ev)
	}
}
