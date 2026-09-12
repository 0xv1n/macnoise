// Package output handles structured telemetry event formatting and emission.
// Events are written in either human-readable or JSONL format to one or more
// io.Writer destinations. The Emitter is safe for concurrent use.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

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
func (e *Emitter) Emit(ev module.TelemetryEvent) error {
	var err error
	ev, err = prepareEvent(ev)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var errs []error
	for i, w := range e.writers {
		var writeErr error
		switch e.format {
		case FormatJSONL:
			writeErr = e.writeJSONL(w, ev)
		default:
			writeErr = e.writeHuman(w, ev)
		}
		if writeErr != nil {
			errs = append(errs, fmt.Errorf("output writer %d: %w", i+1, writeErr))
		}
	}
	return errors.Join(errs...)
}

func (e *Emitter) writeJSONL(w io.Writer, ev module.TelemetryEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if _, err := fmt.Fprintln(w, string(b)); err != nil {
		return fmt.Errorf("write JSONL event: %w", err)
	}
	return nil
}

// humanMarker distinguishes the four outcomes at a glance. A denial and an
// indeterminate result both used to print as [+], since neither is a macnoise
// failure, which made a refused probe read as a clean success.
func humanMarker(outcome module.Outcome) string {
	switch outcome {
	case module.OutcomeDenied:
		return "-"
	case module.OutcomeIndeterminate:
		return "?"
	case module.OutcomeError:
		return "!"
	default:
		return "+"
	}
}

func (e *Emitter) writeHuman(w io.Writer, ev module.TelemetryEvent) error {
	status := humanMarker(ev.Outcome)
	ts := ev.Timestamp.Format("15:04:05")
	if _, err := fmt.Fprintf(w, "[%s] [%s] [%s/%s] %s\n", status, ts, ev.Category, ev.Module, ev.Message); err != nil {
		return fmt.Errorf("write human event: %w", err)
	}
	if ev.Error != "" {
		if _, err := fmt.Fprintf(w, "    error: %s\n", ev.Error); err != nil {
			return fmt.Errorf("write human error: %w", err)
		}
	}
	for k, v := range ev.Details {
		if _, err := fmt.Fprintf(w, "    %s: %v\n", k, v); err != nil {
			return fmt.Errorf("write human detail: %w", err)
		}
	}
	return nil
}

// EmitFunc returns an EventEmitter function backed by this Emitter.
func (e *Emitter) EmitFunc() module.EventEmitter {
	return e.Emit
}
