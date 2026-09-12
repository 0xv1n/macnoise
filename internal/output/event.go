package output

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

// SchemaVersion is the telemetry event schema version embedded in every event.
// 2.0 makes outcome authoritative and adds typed subjects.
const SchemaVersion = "2.0"

// NewEvent constructs a TelemetryEvent pre-populated with module metadata and process context.
func NewEvent(mod module.ModuleInfo, eventType string, outcome module.Outcome, subject module.Subject, message string) module.TelemetryEvent {
	return module.TelemetryEvent{
		SchemaVersion:  SchemaVersion,
		Module:         mod.Name,
		Category:       string(mod.Category),
		EventType:      eventType,
		Outcome:        outcome,
		Subject:        subject,
		Message:        message,
		MITRE:          mod.MITRE,
		ProcessContext: currentProcessContext(),
	}
}

// NormalizeEvent applies the authoritative module identity and emission time,
// then validates the event contract before it reaches any writer.
func NormalizeEvent(info module.ModuleInfo, ev module.TelemetryEvent) (module.TelemetryEvent, error) {
	ev.SchemaVersion = SchemaVersion
	ev.Module = info.Name
	ev.Category = string(info.Category)
	ev.MITRE = append([]module.MITRE(nil), info.MITRE...)
	ev.ProcessContext = currentProcessContext()
	return prepareEvent(ev)
}

func prepareEvent(ev module.TelemetryEvent) (module.TelemetryEvent, error) {
	ev.SchemaVersion = SchemaVersion
	if !ev.Outcome.Valid() {
		return module.TelemetryEvent{}, fmt.Errorf("event %q has invalid outcome %q", ev.EventType, ev.Outcome)
	}
	if err := ev.Subject.Validate(); err != nil {
		return module.TelemetryEvent{}, fmt.Errorf("event %q subject: %w", ev.EventType, err)
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	} else {
		ev.Timestamp = ev.Timestamp.UTC()
	}
	return ev, nil
}

// CurrentProcessContext returns the ProcessContext for the running macnoise process.
func CurrentProcessContext() module.ProcessContext {
	return currentProcessContext()
}

// parentProcessName resolves the parent's executable name, which is what EDR
// correlation keys on: a pid alone says nothing about whether macnoise was
// launched from a shell, a scheduler, or another process.
//
// Resolved once per run rather than per event. currentProcessContext runs for
// every emitted event, so spawning ps each time would be slow and would inject
// spurious process telemetry into the very stream this tool exists to produce.
// An empty result is left empty rather than guessed at.
func parentProcessName() string {
	parentNameOnce.Do(func() {
		out, err := exec.Command("ps", "-p", strconv.Itoa(os.Getppid()), "-o", "comm=").Output()
		if err != nil {
			return
		}
		parentName = filepath.Base(strings.TrimSpace(string(out)))
	})
	return parentName
}

var (
	parentNameOnce sync.Once
	parentName     string
	processOnce    sync.Once
	processContext module.ProcessContext
)

func currentProcessContext() module.ProcessContext {
	processOnce.Do(func() {
		processContext = module.ProcessContext{
			PID:        os.Getpid(),
			PPID:       os.Getppid(),
			ParentName: parentProcessName(),
			Executable: executablePath(),
		}
		if u, err := user.Current(); err == nil {
			processContext.Username = u.Username
		}
	})
	return processContext
}

func executablePath() string {
	if runtime.GOOS == "windows" {
		return "macnoise.exe"
	}
	exe, err := os.Executable()
	if err != nil {
		return "macnoise"
	}
	return exe
}

// WithDetails returns a copy of ev with the Details map replaced by details.
func WithDetails(ev module.TelemetryEvent, details map[string]any) module.TelemetryEvent {
	ev.Details = details
	return ev
}

// WithError returns a copy of ev marked as a macnoise failure with OutcomeError
// and Error populated from err.
//
// Reach for WithOutcome instead when err describes the environment refusing or
// not answering the action rather than macnoise breaking. A refused connection
// or a TCC denial is the telemetry this tool exists to produce, not a fault,
// and recording it here makes it indistinguishable from one.
func WithError(ev module.TelemetryEvent, err error) module.TelemetryEvent {
	ev.Error = err.Error()
	ev.Outcome = module.OutcomeError
	return ev
}

// WithOutcome returns a copy of ev with outcome set. Pass a non-nil err to
// record why the action was refused or left undecided; unlike WithError that
// error does not mark the event as a tool failure.
func WithOutcome(ev module.TelemetryEvent, outcome module.Outcome, err error) module.TelemetryEvent {
	ev.Outcome = outcome
	if err != nil {
		ev.Error = err.Error()
	}
	return ev
}

// DetailStr wraps a string value for use in a TelemetryEvent Details map.
func DetailStr(v string) any { return v }

// DetailInt wraps an int value for use in a TelemetryEvent Details map.
func DetailInt(v int) any { return strconv.Itoa(v) }
