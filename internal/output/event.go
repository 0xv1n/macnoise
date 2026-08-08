package output

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/0xv1n/macnoise/pkg/module"
)

// SchemaVersion is the telemetry event schema version embedded in every event.
// 1.1 added the outcome field.
const SchemaVersion = "1.1"

// NewEvent constructs a TelemetryEvent pre-populated with module metadata and process context.
func NewEvent(mod module.ModuleInfo, eventType string, success bool, message string) module.TelemetryEvent {
	return module.TelemetryEvent{
		SchemaVersion:  SchemaVersion,
		Module:         mod.Name,
		Category:       string(mod.Category),
		EventType:      eventType,
		Success:        success,
		Message:        message,
		MITRE:          mod.MITRE,
		ProcessContext: currentProcessContext(),
	}
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
)

func currentProcessContext() module.ProcessContext {
	pc := module.ProcessContext{
		PID:        os.Getpid(),
		PPID:       os.Getppid(),
		ParentName: parentProcessName(),
		Executable: executablePath(),
	}
	if u, err := user.Current(); err == nil {
		pc.Username = u.Username
	}
	return pc
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

// WithError returns a copy of ev marked as a macnoise failure: Success false,
// Outcome error, Error populated from err.
//
// Reach for WithOutcome instead when err describes the environment refusing or
// not answering the action rather than macnoise breaking. A refused connection
// or a TCC denial is the telemetry this tool exists to produce, not a fault,
// and recording it here makes it indistinguishable from one.
func WithError(ev module.TelemetryEvent, err error) module.TelemetryEvent {
	ev.Error = err.Error()
	ev.Success = false
	ev.Outcome = module.OutcomeError
	return ev
}

// WithOutcome returns a copy of ev with outcome set, keeping Success in sync so
// the two fields can never disagree. Pass a non-nil err to record why the
// action was refused or left undecided; unlike WithError that error does not
// mark the event as a tool failure.
func WithOutcome(ev module.TelemetryEvent, outcome module.Outcome, err error) module.TelemetryEvent {
	ev.Outcome = outcome
	ev.Success = outcome != module.OutcomeError
	if err != nil {
		ev.Error = err.Error()
	}
	return ev
}

// DetailStr wraps a string value for use in a TelemetryEvent Details map.
func DetailStr(v string) any { return v }

// DetailInt wraps an int value for use in a TelemetryEvent Details map.
func DetailInt(v int) any { return strconv.Itoa(v) }
