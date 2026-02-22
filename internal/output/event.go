package output

import (
	"os"
	"os/user"
	"runtime"
	"strconv"

	"github.com/0xv1n/macnoise/pkg/module"
)

// SchemaVersion is the telemetry event schema version embedded in every event.
const SchemaVersion = "1.0"

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

func currentProcessContext() module.ProcessContext {
	pc := module.ProcessContext{
		PID:        os.Getpid(),
		PPID:       os.Getppid(),
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

// WithError returns a copy of ev with Success set to false and Error populated from err.
func WithError(ev module.TelemetryEvent, err error) module.TelemetryEvent {
	ev.Error = err.Error()
	ev.Success = false
	return ev
}

// DetailStr wraps a string value for use in a TelemetryEvent Details map.
func DetailStr(v string) any { return v }

// DetailInt wraps an int value for use in a TelemetryEvent Details map.
func DetailInt(v int) any { return strconv.Itoa(v) }
