package tcc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type tccScreenRecording struct{}

func (t *tccScreenRecording) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "tcc_screen_recording",
		EventTypes:  []string{"screen_capture_attempt"},
		Description: "Attempts a screen capture via screencapture to generate screen-capture telemetry",
		Category:    module.CategoryTCC,
		Tags:        []string{"tcc", "screen-recording", "screencapture", "privacy"},
		Privileges:  module.PrivilegeTCC,
		MITRE: []module.MITRE{
			{Technique: "T1113", Name: "Screen Capture"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (t *tccScreenRecording) ParamSpecs() []module.ParamSpec { return nil }

func (t *tccScreenRecording) CheckPrereqs() error { return nil }

// screenCaptureOutcome classifies a screencapture run.
//
// Unlike the Accessibility probe, this cannot be a granted/denied classifier:
// the command-line screencapture exits 0 and writes a valid image whether or
// not Screen Recording is granted, because the desktop is always capturable
// while other apps' windows are silently excluded. There is no exit code,
// stderr, or output that reveals the grant, and determining it would need the
// CGPreflightScreenCaptureAccess API via cgo, which this pure-Go tool avoids.
//
// So the module reports what it can honestly observe: the capture attempt ran
// (executed) - which is itself the telemetry a detection keys on, a process
// invoking the screen-capture path - or it could not be attempted at all
// (indeterminate), e.g. no display or GUI session. It never claims a permission
// verdict it cannot determine, per the same rule that gave proc_inject its
// indeterminate outcome.
func screenCaptureOutcome(err error, bytes int64) module.Outcome {
	if err == nil && bytes > 0 {
		return module.OutcomeExecuted
	}
	return module.OutcomeIndeterminate
}

func (t *tccScreenRecording) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	info := t.Info()

	// The capture is written to a temp file, its size recorded, and the file
	// deleted immediately. Contents are never read or emitted: the goal is to
	// generate the screen-capture telemetry a real stealer would, not to
	// collect the screen, the same discard posture as the credential modules.
	prefix := "mn_screencap_"
	if runID := module.RunIDFromContext(ctx); runID != "" {
		prefix += runID + "_"
	}
	f, err := os.CreateTemp("", prefix+"*.png")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	_ = f.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	out, runErr := exec.CommandContext(ctx, "screencapture", "-x", tmpPath).CombinedOutput()

	var bytes int64
	if fi, statErr := os.Stat(tmpPath); statErr == nil {
		bytes = fi.Size()
	}
	outcome := screenCaptureOutcome(runErr, bytes)

	ev := output.NewEvent(info, "screen_capture_attempt", true, "attempting screen capture via screencapture")
	details := map[string]any{
		"tool":            "screencapture",
		"bytes_captured":  bytes,
		"permission":      "indeterminate",
		"permission_note": "the CLI cannot determine whether Screen Recording is granted; the capture attempt is the telemetry",
	}

	switch outcome {
	case module.OutcomeExecuted:
		ev.Message = fmt.Sprintf("screen capture ran, wrote %d bytes (Screen Recording grant not determinable from CLI)", bytes)
	default:
		ev.Message = "screen capture could not be attempted (no display or GUI session)"
	}

	var probeErr error
	if runErr != nil {
		probeErr = fmt.Errorf("screencapture: %v: %s", runErr, strings.TrimSpace(string(out)))
	}
	ev = output.WithOutcome(ev, outcome, probeErr)
	emit(output.WithDetails(ev, details))
	return nil
}

func (t *tccScreenRecording) DryRun(params module.Params) []string {
	return []string{"screencapture -x <tempfile> then delete it (probes Screen Recording, contents discarded)"}
}

func (t *tccScreenRecording) Cleanup() error { return nil }

func init() {
	module.Register(&tccScreenRecording{})
}
