package tcc

import (
	"os"

	"github.com/0xv1n/macnoise/pkg/module"
)

// probeOutcome is the result of attempting to reach a TCC-gated resource.
type probeOutcome string

const (
	probeGranted probeOutcome = "granted"
	probeDenied  probeOutcome = "denied"
	probeAbsent  probeOutcome = "absent"
	probeError   probeOutcome = "error"
)

// classifyProbe maps an access error to a TCC probe outcome.
//
// The distinctions matter because these probes exist to measure TCC decisions,
// and every outcome that is not a real denial dilutes that measurement. A
// resource that was never created cannot have been denied, and an unexpected
// failure such as an I/O error is not a privacy decision either. Reporting
// either as "denied" invents a TCC event that never happened, which is worse
// than reporting nothing in a pipeline that treats denials as signal.
func classifyProbe(err error) probeOutcome {
	switch {
	case err == nil:
		return probeGranted
	case os.IsNotExist(err):
		return probeAbsent
	case os.IsPermission(err):
		return probeDenied
	default:
		return probeError
	}
}

// eventOutcome lifts a probe result onto the telemetry event outcome, so the
// distinction these probes work to establish survives into the schema instead
// of living only in details["result"] where a generic consumer cannot see it.
//
// probeAbsent maps to indeterminate rather than denied for the same reason
// classifyProbe separates them: no TCC decision was made, and calling it a
// denial fabricates a privacy event.
func eventOutcome(o probeOutcome) module.Outcome {
	switch o {
	case probeGranted:
		return module.OutcomeExecuted
	case probeDenied:
		return module.OutcomeDenied
	case probeAbsent:
		return module.OutcomeIndeterminate
	default:
		return module.OutcomeError
	}
}
