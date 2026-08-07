package tcc

import _ "os"

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
	default:
		return probeDenied
	}
}
