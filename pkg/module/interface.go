// Package module defines the core Generator interface and supporting types
// used by all MacNoise telemetry modules. Every module implements Generator
// and self-registers via init() so the runner can discover and execute it.
package module

import (
	"context"
	"time"
)

// Privilege represents the privilege level required to run a module.
type Privilege string

// Privilege level constants used in ModuleInfo.
const (
	PrivilegeNone  Privilege = "none"
	PrivilegeRoot  Privilege = "root"
	PrivilegeTCC   Privilege = "tcc"
	PrivilegeAdmin Privilege = "admin"
)

// MITRE holds a single ATT&CK technique reference associated with a module.
type MITRE struct {
	Technique string
	SubTech   string
	Name      string
}

type ModuleInfo struct { //nolint:revive // stutter is intentional: ModuleInfo is clearer than Info at call sites
	Name        string
	Description string
	Category    Category
	Tags        []string
	Privileges  Privilege
	MITRE       []MITRE
	Author      string
	MinMacOS    string
}

// ParamSpec describes a single named parameter accepted by a module.
type ParamSpec struct {
	Name         string
	Description  string
	Required     bool
	DefaultValue string
	Example      string
}

// Params is the key-value map of runtime parameters passed to a module.
type Params map[string]string

// Get returns the value for key, or defaultVal if key is absent or empty.
func (p Params) Get(key, defaultVal string) string {
	if v, ok := p[key]; ok && v != "" {
		return v
	}
	return defaultVal
}

// ProcessContext captures identifying information about the MacNoise process itself.
type ProcessContext struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	ParentName string `json:"parent_name,omitempty"`
	Executable string `json:"executable"`
	Username   string `json:"username"`
}

// Outcome describes what happened to the action a module attempted, which is a
// different question from whether macnoise itself worked. A TCC probe that is
// refused is expected, valid telemetry rather than a fault, and recording it
// the same way as a broken tool leaves a consumer no way to tell the two apart
// short of parsing the message text.
type Outcome string

// Outcome values. Everything except OutcomeError describes a working macnoise.
const (
	// OutcomeExecuted means the action ran and did what the module claims.
	OutcomeExecuted Outcome = "executed"
	// OutcomeDenied means the action ran and the environment refused it.
	OutcomeDenied Outcome = "denied"
	// OutcomeIndeterminate means the action ran but no conclusion can be
	// drawn from it: the target was absent, or the technique leaves no
	// evidence either way.
	OutcomeIndeterminate Outcome = "indeterminate"
	// OutcomeError means macnoise itself failed to carry the action out.
	OutcomeError Outcome = "error"
)

// TelemetryEvent is the structured record emitted by a module for each action it performs.
type TelemetryEvent struct {
	SchemaVersion string    `json:"schema_version"`
	Timestamp     time.Time `json:"timestamp"`
	Module        string    `json:"module"`
	Category      string    `json:"category"`
	EventType     string    `json:"event_type"`
	Success       bool      `json:"success"`
	// Outcome is left empty by NewEvent and set only by modules that need to
	// say something Success cannot express. It is resolved to a concrete value
	// at the output boundary, so emitted records always carry one.
	Outcome        Outcome        `json:"outcome"`
	Message        string         `json:"message"`
	Details        map[string]any `json:"details,omitempty"`
	Error          string         `json:"error,omitempty"`
	MITRE          []MITRE        `json:"mitre,omitempty"`
	ProcessContext ProcessContext `json:"process_context"`
}

// ResolvedOutcome returns ev.Outcome, falling back to Success for the majority
// of events that never set one. It is the single definition of how the two
// fields relate, so an outcome-aware consumer and a Success-only consumer can
// never read the same event differently.
func (ev TelemetryEvent) ResolvedOutcome() Outcome {
	if ev.Outcome != "" {
		return ev.Outcome
	}
	if ev.Success {
		return OutcomeExecuted
	}
	return OutcomeError
}

// EventEmitter is a callback that receives a telemetry event from a module.
type EventEmitter func(TelemetryEvent)

// Generator is implemented by every MacNoise module and drives the runner lifecycle.
type Generator interface {
	Info() ModuleInfo
	ParamSpecs() []ParamSpec
	CheckPrereqs() error
	Generate(ctx context.Context, params Params, emit EventEmitter) error
	DryRun(params Params) []string
	Cleanup() error
}
