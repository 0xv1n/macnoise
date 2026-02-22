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
	Executable string `json:"executable"`
	Username   string `json:"username"`
}

// TelemetryEvent is the structured record emitted by a module for each action it performs.
type TelemetryEvent struct {
	SchemaVersion  string         `json:"schema_version"`
	Timestamp      time.Time      `json:"timestamp"`
	Module         string         `json:"module"`
	Category       string         `json:"category"`
	EventType      string         `json:"event_type"`
	Success        bool           `json:"success"`
	Message        string         `json:"message"`
	Details        map[string]any `json:"details,omitempty"`
	Error          string         `json:"error,omitempty"`
	MITRE          []MITRE        `json:"mitre,omitempty"`
	ProcessContext ProcessContext `json:"process_context"`
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
