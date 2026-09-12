// Package module defines the core Generator interface and supporting types
// used by all MacNoise telemetry modules. Every module implements Generator
// and self-registers via init() so the runner can discover and execute it.
package module

import (
	"context"
	"fmt"
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
	// EventTypes lists every event_type the module can emit. It is declared
	// here (rather than derived) so the catalog can advertise what a consumer
	// should expect to observe; TestModuleEventTypesMatchEmitted guards it
	// against drift by requiring every NewEvent literal in a module's source
	// to appear in this list.
	EventTypes []string
	Author     string
	MinMacOS   string
}

// ParamSpec describes a single named parameter accepted by a module.
type ParamSpec struct {
	Name        string
	Description string
	Type        ParamType
	Required    bool
	Sensitive   bool
	Default     any
	Example     any
	Range       *IntegerRange
	Choices     []string
}

// IntegerRange defines inclusive bounds. A zero Max means no upper bound.
type IntegerRange struct {
	Min int `json:"min"`
	Max int `json:"max,omitempty"`
}

// ParamType identifies the runtime type produced by parameter normalization.
type ParamType string

// Supported parameter types.
const (
	ParamString     ParamType = "string"
	ParamInteger    ParamType = "integer"
	ParamBoolean    ParamType = "boolean"
	ParamPath       ParamType = "path"
	ParamStringList ParamType = "string_list"
	ParamPathList   ParamType = "path_list"
)

// Params holds raw or normalized runtime parameters. NormalizeParams converts
// input values to the types declared by a module's ParamSpecs.
type Params map[string]any

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

// Valid reports whether o is one of the supported event outcomes.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeExecuted, OutcomeDenied, OutcomeIndeterminate, OutcomeError:
		return true
	default:
		return false
	}
}

// Subject identifies the concrete target of an event. Exactly one typed
// subject must be present, which keeps consumers out of the untyped Details
// map when correlating the action to a file, process, endpoint, or resource.
type Subject struct {
	File     *FileSubject     `json:"file,omitempty"`
	Process  *ProcessSubject  `json:"process,omitempty"`
	Network  *NetworkSubject  `json:"network,omitempty"`
	Service  *ServiceSubject  `json:"service,omitempty"`
	Resource *ResourceSubject `json:"resource,omitempty"`
}

// FileSubject identifies a file-system target.
type FileSubject struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

// ProcessSubject identifies a process target or command execution.
type ProcessSubject struct {
	PID        int    `json:"pid,omitempty"`
	Name       string `json:"name,omitempty"`
	Executable string `json:"executable,omitempty"`
	Command    string `json:"command,omitempty"`
}

// NetworkSubject identifies a network endpoint.
type NetworkSubject struct {
	Address string `json:"address,omitempty"`
	URL     string `json:"url,omitempty"`
	Domain  string `json:"domain,omitempty"`
}

// ServiceSubject identifies a persistence or service target.
type ServiceSubject struct {
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}

// ResourceSubject identifies an API or operating-system resource that is not
// a file, process, network endpoint, or service.
type ResourceSubject struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

// File returns a typed file subject.
func File(path string) Subject {
	return Subject{File: &FileSubject{Path: path}}
}

// Process returns a typed process subject.
func Process(name, executable, command string, pid int) Subject {
	return Subject{Process: &ProcessSubject{PID: pid, Name: name, Executable: executable, Command: command}}
}

// Network returns a typed network subject.
func Network(address, url, domain string) Subject {
	return Subject{Network: &NetworkSubject{Address: address, URL: url, Domain: domain}}
}

// Service returns a typed service subject.
func Service(name, domain, path string) Subject {
	return Subject{Service: &ServiceSubject{Name: name, Domain: domain, Path: path}}
}

// Resource returns a typed generic resource subject.
func Resource(kind, name, path string) Subject {
	return Subject{Resource: &ResourceSubject{Kind: kind, Name: name, Path: path}}
}

// Validate requires exactly one typed subject with an identifying value.
func (s Subject) Validate() error {
	count := 0
	if s.File != nil {
		count++
		if s.File.Name == "" && s.File.Path == "" {
			return fmt.Errorf("file subject has no identity")
		}
	}
	if s.Process != nil {
		count++
		if s.Process.PID == 0 && s.Process.Name == "" && s.Process.Executable == "" && s.Process.Command == "" {
			return fmt.Errorf("process subject has no identity")
		}
	}
	if s.Network != nil {
		count++
		if s.Network.Address == "" && s.Network.URL == "" && s.Network.Domain == "" {
			return fmt.Errorf("network subject has no identity")
		}
	}
	if s.Service != nil {
		count++
		if s.Service.Name == "" && s.Service.Domain == "" && s.Service.Path == "" {
			return fmt.Errorf("service subject has no identity")
		}
	}
	if s.Resource != nil {
		count++
		if s.Resource.Kind == "" {
			return fmt.Errorf("resource subject has no kind")
		}
		if s.Resource.Name == "" && s.Resource.Path == "" {
			return fmt.Errorf("resource subject has no identity")
		}
	}
	if count != 1 {
		return fmt.Errorf("event must have exactly one subject, got %d", count)
	}
	return nil
}

// TelemetryEvent is the structured record emitted by a module for each action it performs.
type TelemetryEvent struct {
	SchemaVersion  string         `json:"schema_version"`
	Timestamp      time.Time      `json:"timestamp"`
	Module         string         `json:"module"`
	Category       string         `json:"category"`
	EventType      string         `json:"event_type"`
	Outcome        Outcome        `json:"outcome"`
	Subject        Subject        `json:"subject"`
	Message        string         `json:"message"`
	Details        map[string]any `json:"details,omitempty"`
	Error          string         `json:"error,omitempty"`
	MITRE          []MITRE        `json:"mitre,omitempty"`
	ProcessContext ProcessContext `json:"process_context"`
}

// EventEmitter is a callback that receives a telemetry event from a module.
type EventEmitter func(TelemetryEvent) error

// Generator is implemented by every MacNoise module and drives the runner lifecycle.
type Generator interface {
	Info() ModuleInfo
	ParamSpecs() []ParamSpec
	CheckPrereqs(ctx context.Context, params Params) error
	Generate(ctx context.Context, params Params, emit EventEmitter) error
	DryRun(params Params) []string
	Cleanup(ctx context.Context) error
}
