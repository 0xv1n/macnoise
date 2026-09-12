package runner

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/0xv1n/macnoise/pkg/module"
	"gopkg.in/yaml.v3"
)

const scenarioVersion = 1

// ScenarioValue is either a literal value or an explicit reference. Mapping
// values are reserved for references so scenarios cannot grow an implicit
// template language.
type ScenarioValue struct {
	Literal any
	Input   string
	Output  string
}

// UnmarshalYAML distinguishes explicit input/output references from literals.
func (v *ScenarioValue) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		var ref struct {
			Input  string `yaml:"input,omitempty"`
			Output string `yaml:"output,omitempty"`
		}
		if err := node.Decode(&ref); err != nil {
			return err
		}
		if (ref.Input == "") == (ref.Output == "") {
			return fmt.Errorf("value mapping must contain exactly one of input or output")
		}
		if len(node.Content) != 2 {
			return fmt.Errorf("value reference contains unknown fields")
		}
		v.Input = ref.Input
		v.Output = ref.Output
		return nil
	}
	return node.Decode(&v.Literal)
}

// ScenarioInput declares one typed value supplied to a scenario.
type ScenarioInput struct {
	Type      module.ParamType `yaml:"type"`
	Required  bool             `yaml:"required,omitempty"`
	Sensitive bool             `yaml:"sensitive,omitempty"`
	Default   any              `yaml:"default,omitempty"`
}

// ScenarioStep defines one module, category, or local scenario inclusion.
type ScenarioStep struct {
	ID       string                   `yaml:"id,omitempty"`
	Module   string                   `yaml:"module,omitempty"`
	Category string                   `yaml:"category,omitempty"`
	Include  string                   `yaml:"include,omitempty"`
	OnError  string                   `yaml:"on_error,omitempty"`
	Params   map[string]ScenarioValue `yaml:"params,omitempty"`
	Inputs   map[string]ScenarioValue `yaml:"inputs,omitempty"`
}

// Scenario is the versioned top-level scenario document.
type Scenario struct {
	Version     int                      `yaml:"version"`
	OnError     string                   `yaml:"on_error,omitempty"`
	Name        string                   `yaml:"name"`
	Description string                   `yaml:"description,omitempty"`
	AuditLog    string                   `yaml:"audit_log,omitempty"`
	Inputs      map[string]ScenarioInput `yaml:"inputs,omitempty"`
	Outputs     map[string]ScenarioValue `yaml:"outputs,omitempty"`
	Steps       []ScenarioStep           `yaml:"steps"`
}

// LoadScenario strictly parses one scenario document. Registry-dependent and
// recursive checks happen during preflight in RunScenario.
func LoadScenario(path string) (Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, fmt.Errorf("scenario: read %s: %w", path, err)
	}
	var sc Scenario
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&sc); err != nil {
		return Scenario{}, fmt.Errorf("scenario: parse %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple YAML documents are not supported")
		}
		return Scenario{}, fmt.Errorf("scenario: parse %s: %w", path, err)
	}
	if sc.Version != scenarioVersion {
		return Scenario{}, fmt.Errorf("scenario: %s has unsupported version %d (want %d)", path, sc.Version, scenarioVersion)
	}
	if sc.Name == "" {
		return Scenario{}, fmt.Errorf("scenario: %s has no name", path)
	}
	if len(sc.Steps) == 0 {
		return Scenario{}, fmt.Errorf("scenario: %s contains no steps", path)
	}
	if err := validateFailurePolicy(sc.OnError); err != nil {
		return Scenario{}, fmt.Errorf("scenario: %w", err)
	}
	return sc, nil
}

func validateFailurePolicy(policy string) error {
	if policy != "" && policy != "stop" && policy != "continue" {
		return fmt.Errorf("invalid on_error %q", policy)
	}
	return nil
}
