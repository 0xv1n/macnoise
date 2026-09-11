package runner

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/0xv1n/macnoise/pkg/module"
	"gopkg.in/yaml.v3"
)

// ScenarioStep defines a single module invocation within a scenario.
type ScenarioStep struct {
	Module   string        `yaml:"module"`
	Category string        `yaml:"category"`
	Params   module.Params `yaml:"params"`
}

// Scenario is the top-level structure parsed from a scenario YAML file.
type Scenario struct {
	OnError     string         `yaml:"on_error,omitempty"`
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	AuditLog    string         `yaml:"audit_log,omitempty"`
	Steps       []ScenarioStep `yaml:"steps"`
}

// LoadScenario reads and parses a YAML scenario file, returning an error if the file has no steps.
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
	if len(sc.Steps) == 0 {
		return Scenario{}, fmt.Errorf("scenario: %s contains no steps", path)
	}
	if sc.OnError != "" && sc.OnError != "stop" && sc.OnError != "continue" {
		return Scenario{}, fmt.Errorf("scenario: invalid on_error %q", sc.OnError)
	}
	return sc, nil
}
