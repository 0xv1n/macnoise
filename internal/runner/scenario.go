package runner

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ScenarioStep defines a single module invocation within a scenario.
type ScenarioStep struct {
	Module   string            `yaml:"module"`
	Category string            `yaml:"category"`
	Params   map[string]string `yaml:"params"`
}

// Scenario is the top-level structure parsed from a scenario YAML file.
type Scenario struct {
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
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return Scenario{}, fmt.Errorf("scenario: parse %s: %w", path, err)
	}
	if len(sc.Steps) == 0 {
		return Scenario{}, fmt.Errorf("scenario: %s contains no steps", path)
	}
	return sc, nil
}
