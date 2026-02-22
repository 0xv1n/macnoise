// Package config handles loading and validation of MacNoise configuration.
// Values are read from a YAML file and layered on top of compiled-in defaults.
// An absent or missing file silently returns defaults rather than an error.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the runtime configuration loaded from a YAML file.
type Config struct {
	DefaultFormat  string `yaml:"default_format"`
	DefaultTimeout int    `yaml:"default_timeout"`
	OutputFile     string `yaml:"output_file"`
	AuditLog       string `yaml:"audit_log"`
}

// Defaults returns a Config populated with compiled-in default values.
func Defaults() Config {
	return Config{
		DefaultFormat:  "human",
		DefaultTimeout: 30,
	}
}

// Load reads a YAML config from path (or returns Defaults if path is empty or the file is absent).
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return cfg, nil
}
