package module

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// NormalizeParams validates input against specs, applies defaults only to
// omitted values, and returns values using the declared runtime types.
func NormalizeParams(specs []ParamSpec, input Params) (Params, error) {
	if err := ValidateParamSpecs(specs); err != nil {
		return nil, err
	}
	byName := make(map[string]ParamSpec, len(specs))
	for _, spec := range specs {
		byName[spec.Name] = spec
	}

	unknown := make([]string, 0)
	for name := range input {
		if _, ok := byName[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown parameter %q", unknown[0])
	}

	normalized := make(Params, len(specs))
	for _, spec := range specs {
		value, provided := input[spec.Name]
		if !provided {
			if spec.Default == nil {
				if spec.Required {
					return nil, fmt.Errorf("required parameter %q is missing", spec.Name)
				}
				continue
			}
			value = spec.Default
		}

		value, err := normalizeParamValue(spec, value)
		if err != nil {
			return nil, err
		}
		if spec.Required && emptyParamValue(value) {
			return nil, fmt.Errorf("required parameter %q is empty", spec.Name)
		}
		normalized[spec.Name] = value
	}
	return normalized, nil
}

// ValidateParamSpecs checks that parameter definitions are complete and that
// their defaults match their declared types.
func ValidateParamSpecs(specs []ParamSpec) error {
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if spec.Name == "" {
			return fmt.Errorf("parameter spec has an empty name")
		}
		if _, exists := seen[spec.Name]; exists {
			return fmt.Errorf("duplicate parameter spec %q", spec.Name)
		}
		seen[spec.Name] = struct{}{}
		if !validParamType(spec.Type) {
			return fmt.Errorf("parameter %q has invalid type %q", spec.Name, spec.Type)
		}
		if spec.Range != nil && spec.Type != ParamInteger {
			return fmt.Errorf("parameter %q has integer bounds for type %q", spec.Name, spec.Type)
		}
		if spec.Range != nil && spec.Range.Max != 0 && spec.Range.Max < spec.Range.Min {
			return fmt.Errorf("parameter %q has invalid integer bounds", spec.Name)
		}
		if len(spec.Choices) > 0 && spec.Type != ParamString && spec.Type != ParamStringList {
			return fmt.Errorf("parameter %q has choices for type %q", spec.Name, spec.Type)
		}
		if spec.Default != nil {
			if _, err := normalizeParamValue(spec, spec.Default); err != nil {
				return fmt.Errorf("default: %w", err)
			}
		}
	}
	return nil
}

func validParamType(paramType ParamType) bool {
	switch paramType {
	case ParamString, ParamInteger, ParamBoolean, ParamPath, ParamStringList, ParamPathList:
		return true
	default:
		return false
	}
}

func normalizeParamValue(spec ParamSpec, value any) (any, error) {
	switch spec.Type {
	case ParamString, ParamPath:
		value, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("parameter %q must be %s", spec.Name, articleFor(spec.Type))
		}
		if err := validateChoice(spec, value); err != nil {
			return nil, err
		}
		return value, nil

	case ParamInteger:
		var parsed int
		switch value := value.(type) {
		case int:
			parsed = value
		case int8:
			parsed = int(value)
		case int16:
			parsed = int(value)
		case int32:
			parsed = int(value)
		case int64:
			parsed = int(value)
		case uint:
			parsed = int(value)
		case uint8:
			parsed = int(value)
		case uint16:
			parsed = int(value)
		case uint32:
			parsed = int(value)
		case string:
			var err error
			parsed, err = strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parameter %q must be an integer", spec.Name)
			}
		default:
			return nil, fmt.Errorf("parameter %q must be an integer", spec.Name)
		}
		if spec.Range != nil {
			if parsed < spec.Range.Min {
				return nil, fmt.Errorf("parameter %q must be at least %d", spec.Name, spec.Range.Min)
			}
			if spec.Range.Max != 0 && parsed > spec.Range.Max {
				return nil, fmt.Errorf("parameter %q must be at most %d", spec.Name, spec.Range.Max)
			}
		}
		return parsed, nil

	case ParamBoolean:
		switch value := value.(type) {
		case bool:
			return value, nil
		case string:
			switch strings.ToLower(value) {
			case "true":
				return true, nil
			case "false":
				return false, nil
			}
		}
		return nil, fmt.Errorf("parameter %q must be a boolean", spec.Name)

	case ParamStringList, ParamPathList:
		itemType := "string"
		if spec.Type == ParamPathList {
			itemType = "path"
		}
		var values []string
		if raw, ok := value.([]any); ok {
			values = make([]string, 0, len(raw))
			for i, item := range raw {
				text, ok := item.(string)
				if !ok || text == "" {
					return nil, fmt.Errorf("parameter %q item %d must be a %s", spec.Name, i+1, itemType)
				}
				values = append(values, text)
			}
		} else {
			var ok bool
			values, ok = stringList(value)
			if !ok {
				return nil, fmt.Errorf("parameter %q must be a %s", spec.Name, spec.Type)
			}
		}
		for i, value := range values {
			if value == "" {
				return nil, fmt.Errorf("parameter %q item %d must be a %s", spec.Name, i+1, itemType)
			}
			if err := validateChoice(spec, value); err != nil {
				return nil, fmt.Errorf("parameter %q item %d must be one of %s", spec.Name, i+1, quotedChoices(spec.Choices))
			}
		}
		return values, nil
	}
	return nil, fmt.Errorf("parameter %q has invalid type %q", spec.Name, spec.Type)
}

func validateChoice(spec ParamSpec, value string) error {
	if len(spec.Choices) == 0 {
		return nil
	}
	for _, choice := range spec.Choices {
		if value == choice {
			return nil
		}
	}
	return fmt.Errorf("parameter %q must be one of %s", spec.Name, quotedChoices(spec.Choices))
}

func quotedChoices(choices []string) string {
	quoted := make([]string, len(choices))
	for i, choice := range choices {
		quoted[i] = strconv.Quote(choice)
	}
	return strings.Join(quoted, ", ")
}

func articleFor(paramType ParamType) string {
	if paramType == ParamPath {
		return "a path"
	}
	return "a string"
}

func stringList(value any) ([]string, bool) {
	switch value := value.(type) {
	case []string:
		return append([]string(nil), value...), true
	case []any:
		values := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			values = append(values, text)
		}
		return values, true
	case string:
		if value == "" {
			return []string{}, true
		}
		parts := strings.Split(value, ",")
		values := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				values = append(values, part)
			}
		}
		return values, true
	default:
		return nil, false
	}
}

func emptyParamValue(value any) bool {
	switch value := value.(type) {
	case string:
		return value == ""
	case []string:
		return len(value) == 0
	default:
		return false
	}
}

// String returns a string parameter, or fallback when key is omitted.
func (p Params) String(key, fallback string) string {
	value, ok := p[key]
	if !ok {
		return fallback
	}
	text, ok := value.(string)
	if !ok {
		return fallback
	}
	return text
}

// Int returns an integer parameter, or fallback when key is omitted or invalid.
func (p Params) Int(key string, fallback int) int {
	value, ok := p[key]
	if !ok {
		return fallback
	}
	switch value := value.(type) {
	case int:
		return value
	case string:
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

// Bool returns a boolean parameter, or fallback when key is omitted or invalid.
func (p Params) Bool(key string, fallback bool) bool {
	value, ok := p[key]
	if !ok {
		return fallback
	}
	switch value := value.(type) {
	case bool:
		return value
	case string:
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

// Strings returns a string-list parameter, or fallback when key is omitted.
func (p Params) Strings(key string, fallback []string) []string {
	value, ok := p[key]
	if !ok {
		return append([]string(nil), fallback...)
	}
	values, ok := stringList(value)
	if !ok {
		return append([]string(nil), fallback...)
	}
	return values
}

// Paths returns a path-list parameter, or fallback when key is omitted.
func (p Params) Paths(key string, fallback []string) []string {
	return p.Strings(key, fallback)
}
