package module

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeParamsAppliesTypedDefaults(t *testing.T) {
	specs := []ParamSpec{
		{Name: "name", Type: ParamString, Default: "example"},
		{Name: "count", Type: ParamInteger, Default: 3, Range: &IntegerRange{Min: 1}},
		{Name: "enabled", Type: ParamBoolean, Default: false},
		{Name: "commands", Type: ParamStringList, Default: []string{"whoami", "uname -a"}},
		{Name: "paths", Type: ParamPathList},
		{Name: "mode", Type: ParamString, Choices: []string{"safe", "loud"}},
	}

	params, err := NormalizeParams(specs, Params{
		"count":   "5",
		"enabled": "true",
		"commands": []any{
			`printf "a,b"`,
			"id",
		},
		"paths": []any{"/tmp/one", "/tmp/two"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := params.String("name", "wrong"); got != "example" {
		t.Errorf("name = %q, want default", got)
	}
	if got := params.Int("count", 0); got != 5 {
		t.Errorf("count = %d, want 5", got)
	}
	if got := params.Bool("enabled", false); !got {
		t.Error("enabled = false, want true")
	}
	if got := params.Strings("commands", nil); !reflect.DeepEqual(got, []string{`printf "a,b"`, "id"}) {
		t.Errorf("commands = %#v", got)
	}
	if got := params.Paths("paths", nil); !reflect.DeepEqual(got, []string{"/tmp/one", "/tmp/two"}) {
		t.Errorf("paths = %#v", got)
	}
}

func TestNormalizeParamsPreservesExplicitEmptyValue(t *testing.T) {
	specs := []ParamSpec{{Name: "filter", Type: ParamString, Default: "com.apple"}}

	params, err := NormalizeParams(specs, Params{"filter": ""})
	if err != nil {
		t.Fatal(err)
	}
	if got := params.String("filter", "wrong"); got != "" {
		t.Errorf("filter = %q, want explicit empty value", got)
	}
}

func TestNormalizeParamsRejectsInvalidInputs(t *testing.T) {
	specs := []ParamSpec{
		{Name: "count", Type: ParamInteger, Range: &IntegerRange{Min: 0}},
		{Name: "enabled", Type: ParamBoolean},
		{Name: "paths", Type: ParamPathList},
		{Name: "mode", Type: ParamString, Choices: []string{"safe", "loud"}},
	}

	tests := []struct {
		name   string
		input  Params
		needle string
	}{
		{name: "unknown", input: Params{"other": "value"}, needle: `unknown parameter "other"`},
		{name: "integer", input: Params{"count": "many"}, needle: `parameter "count" must be an integer`},
		{name: "integer range", input: Params{"count": "-1"}, needle: `parameter "count" must be at least 0`},
		{name: "boolean", input: Params{"enabled": "sometimes"}, needle: `parameter "enabled" must be a boolean`},
		{name: "list element", input: Params{"paths": []any{"/tmp/ok", 7}}, needle: `parameter "paths" item 2 must be a path`},
		{name: "choice", input: Params{"mode": "quiet"}, needle: `parameter "mode" must be one of "safe", "loud"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeParams(specs, tt.input)
			if err == nil || !strings.Contains(err.Error(), tt.needle) {
				t.Fatalf("NormalizeParams error = %v, want %q", err, tt.needle)
			}
		})
	}
}

func TestRedactParams(t *testing.T) {
	params := Params{"target": "example.com", "password": "real-secret"}
	redacted := RedactParams([]ParamSpec{
		{Name: "target", Type: ParamString},
		{Name: "password", Type: ParamString, Sensitive: true},
	}, params)

	if redacted.String("target", "") != "example.com" {
		t.Errorf("target = %q, want preserved", redacted["target"])
	}
	if redacted.String("password", "") != RedactedValue {
		t.Errorf("password = %q, want redacted", redacted["password"])
	}
	if params.String("password", "") != "real-secret" {
		t.Error("RedactParams mutated its input")
	}
}
