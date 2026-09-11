package main

import (
	"context"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"
)

func TestParseParamsRejectsMalformedFlags(t *testing.T) {
	for _, flags := range [][]string{{"missing-separator"}, {"=value"}} {
		if _, err := parseParams(flags); err == nil {
			t.Errorf("parseParams(%q) returned nil error", flags)
		}
	}
}

func TestParseParamsPreservesRepeatedListValues(t *testing.T) {
	raw, err := parseParams([]string{"paths=/tmp/one,part", "paths=/tmp/two"})
	if err != nil {
		t.Fatal(err)
	}
	params, err := module.NormalizeParams([]module.ParamSpec{{Name: "paths", Type: module.ParamPathList}}, raw)
	if err != nil {
		t.Fatal(err)
	}
	paths := params.Paths("paths", nil)
	if len(paths) != 2 || paths[0] != "/tmp/one,part" || paths[1] != "/tmp/two" {
		t.Fatalf("paths = %#v", paths)
	}
}

func TestParseParamsPreservesExplicitEmptyValue(t *testing.T) {
	params, err := parseParams([]string{"filter="})
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := params["filter"]; !ok || value != "" {
		t.Fatalf("filter = %#v, present = %v", value, ok)
	}
}

func TestNegativePayloadSizeIsRejectedBeforeExecution(t *testing.T) {
	gen, ok := module.Get("net_exfil")
	if !ok {
		t.Fatal("net_exfil is not registered")
	}

	err := runner.RunSingle(context.Background(), gen, module.Params{"payload_size": "-1"}, func(module.TelemetryEvent) {}, runner.Options{})
	if err == nil || !strings.Contains(err.Error(), `parameter "payload_size" must be at least 0`) {
		t.Fatalf("RunSingle error = %v", err)
	}
}
