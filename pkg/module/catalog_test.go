package module

import (
	"context"
	"testing"
)

type catalogTestGen struct{}

func (catalogTestGen) Info() ModuleInfo {
	return ModuleInfo{
		Name:        "cat_test",
		Category:    CategoryNetwork,
		Description: "desc",
		Privileges:  PrivilegeRoot,
		MinMacOS:    "12.0",
		Tags:        []string{"a", "b"},
		MITRE: []MITRE{
			{Technique: "T1071", SubTech: ".001", Name: "Application Layer Protocol: Web Protocols"},
			{Technique: "T1105", Name: "Ingress Tool Transfer"},
		},
	}
}
func (catalogTestGen) ParamSpecs() []ParamSpec {
	return []ParamSpec{
		{Name: "target", Description: "the target", Required: true, DefaultValue: "1.2.3.4", Example: "10.0.0.1"},
	}
}
func (catalogTestGen) CheckPrereqs() error                                  { return nil }
func (catalogTestGen) Generate(context.Context, Params, EventEmitter) error { return nil }
func (catalogTestGen) DryRun(Params) []string                               { return nil }
func (catalogTestGen) Cleanup() error                                       { return nil }

func TestNewCatalogEntry(t *testing.T) {
	e := NewCatalogEntry(catalogTestGen{})

	if e.Name != "cat_test" || e.Category != CategoryNetwork || e.Privileges != PrivilegeRoot {
		t.Errorf("core fields wrong: %+v", e)
	}
	if len(e.MITRE) != 2 {
		t.Fatalf("expected 2 MITRE entries, got %d", len(e.MITRE))
	}
	// Sub-technique is fully qualified.
	if e.MITRE[0].SubTechnique != "T1071.001" {
		t.Errorf("sub_technique = %q, want T1071.001", e.MITRE[0].SubTechnique)
	}
	// Technique-only entry leaves sub_technique empty.
	if e.MITRE[1].SubTechnique != "" {
		t.Errorf("sub_technique should be empty for technique-only mapping, got %q", e.MITRE[1].SubTechnique)
	}
	if len(e.Params) != 1 || e.Params[0].Name != "target" || !e.Params[0].Required || e.Params[0].Default != "1.2.3.4" {
		t.Errorf("params mapped wrong: %+v", e.Params)
	}
}
