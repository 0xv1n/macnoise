package module_test

import (
	"context"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

type testGen struct {
	name     string
	category module.Category
	tags     []string
}

func (t *testGen) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:       t.name,
		Category:   t.category,
		Tags:       t.tags,
		Privileges: module.PrivilegeNone,
	}
}
func (t *testGen) ParamSpecs() []module.ParamSpec                               { return nil }
func (t *testGen) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }
func (t *testGen) Generate(_ context.Context, _ module.Params, _ module.EventEmitter) error {
	return nil
}
func (t *testGen) DryRun(_ module.Params) []string   { return nil }
func (t *testGen) Cleanup(ctx context.Context) error { return nil }

func TestRegisterAndGet(t *testing.T) {
	var registry module.Registry
	registry.Register(func() module.Generator {
		return &testGen{name: "test_reg_get", category: "network"}
	})

	got, ok := registry.Get("test_reg_get")
	if !ok {
		t.Fatal("expected to find registered module")
	}
	if got.Info().Name != "test_reg_get" {
		t.Errorf("got name %q, want %q", got.Info().Name, "test_reg_get")
	}
}

func TestRegistryReturnsIndependentInvocations(t *testing.T) {
	var registry module.Registry
	registry.Register(func() module.Generator { return &testGen{name: "test_independent"} })
	first, _ := registry.Get("test_independent")
	second, _ := registry.Get("test_independent")
	first.(*testGen).tags = []string{"mutated"}
	if len(second.Info().Tags) != 0 {
		t.Fatal("registry reused mutable invocation state")
	}
}

func TestGetMissing(t *testing.T) {
	var registry module.Registry
	_, ok := registry.Get("does_not_exist_xyz")
	if ok {
		t.Error("expected ok=false for non-existent module")
	}
}

func TestAllSorted(t *testing.T) {
	var registry module.Registry
	registry.Register(func() module.Generator { return &testGen{name: "test_all_b", category: "process"} })
	registry.Register(func() module.Generator { return &testGen{name: "test_all_a", category: "process"} })

	all := registry.All()
	for i := 1; i < len(all); i++ {
		if all[i-1].Info().Name > all[i].Info().Name {
			t.Errorf("All() not sorted: %q > %q", all[i-1].Info().Name, all[i].Info().Name)
		}
	}
}

func TestByCategory(t *testing.T) {
	var registry module.Registry
	registry.Register(func() module.Generator { return &testGen{name: "test_cat_net", category: "network_test_cat"} })
	registry.Register(func() module.Generator { return &testGen{name: "test_cat_proc", category: "process_test_cat"} })

	nets := registry.ByCategory("network_test_cat")
	if len(nets) != 1 {
		t.Errorf("expected 1 network_test_cat module, got %d", len(nets))
	}
	if nets[0].Info().Name != "test_cat_net" {
		t.Errorf("unexpected module: %s", nets[0].Info().Name)
	}
}

func TestByTag(t *testing.T) {
	var registry module.Registry
	registry.Register(func() module.Generator {
		return &testGen{name: "test_tag_a", category: "file", tags: []string{"dns", "outbound"}}
	})
	registry.Register(func() module.Generator {
		return &testGen{name: "test_tag_b", category: "file", tags: []string{"tcp"}}
	})

	tagged := registry.ByTag("dns")
	if len(tagged) != 1 {
		t.Errorf("expected 1 dns-tagged module, got %d", len(tagged))
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	var registry module.Registry
	registry.Register(func() module.Generator {
		return &testGen{name: "test_dup_panic", category: "network"}
	})
	registry.Register(func() module.Generator {
		return &testGen{name: "test_dup_panic", category: "network"}
	})
}

func TestCategoryCounts(t *testing.T) {
	var registry module.Registry
	registry.Register(func() module.Generator { return &testGen{name: "test_count_1", category: "xpc_test"} })
	registry.Register(func() module.Generator { return &testGen{name: "test_count_2", category: "xpc_test"} })

	counts := registry.CategoryCounts()
	if counts["xpc_test"] != 2 {
		t.Errorf("expected count 2 for xpc_test, got %d", counts["xpc_test"])
	}
}
