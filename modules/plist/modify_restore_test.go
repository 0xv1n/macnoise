package plistmod

import (
	"reflect"
	"testing"
)

func TestRestorePreferenceValue(t *testing.T) {
	values := map[string]any{
		"string":  "original",
		"boolean": true,
		"integer": uint64(42),
		"real":    1.25,
		"data":    []byte{0x01, 0x02, 0x03},
		"array":   []any{"first", uint64(2), false},
		"dict":    map[string]any{"nested": true, "count": uint64(3)},
	}

	for name, prior := range values {
		t.Run(name, func(t *testing.T) {
			current := map[string]any{"Target": "replacement", "Concurrent": true}
			if err := restorePreferenceValue(current, "Target", "replacement", prior); err != nil {
				t.Fatalf("restorePreferenceValue: %v", err)
			}
			if !reflect.DeepEqual(current["Target"], prior) {
				t.Errorf("restored value = %#v, want %#v", current["Target"], prior)
			}
			if current["Concurrent"] != true {
				t.Error("restoration changed an unrelated current key")
			}
		})
	}
}

func TestRestorePreferenceValue_ReportsConflict(t *testing.T) {
	for _, current := range map[string]map[string]any{
		"missing":    {},
		"changed":    {"Target": "external change"},
		"wrong type": {"Target": true},
	} {
		if err := restorePreferenceValue(current, "Target", "replacement", "prior"); err == nil {
			t.Errorf("restorePreferenceValue(%#v) succeeded, want conflict", current)
		}
	}
}
