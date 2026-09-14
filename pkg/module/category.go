package module

// Category is the telemetry domain that a module belongs to.
type Category string

// Category constants for each supported telemetry domain.
const (
	CategoryNetwork    Category = "network"
	CategoryProcess    Category = "process"
	CategoryFile       Category = "file"
	CategoryTCC        Category = "tcc"
	CategoryService    Category = "service"
	CategoryPlist      Category = "plist"
	CategoryEvasion    Category = "evasion"
	CategoryCredential Category = "credential"
	CategoryVolume     Category = "volume"
)

// AllCategories returns a slice containing every known Category value.
func AllCategories() []Category {
	return []Category{
		CategoryNetwork,
		CategoryProcess,
		CategoryFile,
		CategoryTCC,
		CategoryService,
		CategoryPlist,
		CategoryEvasion,
		CategoryCredential,
		CategoryVolume,
	}
}
