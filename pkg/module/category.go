package module

// Category is the telemetry domain that a module belongs to.
type Category string

// Category constants for each supported telemetry domain.
const (
	CategoryNetwork          Category = "network"
	CategoryProcess          Category = "process"
	CategoryFile             Category = "file"
	CategoryTCC              Category = "tcc"
	CategoryEndpointSecurity Category = "endpoint_security"
	CategoryService          Category = "service"
	CategoryPlist            Category = "plist"
	CategoryXPC              Category = "xpc"
)

// AllCategories returns a slice containing every known Category value.
func AllCategories() []Category {
	return []Category{
		CategoryNetwork,
		CategoryProcess,
		CategoryFile,
		CategoryTCC,
		CategoryEndpointSecurity,
		CategoryService,
		CategoryPlist,
		CategoryXPC,
	}
}
