package module

// CatalogEntry is the machine-readable description of a module emitted by
// `macnoise list --format jsonl`. It lets a consumer discover modules, their
// ATT&CK mappings, and parameters without parsing the human-readable table.
//
// It intentionally mirrors ModuleInfo and ParamSpec into its own JSON shape
// rather than tagging those shared structs, so the telemetry event schema
// (which already serialises ModuleInfo.MITRE) is left untouched.
type CatalogEntry struct {
	Name        string         `json:"name"`
	Category    Category       `json:"category"`
	Description string         `json:"description"`
	Privileges  Privilege      `json:"privileges"`
	MinMacOS    string         `json:"min_macos,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	MITRE       []CatalogMITRE `json:"mitre,omitempty"`
	Params      []CatalogParam `json:"params,omitempty"`
}

// CatalogMITRE is one ATT&CK reference in a CatalogEntry. SubTechnique is the
// fully-qualified sub-technique ID (e.g. "T1071.001"), empty when the mapping
// is at technique granularity.
type CatalogMITRE struct {
	Technique    string `json:"technique"`
	SubTechnique string `json:"sub_technique,omitempty"`
	Name         string `json:"name"`
}

// CatalogParam is one parameter in a CatalogEntry.
type CatalogParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
	Example     string `json:"example,omitempty"`
}

// NewCatalogEntry builds the catalog view of a module from its Info and
// parameter specs.
func NewCatalogEntry(g Generator) CatalogEntry {
	info := g.Info()

	mitre := make([]CatalogMITRE, 0, len(info.MITRE))
	for _, m := range info.MITRE {
		cm := CatalogMITRE{Technique: m.Technique, Name: m.Name}
		if m.SubTech != "" {
			cm.SubTechnique = m.Technique + m.SubTech
		}
		mitre = append(mitre, cm)
	}

	specs := g.ParamSpecs()
	params := make([]CatalogParam, 0, len(specs))
	for _, s := range specs {
		params = append(params, CatalogParam{
			Name:        s.Name,
			Description: s.Description,
			Required:    s.Required,
			Default:     s.DefaultValue,
			Example:     s.Example,
		})
	}

	return CatalogEntry{
		Name:        info.Name,
		Category:    info.Category,
		Description: info.Description,
		Privileges:  info.Privileges,
		MinMacOS:    info.MinMacOS,
		Tags:        info.Tags,
		MITRE:       mitre,
		Params:      params,
	}
}
