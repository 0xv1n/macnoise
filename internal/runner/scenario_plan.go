package runner

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0xv1n/macnoise/pkg/module"
)

const (
	maxIncludeDepth        = 8
	maxScenarioInvocations = 1000
)

type outputReference struct {
	step string
	name string
}

type valueBinding struct {
	literal   any
	input     string
	ref       *outputReference
	typeName  module.ParamType
	sensitive bool
	label     string
}

type scenarioPlan struct {
	scenario Scenario
	path     string
	inputs   map[string]valueBinding
	steps    []plannedStep
	outputs  map[string]valueBinding
}

type plannedStep struct {
	id          string
	module      string
	includePath string
	policy      string
	params      map[string]valueBinding
	outputs     map[string]module.OutputSpec
	include     *scenarioPlan
}

type preflightState struct {
	registry *module.Registry
	rootDir  string
	stack    map[string]bool
	count    int
}

func preflightScenario(path string, rawInputs module.Params, registry *module.Registry) (*scenarioPlan, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("scenario: resolve %s: %w", path, err)
	}
	rootInputs := make(map[string]valueBinding, len(rawInputs))
	for name, value := range rawInputs {
		rootInputs[name] = valueBinding{literal: value}
	}
	state := &preflightState{
		registry: registry,
		rootDir:  filepath.Dir(absPath),
		stack:    make(map[string]bool),
	}
	return state.load(absPath, rootInputs, 0)
}

// ValidateScenario performs the same recursive preflight used by execution
// without creating a workspace or invoking a module.
func ValidateScenario(path string, inputs module.Params, registry *module.Registry) error {
	if registry == nil {
		registry = &module.DefaultRegistry
	}
	_, err := preflightScenario(path, inputs, registry)
	return err
}

func (s *preflightState) load(path string, supplied map[string]valueBinding, depth int) (*scenarioPlan, error) {
	if depth > maxIncludeDepth {
		return nil, fmt.Errorf("scenario: include depth exceeds %d", maxIncludeDepth)
	}
	path = filepath.Clean(path)
	if s.stack[path] {
		return nil, fmt.Errorf("scenario: include cycle at %s", path)
	}
	s.stack[path] = true
	defer delete(s.stack, path)

	sc, err := LoadScenario(path)
	if err != nil {
		return nil, err
	}
	inputs, err := bindScenarioInputs(sc.Inputs, supplied)
	if err != nil {
		return nil, fmt.Errorf("scenario %q inputs: %w", sc.Name, err)
	}

	plan := &scenarioPlan{scenario: sc, path: path, inputs: inputs}
	priorOutputs := make(map[string]map[string]module.OutputSpec)
	seenIDs := make(map[string]bool)

	for index, rawStep := range sc.Steps {
		if err := validateFailurePolicy(rawStep.OnError); err != nil {
			return nil, fmt.Errorf("scenario %q step %d: %w", sc.Name, index+1, err)
		}
		policy := rawStep.OnError
		if policy == "" {
			policy = sc.OnError
		}
		if policy == "" {
			policy = "stop"
		}
		id := rawStep.ID
		if id == "" {
			id = fmt.Sprintf("step_%d", index+1)
		}
		if !validScenarioIdentifier(id) {
			return nil, fmt.Errorf("scenario %q step %d: invalid id %q", sc.Name, index+1, id)
		}
		if seenIDs[id] {
			return nil, fmt.Errorf("scenario %q: duplicate step id %q", sc.Name, id)
		}
		seenIDs[id] = true

		selectors := 0
		if rawStep.Module != "" {
			selectors++
		}
		if rawStep.Category != "" {
			selectors++
		}
		if rawStep.Include != "" {
			selectors++
		}
		if selectors != 1 {
			return nil, fmt.Errorf("scenario %q step %d: specify exactly one of module, category, or include", sc.Name, index+1)
		}

		switch {
		case rawStep.Module != "":
			if len(rawStep.Inputs) != 0 {
				return nil, fmt.Errorf("scenario %q step %d: inputs are only valid for includes", sc.Name, index+1)
			}
			step, err := s.moduleStep(id, rawStep.Module, policy, rawStep.Params, inputs, priorOutputs)
			if err != nil {
				return nil, fmt.Errorf("scenario %q step %d: %w", sc.Name, index+1, err)
			}
			plan.steps = append(plan.steps, step)
			priorOutputs[id] = step.outputs

		case rawStep.Category != "":
			if len(rawStep.Inputs) != 0 {
				return nil, fmt.Errorf("scenario %q step %d: inputs are only valid for includes", sc.Name, index+1)
			}
			gens := s.registry.ByCategory(module.Category(rawStep.Category))
			if len(gens) == 0 {
				return nil, fmt.Errorf("scenario %q step %d: no modules found for category %q", sc.Name, index+1, rawStep.Category)
			}
			for _, gen := range gens {
				step, err := s.moduleStep(id+"."+gen.Info().Name, gen.Info().Name, policy, rawStep.Params, inputs, priorOutputs)
				if err != nil {
					return nil, fmt.Errorf("scenario %q step %d module %q: %w", sc.Name, index+1, gen.Info().Name, err)
				}
				plan.steps = append(plan.steps, step)
			}

		case rawStep.Include != "":
			if len(rawStep.Params) != 0 {
				return nil, fmt.Errorf("scenario %q step %d: params are not valid for includes", sc.Name, index+1)
			}
			includePath, err := s.resolveInclude(path, rawStep.Include)
			if err != nil {
				return nil, fmt.Errorf("scenario %q step %d: %w", sc.Name, index+1, err)
			}
			bindings, err := compileBindings(rawStep.Inputs, inputs, priorOutputs, nil)
			if err != nil {
				return nil, fmt.Errorf("scenario %q step %d inputs: %w", sc.Name, index+1, err)
			}
			child, err := s.load(includePath, bindings, depth+1)
			if err != nil {
				return nil, err
			}
			outputs := make(map[string]module.OutputSpec, len(child.outputs))
			for name, binding := range child.outputs {
				outputs[name] = module.OutputSpec{Name: name, Type: binding.typeName, Sensitive: binding.sensitive}
			}
			plan.steps = append(plan.steps, plannedStep{
				id:          id,
				includePath: includePath,
				policy:      policy,
				outputs:     outputs,
				include:     child,
			})
			priorOutputs[id] = outputs
		}
	}

	plan.outputs = make(map[string]valueBinding, len(sc.Outputs))
	for name, value := range sc.Outputs {
		if !validScenarioIdentifier(name) {
			return nil, fmt.Errorf("scenario %q has invalid output name %q", sc.Name, name)
		}
		if value.Output == "" || value.Input != "" || value.Literal != nil {
			return nil, fmt.Errorf("scenario %q output %q must reference a preceding step output", sc.Name, name)
		}
		binding, err := compileReference(value, inputs, priorOutputs, nil)
		if err != nil {
			return nil, fmt.Errorf("scenario %q output %q: %w", sc.Name, name, err)
		}
		plan.outputs[name] = binding
	}
	return plan, nil
}

func (s *preflightState) moduleStep(id, name, policy string, raw map[string]ScenarioValue, inputs map[string]valueBinding, prior map[string]map[string]module.OutputSpec) (plannedStep, error) {
	gen, ok := s.registry.Get(name)
	if !ok {
		return plannedStep{}, fmt.Errorf("module %q not found", name)
	}
	s.count++
	if s.count > maxScenarioInvocations {
		return plannedStep{}, fmt.Errorf("expanded scenario exceeds %d module invocations", maxScenarioInvocations)
	}
	params, err := compileBindings(raw, inputs, prior, gen.ParamSpecs())
	if err != nil {
		return plannedStep{}, err
	}
	if _, err := module.NormalizeParams(gen.ParamSpecs(), representativeParams(params, gen.ParamSpecs())); err != nil {
		return plannedStep{}, fmt.Errorf("module %q params: %w", name, err)
	}
	outputs := make(map[string]module.OutputSpec)
	if provider, ok := gen.(module.OutputProvider); ok {
		for _, spec := range provider.OutputSpecs() {
			outputs[spec.Name] = spec
		}
	}
	return plannedStep{id: id, module: name, policy: policy, params: params, outputs: outputs}, nil
}

func (s *preflightState) resolveInclude(parent, include string) (string, error) {
	if filepath.IsAbs(include) {
		return "", fmt.Errorf("include %q must be relative", include)
	}
	resolved, err := filepath.Abs(filepath.Join(filepath.Dir(parent), include))
	if err != nil {
		return "", fmt.Errorf("resolve include %q: %w", include, err)
	}
	rel, err := filepath.Rel(s.rootDir, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("include %q escapes scenario root %s", include, s.rootDir)
	}
	return resolved, nil
}

func bindScenarioInputs(declared map[string]ScenarioInput, supplied map[string]valueBinding) (map[string]valueBinding, error) {
	for name := range supplied {
		if _, ok := declared[name]; !ok {
			return nil, fmt.Errorf("unknown input %q", name)
		}
	}
	names := sortedKeys(declared)
	specs := make([]module.ParamSpec, 0, len(names))
	for _, name := range names {
		if !validScenarioIdentifier(name) {
			return nil, fmt.Errorf("invalid input name %q", name)
		}
		decl := declared[name]
		specs = append(specs, module.ParamSpec{Name: name, Type: decl.Type, Required: decl.Required, Sensitive: decl.Sensitive, Default: decl.Default})
	}
	if err := module.ValidateParamSpecs(specs); err != nil {
		return nil, err
	}

	bound := make(map[string]valueBinding, len(declared))
	for _, spec := range specs {
		value, ok := supplied[spec.Name]
		if !ok {
			if spec.Default == nil {
				if spec.Required {
					return nil, fmt.Errorf("required input %q is missing", spec.Name)
				}
				continue
			}
			value = valueBinding{literal: spec.Default}
		}
		value.sensitive = value.sensitive || spec.Sensitive
		if value.typeName != "" {
			if value.typeName != spec.Type {
				return nil, fmt.Errorf("input %q requires %s, got %s", spec.Name, spec.Type, value.typeName)
			}
		} else {
			normalized, err := module.NormalizeParams([]module.ParamSpec{spec}, module.Params{spec.Name: value.literal})
			if err != nil {
				return nil, err
			}
			value.literal = normalized[spec.Name]
			value.typeName = spec.Type
		}
		bound[spec.Name] = value
	}
	return bound, nil
}

func compileBindings(raw map[string]ScenarioValue, inputs map[string]valueBinding, prior map[string]map[string]module.OutputSpec, specs []module.ParamSpec) (map[string]valueBinding, error) {
	byName := make(map[string]module.ParamSpec, len(specs))
	for _, spec := range specs {
		byName[spec.Name] = spec
	}
	bound := make(map[string]valueBinding, len(raw))
	for name, value := range raw {
		var target *module.ParamSpec
		if specs != nil {
			spec, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("unknown parameter %q", name)
			}
			target = &spec
		}
		binding, err := compileReference(value, inputs, prior, target)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		bound[name] = binding
	}
	return bound, nil
}

func compileReference(value ScenarioValue, inputs map[string]valueBinding, prior map[string]map[string]module.OutputSpec, target *module.ParamSpec) (valueBinding, error) {
	var binding valueBinding
	switch {
	case value.Input != "":
		found, ok := inputs[value.Input]
		if !ok {
			return binding, fmt.Errorf("unknown input %q", value.Input)
		}
		binding = valueBinding{
			input:     value.Input,
			typeName:  found.typeName,
			sensitive: found.sensitive,
			label:     "input:" + value.Input,
		}
	case value.Output != "":
		ref, err := parseOutputReference(value.Output)
		if err != nil {
			return binding, err
		}
		outputs, ok := prior[ref.step]
		if !ok {
			return binding, fmt.Errorf("output reference %q does not name a preceding step", value.Output)
		}
		spec, ok := outputs[ref.name]
		if !ok {
			return binding, fmt.Errorf("step %q has no output %q", ref.step, ref.name)
		}
		binding = valueBinding{ref: &ref, typeName: spec.Type, sensitive: spec.Sensitive, label: "output:" + value.Output}
	default:
		binding.literal = value.Literal
	}

	if target != nil {
		if binding.typeName != "" {
			if binding.typeName != target.Type {
				return valueBinding{}, fmt.Errorf("requires %s, got %s", target.Type, binding.typeName)
			}
			binding.sensitive = binding.sensitive || target.Sensitive
			return binding, nil
		}
		normalized, err := module.NormalizeParams([]module.ParamSpec{*target}, module.Params{target.Name: binding.literal})
		if err != nil {
			return valueBinding{}, err
		}
		binding.literal = normalized[target.Name]
		binding.typeName = target.Type
		binding.sensitive = target.Sensitive
	}
	return binding, nil
}

func parseOutputReference(raw string) (outputReference, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return outputReference{}, fmt.Errorf("invalid output reference %q (want step.output)", raw)
	}
	return outputReference{step: parts[0], name: parts[1]}, nil
}

func representativeParams(bindings map[string]valueBinding, specs []module.ParamSpec) module.Params {
	params := make(module.Params, len(bindings))
	byName := make(map[string]module.ParamSpec, len(specs))
	for _, spec := range specs {
		byName[spec.Name] = spec
	}
	for name, binding := range bindings {
		if binding.ref == nil && binding.input == "" {
			params[name] = binding.literal
			continue
		}
		params[name] = placeholderValue(byName[name], binding.label)
	}
	return params
}

func placeholderValue(spec module.ParamSpec, label string) any {
	placeholder := "<" + label + ">"
	switch spec.Type {
	case module.ParamInteger:
		if spec.Default != nil {
			return spec.Default
		}
		if spec.Range != nil {
			return spec.Range.Min
		}
		return 0
	case module.ParamBoolean:
		return false
	case module.ParamStringList, module.ParamPathList:
		return []string{placeholder}
	default:
		if len(spec.Choices) > 0 {
			return spec.Choices[0]
		}
		return placeholder
	}
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validScenarioIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}
