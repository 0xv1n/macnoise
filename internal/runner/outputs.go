package runner

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/0xv1n/macnoise/pkg/module"
)

type outputCollector struct {
	mu     sync.Mutex
	specs  map[string]module.OutputSpec
	items  module.Params
	errors []error
}

func newOutputCollector(gen module.Generator) *outputCollector {
	specs := make(map[string]module.OutputSpec)
	if provider, ok := gen.(module.OutputProvider); ok {
		for _, spec := range provider.OutputSpecs() {
			specs[spec.Name] = spec
		}
	}
	return &outputCollector{specs: specs, items: make(module.Params)}
}

func (c *outputCollector) publish(name string, value any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	spec, ok := c.specs[name]
	if !ok {
		err := fmt.Errorf("undeclared module output %q", name)
		c.errors = append(c.errors, err)
		return err
	}
	if _, duplicate := c.items[name]; duplicate {
		err := fmt.Errorf("module output %q was published more than once", name)
		c.errors = append(c.errors, err)
		return err
	}
	normalized, err := module.NormalizeOutput(spec, value)
	if err != nil {
		c.errors = append(c.errors, err)
		return err
	}
	c.items[name] = normalized
	return nil
}

func (c *outputCollector) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return errors.Join(c.errors...)
}

func (c *outputCollector) requireAll() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	missing := make([]string, 0)
	for name := range c.specs {
		if _, ok := c.items[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("module did not publish declared output %q", missing[0])
}

func (c *outputCollector) values() module.Params {
	c.mu.Lock()
	defer c.mu.Unlock()
	values := make(module.Params, len(c.items))
	for name, value := range c.items {
		values[name] = value
	}
	return values
}
