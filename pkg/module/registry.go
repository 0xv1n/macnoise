package module

import (
	"fmt"
	"sort"
	"sync"
)

// Factory constructs an independent module invocation with no runtime state.
type Factory func() Generator

// Registry stores constructors, never module instances. Its zero value is usable.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// DefaultRegistry holds the built-in module constructors.
var DefaultRegistry Registry

// Register adds a constructor to the built-in registry.
func Register(newGenerator Factory) { DefaultRegistry.Register(newGenerator) }

// Register adds a constructor, panicking on duplicate or empty names.
func (r *Registry) Register(newGenerator Factory) {
	name := newGenerator().Info().Name
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" {
		panic("module: empty registration name")
	}
	if r.factories == nil {
		r.factories = make(map[string]Factory)
	}
	if _, exists := r.factories[name]; exists {
		panic(fmt.Sprintf("module: duplicate registration for %q", name))
	}
	r.factories[name] = newGenerator
}

// Get constructs a new invocation of a registered module.
func (r *Registry) Get(name string) (Generator, bool) {
	r.mu.RLock()
	newGenerator, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return newGenerator(), true
}

// Get constructs a new invocation from the built-in registry.
func Get(name string) (Generator, bool) { return DefaultRegistry.Get(name) }

// All constructs every registered module in name order.
func (r *Registry) All() []Generator {
	r.mu.RLock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	r.mu.RUnlock()
	sort.Strings(names)
	all := make([]Generator, 0, len(names))
	for _, name := range names {
		g, _ := r.Get(name)
		all = append(all, g)
	}
	return all
}

// All constructs every built-in module in name order.
func All() []Generator { return DefaultRegistry.All() }

// ByCategory constructs the modules belonging to a category.
func (r *Registry) ByCategory(cat Category) []Generator {
	var out []Generator
	for _, g := range r.All() {
		if g.Info().Category == cat {
			out = append(out, g)
		}
	}
	return out
}

// ByCategory constructs built-in modules belonging to a category.
func ByCategory(cat Category) []Generator { return DefaultRegistry.ByCategory(cat) }

// ByTag constructs the modules carrying tag.
func (r *Registry) ByTag(tag string) []Generator {
	var out []Generator
	for _, g := range r.All() {
		for _, candidate := range g.Info().Tags {
			if candidate == tag {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// ByTag constructs built-in modules carrying tag.
func ByTag(tag string) []Generator { return DefaultRegistry.ByTag(tag) }

// CategoryCounts reports the number of modules in each category.
func (r *Registry) CategoryCounts() map[Category]int {
	counts := make(map[Category]int)
	for _, g := range r.All() {
		counts[g.Info().Category]++
	}
	return counts
}

// CategoryCounts reports the number of built-in modules in each category.
func CategoryCounts() map[Category]int { return DefaultRegistry.CategoryCounts() }
