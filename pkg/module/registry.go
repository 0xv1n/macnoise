package module

import (
	"fmt"
	"sort"
	"sync"
)

var (
	mu       sync.RWMutex
	registry = map[string]Generator{}
)

// Register adds g to the global module registry. It panics on duplicate names.
func Register(g Generator) {
	mu.Lock()
	defer mu.Unlock()
	name := g.Info().Name
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("module: duplicate registration for %q", name))
	}
	registry[name] = g
}

// Get looks up a module by name, returning it and a found boolean.
func Get(name string) (Generator, bool) {
	mu.RLock()
	defer mu.RUnlock()
	g, ok := registry[name]
	return g, ok
}

// All returns every registered module sorted by name.
func All() []Generator {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Generator, 0, len(registry))
	for _, g := range registry {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Info().Name < out[j].Info().Name
	})
	return out
}

// ByCategory returns all registered modules in the given category, sorted by name.
func ByCategory(cat Category) []Generator {
	mu.RLock()
	defer mu.RUnlock()
	var out []Generator
	for _, g := range registry {
		if g.Info().Category == cat {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Info().Name < out[j].Info().Name
	})
	return out
}

// ByTag returns all registered modules that carry the given tag, sorted by name.
func ByTag(tag string) []Generator {
	mu.RLock()
	defer mu.RUnlock()
	var out []Generator
	for _, g := range registry {
		for _, t := range g.Info().Tags {
			if t == tag {
				out = append(out, g)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Info().Name < out[j].Info().Name
	})
	return out
}

// CategoryCounts returns a map from Category to the number of registered modules in that category.
func CategoryCounts() map[Category]int {
	mu.RLock()
	defer mu.RUnlock()
	counts := map[Category]int{}
	for _, g := range registry {
		counts[g.Info().Category]++
	}
	return counts
}
