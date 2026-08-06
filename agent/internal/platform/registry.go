package platform

import (
	"fmt"
	"runtime"
)

var registry = map[string]PlatformDriver{}

// Register adds a PlatformDriver to the global registry.
// Called from each platform sub-package's init() function.
func Register(d PlatformDriver) {
	registry[d.Name()] = d
}

// Resolve returns the PlatformDriver for the current OS.
// Returns an error if no driver was registered for runtime.GOOS.
func Resolve() (PlatformDriver, error) {
	d, ok := registry[runtime.GOOS]
	if !ok {
		return nil, fmt.Errorf("no platform driver registered for %q — supported: %v", runtime.GOOS, keys(registry))
	}
	return d, nil
}

func keys(m map[string]PlatformDriver) []string {
	k := make([]string, 0, len(m))
	for name := range m {
		k = append(k, name)
	}
	return k
}
