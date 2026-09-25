// Package destination defines where resolved values can be written and the registry
// of implementations. Destinations receive already-decrypted values and know
// nothing about crypto or access.
package destination

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry is one variable as a destination sees it.
type Entry struct {
	Value  string
	Secret bool // Live may leave Value empty when the host hides it
	// Updated is when the host last changed the variable, zero when it does
	// not say. Live sets it where the host hides values, so diff can notice an
	// edit made at the host since the last sync without reading the value.
	Updated time.Time
}

// Snapshot is the set of variables at (or wanted at) a destination.
type Snapshot map[string]Entry

// ApplyOptions tunes Apply.
type ApplyOptions struct {
	Prune  bool // delete destination keys not in want
	DryRun bool // report what would change without writing
}

// Report summarizes an Apply. Each slice holds key names, sorted.
type Report struct {
	Created, Updated, Unchanged, Pruned, Skipped []string
}

// Destination is the extension point. See README → "Adding a destination".
type Destination interface {
	Name() string
	Live(ctx context.Context) (Snapshot, error)
	Apply(ctx context.Context, want Snapshot, opts ApplyOptions) (Report, error)
}

// Env is what a Factory gets to build a Destination.
type Env struct {
	Root   string              // repo root
	Env    string              // environment name, e.g. "production"
	Getenv func(string) string // for tokens; never os.Getenv directly
	Log    io.Writer           // stderr for progress
}

// Factory builds a Destination from its raw sync.<env>.<name> config.
// Unknown config fields are an error.
type Factory func(env Env, raw map[string]any) (Destination, error)

// The registry is the one sanctioned global (see README → Architecture). It is
// populated from init() in each implementation package.
var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register adds a factory under name. Called from init() in each impl package.
// Registering the same name twice, an empty name, or a nil factory is a
// programming error and panics.
func Register(name string, f Factory) {
	if name == "" {
		panic("destination: Register with empty name")
	}
	if f == nil {
		panic(fmt.Sprintf("destination: Register(%q) with nil factory", name))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("destination: %q registered twice", name))
	}
	registry[name] = f
}

// Registered reports whether name has a factory.
func Registered(name string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := registry[name]
	return ok
}

// Names lists registered destination names, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// New builds a destination by name.
func New(name string, env Env, raw map[string]any) (Destination, error) {
	mu.RLock()
	f, ok := registry[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown destination %q (registered: %s)", name, strings.Join(Names(), ", "))
	}
	// Implementations prefix their own errors with the destination name.
	return f(env, raw)
}

// ReadsBackSecrets reports whether a destination can return secret values from
// Live (dotenv can; github and vercel cannot). Used by diff messages.
type SecretReader interface {
	ReadsBackSecrets() bool
}

// CaseInsensitiveNames is implemented by destinations that store variable
// names case-insensitively (GitHub folds them to uppercase). diff then
// matches a live name to the wanted key with strings.EqualFold instead of
// reporting the key missing and its folded spelling extra.
type CaseInsensitiveNames interface {
	CaseInsensitiveNames() bool
}
