package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/montanaflynn/envc/internal/resolve"
)

// overridePath returns the absolute path of the override file for env: the
// dotenv destination's `override` if configured, else ./.env.local. exists
// reports whether a file is there.
func (a *App) overridePath(env string) (path string, exists bool) {
	path = ".env.local"
	if cfg, ok := a.Roster.Sync[env]["dotenv"]; ok {
		if v, ok := cfg["override"].(string); ok && v != "" {
			path = v
		}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(a.root(), path)
	}
	_, err := os.Stat(path)
	return path, err == nil
}

// RunEnv builds the child environment for `envc run`:
// process env > override file > resolved values. Returns KEY=value strings.
func (a *App) RunEnv(env string, pure bool, environ []string) ([]string, error) {
	base, err := a.Resolve(env)
	if err != nil {
		return nil, err
	}
	layers := []resolve.Vars{base}
	if !pure {
		if path, ok := a.overridePath(env); ok {
			data, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, exitErr(ExitDrift, fmt.Errorf("read %s: %w", path, err))
			}
			if err == nil {
				vars, err := resolve.Parse(string(data))
				if err != nil {
					return nil, usagef("parse %s: %v", path, err)
				}
				layers = append(layers, vars)
			}
		}
	}
	proc := make(resolve.Vars, len(environ))
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		proc[k] = v
	}
	layers = append(layers, proc)
	return sortedVars(resolve.Merge(layers...)), nil
}
