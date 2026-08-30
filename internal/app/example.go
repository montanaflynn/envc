package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/resolve"
)

// exampleName is the repo-relative name of env's template: .env.<env>.example.
func exampleName(env string) string { return ".env." + env + ".example" }

// ExamplePath returns root/.env.<env>.example.
func ExamplePath(root, env string) string { return filepath.Join(root, exampleName(env)) }

// Example renders the .env template for env from the manifest on disk: every
// key in manifest order with its metadata as comments, public values filled,
// secrets blank. It needs no envelope, no key, and no decrypt access; a
// manifest whose secrets are still plaintext renders them blank too.
func (a *App) Example(env string) (string, error) {
	if err := baseGuard(env); err != nil {
		return "", err
	}
	f, err := a.loadLenient(env)
	if err != nil {
		return "", err
	}
	return a.exampleText(env, f)
}

// exampleText is Example for an already-loaded manifest: the resolved view,
// with inherited entries marked "# from base".
func (a *App) exampleText(env string, f *envfile.File) (string, error) {
	v, err := a.view(env, f)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# .env template for %s, written by envc. Secrets are blank; do not edit — it is regenerated from %s.\n", env, relPath(envfile.Path("", env)))
	fmt.Fprintf(&b, "# Copy any line into %s to override it for `envc run`.\n", a.overrideName(env))
	for _, k := range v.Keys() {
		e := v.Config[k]
		b.WriteByte('\n')
		if e.Description != "" {
			for _, line := range strings.Split(strings.TrimRight(e.Description, "\n"), "\n") {
				b.WriteString("# " + line + "\n")
			}
		}
		if e.IsSecret() {
			b.WriteString("# secret\n")
		}
		if !e.IsRequired() {
			b.WriteString("# optional\n")
		}
		if len(e.Enum) > 0 {
			b.WriteString("# enum: " + strings.Join(e.Enum, ", ") + "\n")
		}
		if e.Pattern != "" {
			b.WriteString("# pattern: " + e.Pattern + "\n")
		}
		if v.Origin[k] == BaseName {
			b.WriteString("# from base\n")
		}
		if e.IsSecret() {
			b.WriteString(k + "=\n")
		} else {
			b.WriteString(resolve.EncodeLine(k, e.Value) + "\n")
		}
	}
	return b.String(), nil
}

// refreshAllExamples rewrites every environment's template (after a base
// change). Environments whose manifest does not load are skipped; check
// reports them.
func (a *App) refreshAllExamples() error {
	envs, err := a.EnvList()
	if err != nil {
		return err
	}
	for _, env := range envs {
		f, err := a.loadLenient(env)
		if err != nil {
			continue
		}
		if err := a.refreshExample(env, f); err != nil {
			return err
		}
	}
	return nil
}

// overrideName is the display name of env's override file: the dotenv
// destination's `override` if configured, else .env.local.
func (a *App) overrideName(env string) string {
	if v, ok := a.Roster.Sync[env]["dotenv"]["override"].(string); ok && v != "" {
		return v
	}
	return ".env.local"
}

// refreshExample writes .env.<env>.example for f unless DryRun. The file is
// only touched when its content would change. Called by every manifest save
// and after sync; reads never call it.
func (a *App) refreshExample(env string, f *envfile.File) error {
	if a.Opts.DryRun || isBase(env) {
		return nil
	}
	want, err := a.exampleText(env, f)
	if err != nil {
		return err
	}
	path := ExamplePath(a.root(), env)
	if have, err := os.ReadFile(path); err == nil && string(have) == want {
		return nil
	}
	if err := writeFileAtomic(path, []byte(want), 0o644); err != nil {
		return exitErr(ExitDrift, fmt.Errorf("write %s: %w", exampleName(env), err))
	}
	return nil
}

// removeExample deletes .env.<env>.example; missing is fine.
func removeExample(root, env string) error {
	if err := os.Remove(ExamplePath(root, env)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return exitErr(ExitDrift, fmt.Errorf("remove %s: %w", exampleName(env), err))
	}
	return nil
}

// exampleStale reports whether .env.<env>.example is missing or differs
// from what the loaded manifest would generate. It never writes.
func (a *App) exampleStale(env string, f *envfile.File) bool {
	want, err := a.exampleText(env, f)
	if err != nil {
		return false
	}
	have, err := os.ReadFile(ExamplePath(a.root(), env))
	return err != nil || string(have) != want
}

// writeFileAtomic writes data to a temp file beside path and renames it into place.
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
