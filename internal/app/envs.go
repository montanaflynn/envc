package app

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/montanaflynn/envc/internal/destination/github"
	"github.com/montanaflynn/envc/internal/destination/vercel"
	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/roster"
	"github.com/montanaflynn/envc/internal/state"
)

// envNamePattern is the allowed shape of an environment name: it becomes a
// file name under .envc/environments/, so no separators or leading dots.
var envNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func checkEnvName(env string) error {
	if isBase(env) {
		return usagef("%s", BaseNotEnvMsg)
	}
	if !envNamePattern.MatchString(env) {
		return usagef("invalid environment name %q (must match %s)", env, envNamePattern)
	}
	return nil
}

// EnvAdd creates .envc/environments/<env>.yaml if missing and merges destinations into
// sync.<env>. Settings that a destination would otherwise derive from local,
// uncommitted state are resolved now and pinned: the Vercel project (and
// team) from .vercel/project.json, the GitHub repository from git remote
// origin. `check` (and CI, where neither exists) then never has to guess.
func (a *App) EnvAdd(env string, o EnvAddOptions) error {
	if err := checkEnvName(env); err != nil {
		return err
	}
	dests := a.Roster.Sync[env]
	if dests == nil {
		dests = map[string]roster.DestConfig{}
	}
	merge := func(name string, fields map[string]string) {
		cfg := dests[name]
		if cfg == nil {
			cfg = roster.DestConfig{}
		}
		for k, v := range fields {
			if v != "" {
				cfg[k] = v
			}
		}
		dests[name] = cfg
	}

	if o.Override != "" && o.Dotenv == "" && dests["dotenv"] == nil {
		return usagef("env add %s: --override requires --dotenv (or an existing dotenv destination)", env)
	}
	if o.Dotenv != "" || o.Override != "" {
		merge("dotenv", map[string]string{"path": o.Dotenv, "override": o.Override})
	}
	switch o.GitHubScope {
	case "", github.ScopeEnvironment:
		if o.GitHubScope != "" && o.GitHub == "" {
			return usagef("env add %s: --github-scope environment requires --github NAME", env)
		}
	case github.ScopeRepository:
		if o.GitHub != "" {
			return usagef("env add %s: --github NAME does not apply to --github-scope repository; repository scope has no environment", env)
		}
	default:
		return usagef("env add %s: --github-scope: scope %q must be %s or %s", env, o.GitHubScope, github.ScopeEnvironment, github.ScopeRepository)
	}
	if o.GitHub != "" || o.GitHubScope == github.ScopeRepository {
		// Rebuild the block for the chosen scope so switching scopes never
		// leaves a field the other scope rejects.
		cfg := roster.DestConfig{}
		for k, v := range dests["github"] {
			cfg[k] = v
		}
		if o.GitHubScope == github.ScopeRepository {
			delete(cfg, "environment")
			cfg["scope"] = github.ScopeRepository
		} else {
			delete(cfg, "scope")
			cfg["environment"] = o.GitHub
		}
		parsed, err := github.ParseConfig(a.root(), env, map[string]any(cfg))
		if err != nil {
			return usagef("env add %s: cannot pin the GitHub repository: %v (add a git remote named origin, or set sync.%s.github.repository: owner/repo in %s by hand)", env, err, env, roster.FileName)
		}
		cfg["repository"] = parsed.Repository
		if others := a.githubRepoShared(env, cfg); len(others) > 0 {
			return usagef("env add %s: %s already syncs to %s at scope: repository; repository secrets are shared, so only one environment can use them (use --github NAME for a GitHub Environment instead)", env, joinComma(others), parsed.Repository)
		}
		dests["github"] = cfg
	}
	if o.VercelProject != "" && o.Vercel == "" && dests["vercel"] == nil {
		return usagef("env add %s: --vercel-project requires --vercel (or an existing vercel destination)", env)
	}
	if o.Vercel != "" || o.VercelProject != "" {
		merge("vercel", map[string]string{"environment": o.Vercel, "project": o.VercelProject})
		cfg, err := vercel.ParseConfig(a.root(), map[string]any(dests["vercel"]))
		if err != nil {
			return usagef("env add %s: cannot pin the Vercel project: %v (pass --vercel-project NAME, or run `vercel link` first)", env, err)
		}
		merge("vercel", map[string]string{"project": cfg.Project, "team": cfg.Team})
	}
	if o.Convex != "" {
		merge("convex", map[string]string{"deployment": o.Convex})
	}
	// Create the file only once every flag checked out, so a refused add
	// leaves nothing behind.
	path := envfile.Path(a.root(), env)
	if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return exitErr(ExitDrift, fmt.Errorf("stat %s: %w", path, err))
		}
		if !a.Opts.DryRun {
			if err := envfile.New().Save(path); err != nil {
				return exitErr(ExitDrift, err)
			}
		}
	}
	if len(dests) > 0 {
		a.Roster.Sync[env] = dests
	}
	if err := a.saveRoster(); err != nil {
		return err
	}
	// The template's header names the override file, so refresh it even when
	// only sync config changed.
	f, err := a.loadLenient(env)
	if err != nil {
		return err
	}
	return a.refreshExample(env, f)
}

// githubRepoShared returns the other environments (sorted) whose github
// destination writes repository-scope secrets to the same repository as
// raw. Repository scope has no per-environment namespace, so any such pair
// overwrites each other's values on every sync.
func (a *App) githubRepoShared(env string, raw map[string]any) []string {
	mine, err := github.ParseConfig(a.root(), env, raw)
	if err != nil || mine.Scope != github.ScopeRepository {
		return nil
	}
	var others []string
	for other, dests := range a.Roster.Sync {
		theirRaw, ok := dests[github.Name]
		if other == env || !ok {
			continue
		}
		theirs, err := github.ParseConfig(a.root(), other, map[string]any(theirRaw))
		if err == nil && theirs.Scope == github.ScopeRepository && strings.EqualFold(theirs.Repository, mine.Repository) {
			others = append(others, other)
		}
	}
	sort.Strings(others)
	return others
}

// githubSharedErr is the problem githubRepoShared reports, for check and sync.
func (a *App) githubSharedErr(env string) error {
	raw := map[string]any(a.Roster.Sync[env][github.Name])
	others := a.githubRepoShared(env, raw)
	if len(others) == 0 {
		return nil
	}
	cfg, _ := github.ParseConfig(a.root(), env, raw)
	return fmt.Errorf("github: %s also syncs to %s at scope: repository; each sync would overwrite the other's values (give all but one a GitHub Environment instead)", joinComma(others), cfg.Repository)
}

// EnvList returns environment names (sorted).
func (a *App) EnvList() ([]string, error) {
	envs, err := envfile.List(a.root())
	if err != nil {
		return nil, exitErr(ExitDrift, err)
	}
	return envs, nil
}

// EnvRemove deletes .envc/environments/<env>.yaml, .envc/state/<env>/,
// .env.<env>.example, and sync.<env>. Refuses if the file has secrets unless force.
func (a *App) EnvRemove(env string, force bool) error {
	if err := baseGuard(env); err != nil {
		return err
	}
	f, err := a.loadLenient(env)
	if err != nil {
		return err
	}
	if n := len(f.SecretKeys()); n > 0 && !force {
		return usagef("env rm %s: %s has %d secret value(s); pass --force to delete it", env, relPath(envfile.Path("", env)), n)
	}
	delete(a.Roster.Sync, env)
	if err := a.saveRoster(); err != nil {
		return err
	}
	if a.Opts.DryRun {
		a.stage(env, nil)
		return a.resealBase()
	}
	p := envfile.Path(a.root(), env)
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return exitErr(ExitDrift, fmt.Errorf("remove %s: %w", p, err))
	}
	if err := state.Remove(a.root(), env); err != nil {
		return exitErr(ExitDrift, err)
	}
	if err := removeExample(a.root(), env); err != nil {
		return err
	}
	// The environment's principals leave the derived base access.
	a.stage(env, nil)
	return a.resealBase()
}
