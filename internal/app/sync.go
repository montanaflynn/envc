package app

import (
	"context"
	"fmt"
	"sort"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/resolve"
	"github.com/montanaflynn/envc/internal/state"
)

// destNames returns the destination names configured for env (sorted), or
// only the one named. Both "nothing configured" and "not configured" are usage errors.
func (a *App) destNames(env, only string) ([]string, error) {
	dests := a.Roster.Sync[env]
	if len(dests) == 0 {
		return nil, usagef("no destinations configured for %s; see `envc env add %s --dotenv|--github|--vercel|--convex`", env, env)
	}
	names := make([]string, 0, len(dests))
	for n := range dests {
		names = append(names, n)
	}
	sort.Strings(names)
	if only == "" {
		return names, nil
	}
	if !contains(names, only) {
		return nil, usagef("destination %q is not configured for %s (configured: %s)", only, env, joinComma(names))
	}
	return []string{only}, nil
}

// newDestination builds one destination from the roster config.
func (a *App) newDestination(env, name string) (destination.Destination, error) {
	raw := map[string]any(a.Roster.Sync[env][name])
	if raw == nil {
		raw = map[string]any{}
	}
	return destination.New(name, destination.Env{
		Root:   a.root(),
		Env:    env,
		Getenv: a.getenv,
		Log:    a.stderr(),
	}, raw)
}

// readsBackSecrets reports whether d returns secret values from Live.
func readsBackSecrets(d destination.Destination) bool {
	sr, ok := d.(destination.SecretReader)
	return ok && sr.ReadsBackSecrets()
}

// syncKey is the key that signs sync records for f. A file with no secrets
// has no data key; its records are keyed by the all-zero DataKey and carry an
// empty key_id. Public-only environments have nothing to protect, and the
// zero key keeps the HMACs deterministic across machines.
func (a *App) syncKey(env string, f *envfile.File) (crypto.DataKey, string, error) {
	if len(f.SecretKeys()) == 0 {
		return crypto.DataKey{}, "", nil
	}
	k, err := a.dataKeyFor(env, f, true)
	if err != nil {
		return crypto.DataKey{}, "", err
	}
	return k, k.ID(), nil
}

// Sync decrypts, resolves, applies each destination (or only one), and
// records what was pushed in .envc/state/<env>/sync.yaml for destinations
// that cannot read secrets back.
func (a *App) Sync(ctx context.Context, env, only string, prune bool) ([]SyncResult, error) {
	ctx = ctxOrBackground(ctx)
	if err := baseGuard(env); err != nil {
		return nil, err
	}
	names, err := a.destNames(env, only)
	if err != nil {
		return nil, err
	}
	f, err := a.Load(env)
	if err != nil {
		return nil, err
	}
	v, err := a.view(env, f)
	if err != nil {
		return nil, err
	}
	vars, err := a.viewVars(env, f, v)
	if err != nil {
		return nil, err
	}
	rk, keyID, err := a.syncKey(env, f)
	if err != nil {
		return nil, err
	}
	want := wantSnapshot(v, vars)
	opts := destination.ApplyOptions{Prune: prune, DryRun: a.Opts.DryRun}

	results := make([]SyncResult, 0, len(names))
	for _, name := range names {
		res := SyncResult{Destination: name}
		d, err := a.newDestination(env, name)
		if err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}
		res.Report, res.Err = d.Apply(ctx, want, opts)
		if res.Err == nil && !a.Opts.DryRun && !readsBackSecrets(d) {
			res.Err = a.writeSyncState(env, name, rk, keyID, vars)
		}
		results = append(results, res)
	}
	for _, res := range results {
		if res.Err == nil {
			if err := a.refreshExample(env, f); err != nil {
				return results, err
			}
			break
		}
	}
	return results, nil
}

// writeSyncState records the synced values for one destination.
func (a *App) writeSyncState(env, name string, k crypto.DataKey, keyID string, vars resolve.Vars) error {
	rec, err := state.LoadSync(a.root(), env)
	if err != nil {
		return fmt.Errorf("sync record: %w", err)
	}
	keys := make(map[string]string, len(vars))
	for key, v := range vars {
		keys[key] = k.SyncHMAC(key, v)
	}
	rec[name] = state.Destination{At: a.now().UTC(), KeyID: keyID, Keys: keys}
	if err := rec.Save(a.root(), env); err != nil {
		return fmt.Errorf("sync record: %w", err)
	}
	return nil
}
