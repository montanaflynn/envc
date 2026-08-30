package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/resolve"
	"github.com/montanaflynn/envc/internal/roster"
	"github.com/montanaflynn/envc/internal/state"
)

// checkRoster validates .envc.yaml: schema, groups, and the sync config of
// every environment it names. Read-only.
func (a *App) checkRoster(envs []string) []Problem {
	probs := []Problem{}
	addR := func(path, format string, args ...any) {
		probs = append(probs, Problem{File: roster.FileName, Path: path, Msg: fmt.Sprintf(format, args...)})
	}
	for _, p := range a.Roster.Validate() {
		addR(p.Path, "%s", p.Msg)
	}
	for _, syncEnv := range a.Roster.EnvironmentsWith("") {
		if !contains(envs, syncEnv) {
			addR("sync."+syncEnv, "no %s for this environment", envPath(syncEnv))
		}
		names := make([]string, 0, len(a.Roster.Sync[syncEnv]))
		for n := range a.Roster.Sync[syncEnv] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			path := "sync." + syncEnv + "." + name
			if !destination.Registered(name) {
				addR(path, "unknown destination %q (registered: %s)", name, joinComma(destination.Names()))
				continue
			}
			if _, err := a.newDestination(syncEnv, name); err != nil {
				addR(path, "%v", err)
			}
		}
	}
	return probs
}

// inspectEnv validates one target read-only: the manifest, its envelope,
// and (with a key) the values and the sync record. It returns the loaded
// file (nil when it could not be loaded), the problems it cannot fix, and
// whether ensure may write fixes: only when the file loaded and nothing
// non-warning is wrong with it. Conditions ensure fixes — plaintext secrets,
// a missing or mismatched envelope — are not reported here.
func (a *App) inspectEnv(env string) (*envfile.File, []Problem, bool) {
	file := envPath(env)
	delete(a.macBroken, env)
	var probs []Problem
	add := func(path, format string, args ...any) {
		probs = append(probs, Problem{File: file, Path: path, Msg: fmt.Sprintf(format, args...)})
	}
	fixable := func(f *envfile.File) (*envfile.File, []Problem, bool) {
		for _, p := range probs {
			if !p.Warn {
				return f, probs, false
			}
		}
		return f, probs, f != nil
	}
	addE := func(path, format string, args ...any) {
		probs = append(probs, Problem{File: envelopePath(env), Path: path, Msg: fmt.Sprintf(format, args...)})
	}
	warn := func(path, format string, args ...any) {
		probs = append(probs, Problem{File: file, Path: path, Msg: fmt.Sprintf(format, args...), Warn: true})
	}

	var f *envfile.File
	var err error
	if isBase(env) {
		f, err = envfile.LoadBase(envfile.BasePath(a.root()))
	} else {
		f, err = envfile.Load(envfile.Path(a.root(), env))
	}
	if err != nil {
		add("", "%v", err)
		return fixable(nil)
	}
	f.Crypto, err = state.LoadEnvelope(a.root(), env)
	if err != nil {
		addE("", "%v", err)
		return fixable(nil)
	}
	if f.Crypto == nil && len(f.EncryptedKeys()) > 0 {
		addE("", "%s", missingEnvelope(env))
		return fixable(nil)
	}
	for _, p := range f.Validate() {
		if strings.HasSuffix(p.Path, ".value") && strings.Contains(p.Msg, "plaintext") {
			continue // ensure encrypts it
		}
		add(p.Path, "%s", p.Msg)
	}
	if f.Crypto != nil {
		for _, p := range f.Crypto.Validate() {
			addE(p.Path, "%s", p.Msg)
		}
	}
	// GitHub folds variable and secret names to uppercase, so a lowercase key
	// would sync fine but never match on diff.
	if _, hasGitHub := a.Roster.Sync[env]["github"]; hasGitHub {
		for _, k := range f.Keys() {
			if k != strings.ToUpper(k) {
				warn("config."+k, "GitHub Actions uppercases variable names; use %s so diff can match it", strings.ToUpper(k))
			}
		}
	}

	// Access must resolve; whether the envelope matches it is ensure's to
	// fix, not a problem to report.
	if _, err := a.Roster.Expand(f.Access); err != nil {
		add("access", "%s", strings.TrimPrefix(err.Error(), "access: "))
	} else if _, err := a.recipients(env, f); err != nil {
		add("access", "%v", errors.Unwrap(err))
	}
	secrets := f.SecretKeys()

	// Values that need no key.
	for _, key := range f.Keys() {
		e := f.Config[key]
		if !e.IsSecret() {
			for _, vp := range checkValue(key, e, e.Value) {
				add(vp.Path, "%s", vp.Msg)
			}
			if e.IsRequired() && e.Value == "" {
				warn("config."+key+".value", "required value is empty")
			}
		}
	}

	// With a key: MAC, enum, pattern on secrets. Never prompt, never fail
	// because no key is present.
	if f.Crypto == nil || len(secrets) == 0 || len(f.PlaintextSecretKeys()) > 0 {
		return fixable(f)
	}
	k, ok, err := a.tryDataKey(env, f)
	if err != nil {
		addE("key", "%v", errors.Unwrap(err))
		return fixable(f)
	}
	if !ok {
		return fixable(f)
	}
	vals, err := decryptTokens(env, f, k)
	if err != nil {
		add("config", "%v", errors.Unwrap(err))
		return fixable(f)
	}
	if err := verifyMAC(env, f, k, vals); err != nil {
		// Every token decrypted, only the MAC disagrees: a hand edit
		// (e.g. a deleted secret). Repairable by ensure, not a problem.
		if a.macBroken == nil {
			a.macBroken = map[string]bool{}
		}
		a.macBroken[env] = true
	}
	for _, vp := range checkValues(f, vals) {
		add(vp.Path, "%s", vp.Msg)
	}
	for _, key := range secrets {
		if f.Config[key].IsRequired() && vals[key] == "" {
			warn("config."+key+".value", "required value is empty")
		}
	}
	if isBase(env) {
		return fixable(f)
	}
	v, err := a.view(env, f)
	if err != nil {
		return fixable(f)
	}
	own := make(map[string]string, len(f.Config))
	for key, e := range f.Config {
		if e.IsSecret() {
			own[key] = vals[key]
		} else {
			own[key] = e.Value
		}
	}
	probs = append(probs, a.checkSyncState(env, v, a.tryViewVars(v, own), k, k.ID())...)
	return fixable(f)
}

// checkSyncState warns, per recorded destination, about values that differ
// from what the sync record says was pushed. Only destinations that have a
// record are considered: a never-synced environment is not a warning. A
// record from another data key is reported as stale.
func (a *App) checkSyncState(env string, v *view, vars map[string]string, k crypto.DataKey, keyID string) []Problem {
	rec, err := state.LoadSync(a.root(), env)
	if err != nil {
		return []Problem{{File: syncPath(env), Msg: err.Error()}}
	}
	if len(rec) == 0 {
		return nil
	}
	var probs []Problem
	names := make([]string, 0, len(rec))
	for n := range rec {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		d := rec[name]
		if d.KeyID != keyID {
			probs = append(probs, Problem{File: syncPath(env), Path: name, Warn: true,
				Msg: fmt.Sprintf("recorded under another data key; run envc sync %s", env)})
			continue
		}
		var changed []string
		for _, key := range v.Keys() {
			val, known := vars[key]
			if !known {
				continue // inherited secret without a base key here: not checkable
			}
			if h, ok := d.Keys[key]; !ok || h != k.SyncHMAC(key, val) {
				changed = append(changed, key)
			}
		}
		if len(changed) > 0 {
			probs = append(probs, Problem{File: syncPath(env), Path: name, Warn: true,
				Msg: fmt.Sprintf("%d value(s) changed since last sync (%s); run envc sync %s", len(changed), joinComma(changed), env)})
		}
	}
	return probs
}

// checkDotenv warns when a configured .env is missing or differs from the
// resolved values. Secret values need a key; without one it stays silent and
// never prompts. Problems the manifest itself has are left to checkEnv.
func (a *App) checkDotenv(env string) []Problem {
	cfg, ok := a.Roster.Sync[env]["dotenv"]
	if !ok {
		return nil
	}
	f, err := a.loadLenient(env)
	if err != nil || len(f.PlaintextSecretKeys()) > 0 {
		return nil
	}
	own := make(map[string]string, len(f.Config))
	var vals map[string]string
	if len(f.SecretKeys()) > 0 {
		k, ok, err := a.tryDataKey(env, f)
		if err != nil || !ok {
			return nil
		}
		if vals, err = decryptTokens(env, f, k); err != nil {
			return nil
		}
	}
	for key, e := range f.Config {
		if e.IsSecret() {
			own[key] = vals[key]
		} else {
			own[key] = e.Value
		}
	}
	v, err := a.view(env, f)
	if err != nil {
		return nil
	}
	vars := a.tryViewVars(v, own)
	if len(vars) != len(v.Keys()) {
		return nil // an inherited secret this key cannot read
	}
	path := ".env"
	if p, ok := cfg["path"].(string); ok && p != "" {
		path = p
	}
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(a.root(), abs)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return []Problem{{File: relPath(path), Warn: true, Msg: fmt.Sprintf("missing; run envc sync %s", env)}}
	}
	live, err := resolve.Parse(string(data))
	if err != nil || !sameVars(live, resolve.Vars(vars)) {
		return []Problem{{File: relPath(path), Warn: true, Msg: fmt.Sprintf("stale; run envc sync %s", env)}}
	}
	return nil
}

func sameVars(x, y resolve.Vars) bool {
	if len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if w, ok := y[k]; !ok || w != v {
			return false
		}
	}
	return true
}
