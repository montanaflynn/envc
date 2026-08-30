package app

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/resolve"
)

// valueProblem is one enum/pattern violation.
type valueProblem struct {
	Key  string
	Path string // "config.KEY.enum" or "config.KEY.pattern"
	Msg  string
}

// checkValue validates plain against e's enum and pattern.
func checkValue(key string, e envfile.Entry, plain string) []valueProblem {
	var probs []valueProblem
	if len(e.Enum) > 0 && !contains(e.Enum, plain) {
		shown := plain
		if e.IsSecret() {
			shown = "<redacted>"
		}
		probs = append(probs, valueProblem{key, "config." + key + ".enum",
			fmt.Sprintf("value %q is not one of %s", shown, joinComma(e.Enum))})
	}
	if e.Pattern != "" {
		_, err := regexp.Compile(e.Pattern)
		if err != nil {
			probs = append(probs, valueProblem{key, "config." + key + ".pattern", fmt.Sprintf("invalid regexp: %v", err)})
		} else if !regexp.MustCompile("^(?:" + e.Pattern + ")$").MatchString(plain) {
			probs = append(probs, valueProblem{key, "config." + key + ".pattern",
				fmt.Sprintf("value does not match pattern %s", e.Pattern)})
		}
	}
	return probs
}

// checkValues validates every key in vars against its entry, sorted by key.
func checkValues(f *envfile.File, vars map[string]string) []valueProblem {
	var probs []valueProblem
	for _, key := range f.Keys() {
		v, ok := vars[key]
		if !ok {
			continue
		}
		probs = append(probs, checkValue(key, f.Config[key], v)...)
	}
	return probs
}

func valueProblemsError(env string, probs []valueProblem) error {
	msgs := make([]string, len(probs))
	for i, p := range probs {
		msgs[i] = p.Path + ": " + p.Msg
	}
	return usagef("%s: %s", envPath(env), joinSemi(msgs))
}

// decryptFile returns every value of f in the clear, MAC verified, and
// enum/pattern checked.
func (a *App) decryptFile(env string, f *envfile.File) (resolve.Vars, error) {
	secrets, _, err := a.secrets(env, f)
	if err != nil {
		return nil, err
	}
	vars := make(resolve.Vars, len(f.Config))
	for key, e := range f.Config {
		if e.IsSecret() {
			vars[key] = secrets[key]
		} else {
			vars[key] = e.Value
		}
	}
	if probs := checkValues(f, vars); len(probs) > 0 {
		return nil, valueProblemsError(env, probs)
	}
	return vars, nil
}

// Decrypt returns every value in the clear, MAC verified. Enum/pattern are
// checked and returned as an error with ExitUsage if violated.
func (a *App) Decrypt(env string) (resolve.Vars, error) {
	f, err := a.Load(env)
	if err != nil {
		return nil, err
	}
	return a.decryptFile(env, f)
}

// Get returns one decrypted value (MAC verified). Only the requested key's
// enum/pattern is checked: an unrelated key's violation must not hide this
// one's value (Decrypt and Resolve still validate the whole file). A key the
// environment does not define itself is read from base when it inherits it.
func (a *App) Get(env, key string) (string, error) {
	f, err := a.Load(env)
	if err != nil {
		return "", err
	}
	e, ok := f.Config[key]
	if !ok {
		if !isBase(env) && f.InheritsBase() && a.BaseHas(key) {
			return a.Get(BaseName, key)
		}
		return "", usagef("%s: no key %s", envPath(env), key)
	}
	value := e.Value
	if e.IsSecret() {
		secrets, _, err := a.secrets(env, f)
		if err != nil {
			return "", err
		}
		value = secrets[key]
	}
	if probs := checkValue(key, e, value); len(probs) > 0 {
		return "", valueProblemsError(env, probs)
	}
	return value, nil
}

// Set creates or updates one entry. Secrets are encrypted immediately; the
// envelope is created if the file had none yet.
func (a *App) Set(env, key string, o SetOptions) error {
	if !envfile.KeyPattern.MatchString(key) {
		return usagef("invalid key name %q (must match %s)", key, envfile.KeyPattern)
	}
	f, err := a.Load(env)
	if err != nil {
		return err
	}
	e, exists := f.Config[key]
	if !exists {
		if o.Secret == nil {
			return usagef("%s: new key %s: pass --secret or --public", envPath(env), key)
		}
		if !o.HasValue {
			return usagef("%s: new key %s: a value is required", envPath(env), key)
		}
	}
	wasSecret := exists && e.IsSecret()
	newSecret := wasSecret
	if o.Secret != nil {
		newSecret = *o.Secret
	}
	flip := exists && wasSecret != newSecret

	// Metadata.
	if o.Description != nil {
		e.Description = *o.Description
	}
	metaChanged := false
	if o.Enum != nil {
		e.Enum = o.Enum
		if len(e.Enum) == 0 {
			e.Enum = nil
		}
		metaChanged = true
	}
	if o.Pattern != nil {
		e.Pattern = *o.Pattern
		metaChanged = true
	}
	secret := newSecret
	e.Secret = &secret

	// Fast path: metadata-only patch with no flip and nothing to validate
	// against — no key needed.
	if !o.HasValue && !flip && !metaChanged {
		f.Config[key] = e
		return a.saveFile(env, f)
	}

	// Everything else needs the plaintext of this key.
	var plain string
	switch {
	case o.HasValue:
		plain = o.Value
	case wasSecret && crypto.IsToken(e.Value):
		k, err := a.dataKeyFor(env, f, true)
		if err != nil {
			return err
		}
		plain, err = k.Decrypt(key, e.Value)
		if err != nil {
			return decryptf("%s: %v", envPath(env), err)
		}
	default:
		plain = e.Value
	}
	if probs := checkValue(key, e, plain); len(probs) > 0 {
		return valueProblemsError(env, probs)
	}

	// Public values that were public need no key.
	if !newSecret && !wasSecret {
		e.Value = plain
		f.Config[key] = e
		return a.saveFile(env, f)
	}

	// The secret set changes (or a secret is re-encrypted): decrypt every
	// secret, verify the MAC over the file as it is, then re-seal.
	secrets, k, err := a.secrets(env, f)
	if err != nil {
		return err
	}
	delete(secrets, key)
	rs, err := a.recipients(env, f)
	if err != nil {
		return err
	}
	if newSecret {
		if len(rs) == 0 {
			return noAccessHint(env)
		}
		newKey := f.Crypto == nil
		if newKey {
			k, err = crypto.NewDataKey()
		} else {
			k, err = a.dataKeyFor(env, f, true)
		}
		if err != nil {
			return exitErr(ExitDrift, err)
		}
		secrets[key] = plain
		// A metadata-only patch on an existing secret keeps its token so the
		// ciphertext does not churn in the git diff. Otherwise encrypt here
		// rather than via seal's "not yet a token" rule, so a value that
		// happens to look like ENC[envc1,…] is still encrypted.
		if o.HasValue || !wasSecret {
			if e.Value, err = k.Encrypt(key, plain); err != nil {
				return exitErr(ExitDrift, fmt.Errorf("%s: %w", envPath(env), err))
			}
		}
		f.Config[key] = e
		if err := a.seal(env, f, k, secrets, rs, false, newKey); err != nil {
			return err
		}
		return a.saveFile(env, f)
	}

	// secret → public flip.
	e.Value = plain
	f.Config[key] = e
	if len(secrets) == 0 {
		f.Crypto = nil
		delete(a.keys, env)
	} else {
		f.Crypto.MAC = k.MAC(secrets)
	}
	return a.saveFile(env, f)
}

// Unset deletes an entry (recomputing the MAC when it was a secret). A key
// the environment only inherits cannot be unset there.
func (a *App) Unset(env, key string) error {
	f, err := a.Load(env)
	if err != nil {
		return err
	}
	e, ok := f.Config[key]
	if !ok {
		if !isBase(env) && f.InheritsBase() && a.BaseHas(key) {
			return usagef("%s: %s", envPath(env), baseHint(key))
		}
		return usagef("%s: no key %s", envPath(env), key)
	}
	if !e.IsSecret() {
		delete(f.Config, key)
		return a.saveFile(env, f)
	}
	secrets, k, err := a.secrets(env, f)
	if err != nil {
		return err
	}
	delete(secrets, key)
	delete(f.Config, key)
	if len(secrets) == 0 {
		f.Crypto = nil
		delete(a.keys, env)
	} else {
		f.Crypto.MAC = k.MAC(secrets)
	}
	return a.saveFile(env, f)
}

// sortedVars renders vars as sorted KEY=value strings (raw values).
func sortedVars(vars resolve.Vars) []string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k + "=" + vars[k]
	}
	return out
}
