package app

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/resolve"
	"github.com/montanaflynn/envc/internal/sshkey"
	"github.com/montanaflynn/envc/internal/state"
)

// envPath is the display name of an environment file
// (".envc/environments/<env>.yaml") or of the base layer (".envc/base.yaml").
func envPath(env string) string {
	if isBase(env) {
		return envfile.BaseFile
	}
	return relPath(envfile.Path("", env))
}

// envelopePath is the display name of an envelope (".envc/state/<env>/envelope.yaml").
func envelopePath(env string) string { return relPath(state.EnvelopePath("", env)) }

// syncPath is the display name of a sync record (".envc/state/<env>/sync.yaml").
func syncPath(env string) string { return relPath(state.SyncPath("", env)) }

// recipients resolves file.Access to age recipients, de-duplicated and sorted
// by ID. An access name that is neither a principal nor a group is ExitUsage.
// For the base layer the access is derived: every inheriting environment's
// principals (see baseAccess).
func (a *App) recipients(env string, f *envfile.File) ([]crypto.Recipient, error) {
	var principals []string
	var err error
	if isBase(env) {
		principals, err = a.baseAccess()
	} else {
		principals, err = a.Roster.Expand(f.Access)
		if err != nil {
			err = usagef("%s: %v", envPath(env), err)
		}
	}
	if err != nil {
		return nil, err
	}
	refs, err := a.Roster.KeysFor(principals)
	if err != nil {
		return nil, usagef("%s: %v", envPath(env), err)
	}
	seen := map[string]bool{}
	var rs []crypto.Recipient
	for _, ref := range refs {
		var r crypto.Recipient
		if ref.SSH != "" {
			pk, err := sshkey.Parse(ref.SSH)
			if err != nil {
				return nil, usagef(".envc.yaml: principals.%s: %v", ref.Principal, err)
			}
			r, err = crypto.RecipientFromSSH(pk)
			if err != nil {
				return nil, usagef(".envc.yaml: principals.%s: %v", ref.Principal, err)
			}
		} else {
			r, err = crypto.RecipientFromAge(ref.Age)
			if err != nil {
				return nil, usagef(".envc.yaml: principals.%s.age: %v", ref.Principal, err)
			}
		}
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	return rs, nil
}

func recipientIDs(rs []crypto.Recipient) []string {
	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = r.ID
	}
	return ids
}

// sameIDs reports whether two ID lists hold the same set.
func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := sortedStrings(a), sortedStrings(b)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// identityOptions builds crypto.IdentityOptions from Opts. interactive=false
// forbids prompting and silences discovery notices (used by check).
func (a *App) identityOptions(interactive bool) crypto.IdentityOptions {
	o := crypto.IdentityOptions{
		Getenv: a.getenv,
		Home:   a.getenv("HOME"),
		Stdin:  a.Opts.Stdin,
		Stderr: a.stderr(),
		IsTTY:  a.Opts.IsTTY && interactive,
		Prompt: a.promptOnce,
	}
	if !interactive {
		o.Stderr = io.Discard
	}
	return o
}

// promptOnce is the passphrase prompt handed to crypto. crypto builds fresh
// identities for every envelope it opens, so without this memo a command
// touching several environments would ask for the same passphrase once per
// environment. The prompt text embeds the key source, so it is the cache key.
func (a *App) promptOnce(text string) (string, error) {
	if s, ok := a.passphrases[text]; ok {
		return s, nil
	}
	var (
		s   string
		err error
	)
	if a.Opts.Prompt != nil {
		s, err = a.Opts.Prompt(text)
	} else {
		s, err = crypto.TTYPrompt(text)
	}
	if err != nil {
		return "", err
	}
	if a.passphrases == nil {
		a.passphrases = map[string]string{}
	}
	a.passphrases[text] = s
	return s, nil
}

// DataKey unwraps (and caches) the data key for env. Returns an ExitError
// with ExitDecrypt wrapping crypto.ErrNoIdentity when no key works.
func (a *App) DataKey(env string) (crypto.DataKey, error) {
	if k, ok := a.keys[env]; ok {
		return k, nil
	}
	f, err := a.Load(env)
	if err != nil {
		return crypto.DataKey{}, err
	}
	return a.dataKeyFor(env, f, true)
}

// dataKeyFor unwraps the envelope of f. With interactive=false no passphrase
// prompt happens and ErrNoIdentity is returned unwrapped so callers can
// distinguish "no key here" from "cannot open".
func (a *App) dataKeyFor(env string, f *envfile.File, interactive bool) (crypto.DataKey, error) {
	if k, ok := a.keys[env]; ok {
		return k, nil
	}
	if f.Crypto == nil {
		return crypto.DataKey{}, decryptf("%s: no envelope (no secrets have been encrypted yet)", envPath(env))
	}
	wrapped, err := base64.StdEncoding.DecodeString(f.Crypto.Key)
	if err != nil {
		return crypto.DataKey{}, decryptf("%s: key is not base64: %v", envelopePath(env), err)
	}
	// Discovery notices ("skipping ~/.ssh/id_rsa: passphrase-protected and no
	// TTY") are only interesting if nothing else opens the file, so buffer
	// them and flush on failure.
	var notices bytes.Buffer
	iopts := a.identityOptions(interactive)
	if interactive {
		iopts.Stderr = &notices
	}
	flush := func() { io.Copy(a.stderr(), &notices) } //nolint:errcheck
	ids, err := crypto.FindIdentities(iopts, f.Crypto.Recipients)
	if err != nil {
		flush()
		if errors.Is(err, crypto.ErrNoIdentity) {
			if !interactive {
				return crypto.DataKey{}, err
			}
			return crypto.DataKey{}, &ExitError{Code: ExitDecrypt, Err: fmt.Errorf(
				"cannot decrypt %s: %w (recipients: %s; searched ENVC_PRIVATE_KEY, ENVC_PRIVATE_KEY_FILE, ~/.ssh/id_ed25519, ~/.ssh/id_rsa)",
				envPath(env), err, joinComma(f.Crypto.Recipients))}
		}
		return crypto.DataKey{}, decryptf("cannot decrypt %s: %v", envPath(env), err)
	}
	k, err := crypto.Unwrap(wrapped, ids)
	if err != nil {
		flush()
		if !interactive && errors.Is(err, crypto.ErrNoIdentity) {
			return crypto.DataKey{}, err
		}
		return crypto.DataKey{}, &ExitError{Code: ExitDecrypt, Err: fmt.Errorf(
			"cannot decrypt %s: %w (tried: %s)", envPath(env), err, joinComma(identitySources(ids)))}
	}
	a.keys[env] = k
	return k, nil
}

// tryDataKey obtains the data key without prompting. ok=false means no usable
// key is present (not an error); err is set for a real failure such as a
// tampered envelope.
func (a *App) tryDataKey(env string, f *envfile.File) (k crypto.DataKey, ok bool, err error) {
	k, err = a.dataKeyFor(env, f, false)
	if err != nil {
		if errors.Is(err, crypto.ErrNoIdentity) {
			return crypto.DataKey{}, false, nil
		}
		return crypto.DataKey{}, false, err
	}
	return k, true, nil
}

func identitySources(ids []crypto.Identity) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.Source
	}
	return out
}

// decryptTokens decrypts every secret whose value is a token, using k. It
// returns the plaintexts keyed by config key.
func decryptTokens(env string, f *envfile.File, k crypto.DataKey) (map[string]string, error) {
	out := map[string]string{}
	for _, key := range f.SecretKeys() {
		v := f.Config[key].Value
		if !crypto.IsToken(v) {
			continue
		}
		plain, err := k.Decrypt(key, v)
		if err != nil {
			return nil, decryptf("%s: %v", envPath(env), err)
		}
		out[key] = plain
	}
	return out, nil
}

// verifyMAC compares k.MAC(secrets) with f.Crypto.MAC.
func verifyMAC(env string, f *envfile.File, k crypto.DataKey, secrets map[string]string) error {
	want := k.MAC(secrets)
	if f.Crypto == nil || !hmac.Equal([]byte(want), []byte(f.Crypto.MAC)) {
		return &ExitError{Code: ExitDecrypt, Err: fmt.Errorf("%s: %w; run `envc ensure %s` to repair a hand-edited file", envPath(env), crypto.ErrBadMAC, env)}
	}
	return nil
}

// secrets decrypts every secret in f and verifies the MAC. Plaintext secret
// values are refused (the user must run ensure). A file without secrets
// yields an empty map and needs no key.
func (a *App) secrets(env string, f *envfile.File) (map[string]string, crypto.DataKey, error) {
	if len(f.SecretKeys()) == 0 {
		return map[string]string{}, crypto.DataKey{}, nil
	}
	if plain := f.PlaintextSecretKeys(); len(plain) > 0 {
		return nil, crypto.DataKey{}, usagef("%s: secret value(s) %s are plaintext; run `envc ensure %s`", envPath(env), joinComma(plain), env)
	}
	k, err := a.dataKeyFor(env, f, true)
	if err != nil {
		return nil, crypto.DataKey{}, err
	}
	vals, err := decryptTokens(env, f, k)
	if err != nil {
		return nil, crypto.DataKey{}, err
	}
	if err := verifyMAC(env, f, k, vals); err != nil {
		return nil, crypto.DataKey{}, err
	}
	return vals, k, nil
}

// seal writes secrets into f under k: plaintext secret values (or all of
// them when encryptAll) get a fresh token, the MAC is recomputed over the
// complete secrets map, and the data key is wrapped to rs. With
// freshWrap=false, when k is the key already in the envelope and rs matches
// the envelope's recipients, its key is left untouched so unrelated edits
// (set, allow) do not churn it. freshWrap=true always wraps anew: a new data
// key, or an explicit rewrap, must not trust a recipients list that may have
// been hand-edited to match access while the key still opens for a removed
// reader.
func (a *App) seal(env string, f *envfile.File, k crypto.DataKey, secrets map[string]string, rs []crypto.Recipient, encryptAll, freshWrap bool) error {
	for key, plain := range secrets {
		e := f.Config[key]
		if encryptAll || !crypto.IsToken(e.Value) {
			tok, err := k.Encrypt(key, plain)
			if err != nil {
				return exitErr(ExitDrift, fmt.Errorf("%s: %w", envPath(env), err))
			}
			e.Value = tok
			f.Config[key] = e
		}
	}
	if len(rs) == 0 {
		return noAccessHint(env)
	}
	ids := recipientIDs(rs)
	key := ""
	if !freshWrap && f.Crypto != nil && f.Crypto.Key != "" && sameIDs(f.Crypto.Recipients, ids) {
		key = f.Crypto.Key
	} else {
		wrapped, err := crypto.Wrap(k, rs)
		if err != nil {
			return exitErr(ExitDrift, fmt.Errorf("%s: %w", envPath(env), err))
		}
		key = base64.StdEncoding.EncodeToString(wrapped)
	}
	f.Crypto = &state.Envelope{
		Version:    crypto.Version,
		Recipients: ids,
		Key:        key,
		MAC:        k.MAC(secrets),
	}
	a.keys[env] = k
	return nil
}

// currentSecrets returns f's secret values: encrypted ones decrypted under
// the envelope's data key (MAC-verified when no plaintext is pending) plus
// any plaintext ones as written. A file without an envelope gets a fresh
// data key.
func (a *App) currentSecrets(env string, f *envfile.File) (secrets map[string]string, k crypto.DataKey, plain []string, err error) {
	plain = f.PlaintextSecretKeys()
	if f.Crypto != nil {
		k, err = a.dataKeyFor(env, f, true)
		if err != nil {
			return nil, k, nil, err
		}
	} else if k, err = crypto.NewDataKey(); err != nil {
		return nil, k, nil, exitErr(ExitDrift, err)
	}
	secrets, err = decryptTokens(env, f, k)
	if err != nil {
		return nil, k, nil, err
	}
	// With plaintext secrets present the MAC cannot cover the current set
	// (README: hand-edit as plaintext, then ensure), so it is not verified;
	// the plaintext values are encrypted and the MAC recomputed by seal.
	if f.Crypto != nil && len(plain) == 0 {
		if err := verifyMAC(env, f, k, secrets); err != nil {
			return nil, k, nil, err
		}
	}
	for _, key := range plain {
		secrets[key] = f.Config[key].Value
	}
	return secrets, k, plain, nil
}

// rewrapFile makes f's envelope match its resolved access under the current
// data key, encrypting any plaintext secrets, and saves it. A file with no
// secrets loses its envelope. Effects are recorded only for what changed.
func (a *App) rewrapFile(env string, f *envfile.File) error {
	rs, err := a.recipients(env, f)
	if err != nil {
		return err
	}
	if len(f.SecretKeys()) == 0 {
		had := f.Crypto != nil
		f.Crypto = nil
		delete(a.keys, env)
		if err := a.saveFile(env, f); err != nil {
			return err
		}
		if had {
			a.effect("remove " + env + " envelope")
		}
		return nil
	}
	if len(rs) == 0 {
		return noAccessHint(env)
	}
	old := envelopeRecipients(f)
	secrets, k, plain, err := a.currentSecrets(env, f)
	if err != nil {
		return err
	}
	// Always wrap afresh: ensure must guarantee the envelope key opens for
	// exactly the resolved access list.
	if err := a.seal(env, f, k, secrets, rs, false, true); err != nil {
		return err
	}
	if err := a.saveFile(env, f); err != nil {
		return err
	}
	if len(plain) > 0 {
		a.effect(encryptEffect(plain))
	}
	if e := a.readersEffect(env, f, old, recipientIDs(rs)); e != "" {
		a.effect(e)
	}
	return nil
}

// reencryptFile re-keys f: a new data key, every secret re-encrypted, the
// envelope wrapped to the resolved access. Plaintext secrets are encrypted
// on the way. Saves and records the effect.
func (a *App) reencryptFile(env string, f *envfile.File) error {
	if len(f.SecretKeys()) == 0 || f.Crypto == nil {
		// Nothing encrypted under an old key: rewrap creates or clears the envelope.
		return a.rewrapFile(env, f)
	}
	rs, err := a.recipients(env, f)
	if err != nil {
		return err
	}
	if len(rs) == 0 {
		return noAccessHint(env)
	}
	oldIDs := envelopeRecipients(f)
	secrets, old, plain, err := a.currentSecrets(env, f)
	if err != nil {
		return err
	}
	// The sync record covers the resolved values (base included), so carry
	// them across the key change before the file is re-sealed.
	var vars resolve.Vars
	if !isBase(env) && len(plain) == 0 {
		v, err := a.view(env, f)
		if err != nil {
			return err
		}
		if vars, err = a.viewVars(env, f, v); err != nil {
			return err
		}
	}
	k, err := crypto.NewDataKey()
	if err != nil {
		return exitErr(ExitDrift, err)
	}
	if err := a.seal(env, f, k, secrets, rs, true, true); err != nil {
		return err
	}
	if err := a.saveFile(env, f); err != nil {
		return err
	}
	if len(plain) > 0 {
		a.effect(encryptEffect(plain))
	}
	a.effect(a.rekeyEffect(env, oldIDs, recipientIDs(rs)))
	return a.rekeySyncState(env, vars, old, k)
}

// envelopeRecipients returns f's current recipient IDs, or nil without an envelope.
func envelopeRecipients(f *envfile.File) []string {
	if f.Crypto == nil {
		return nil
	}
	return f.Crypto.Recipients
}

// rekeySyncState carries the sync record across a data-key change: every
// stored HMAC that still matches the current value under the old key is
// rewritten under the new key, so a re-key with no value changes leaves
// diff clean. Entries that no longer match are dropped (they were unsynced
// anyway). A record made under some other key is left alone; diff reports it
// as stale.
func (a *App) rekeySyncState(env string, vars resolve.Vars, old, k crypto.DataKey) error {
	if isBase(env) {
		return nil // base has no sync record; environments' records use their own keys
	}
	rec, err := state.LoadSync(a.root(), env)
	if err != nil {
		return exitErr(ExitDrift, err)
	}
	if len(rec) == 0 {
		return nil
	}
	changed := false
	for name, d := range rec {
		if d.KeyID != old.ID() {
			continue
		}
		keys := make(map[string]string, len(d.Keys))
		for key, h := range d.Keys {
			if v, ok := vars[key]; ok && h == old.SyncHMAC(key, v) {
				keys[key] = k.SyncHMAC(key, v)
			}
		}
		d.KeyID, d.Keys = k.ID(), keys
		rec[name] = d
		changed = true
	}
	if !changed || a.Opts.DryRun {
		return nil
	}
	if err := rec.Save(a.root(), env); err != nil {
		return exitErr(ExitDrift, err)
	}
	return nil
}

// reseal rewraps or re-keys each env, in order, then brings base in line
// with the (possibly changed) derived access.
func (a *App) reseal(envs []string, reencrypt bool) error {
	for _, env := range envs {
		f, err := a.Load(env)
		if err != nil {
			return err
		}
		a.stage(env, f)
		if reencrypt {
			err = a.reencryptFile(env, f)
		} else {
			err = a.rewrapFile(env, f)
		}
		if err != nil {
			return err
		}
	}
	return a.resealBase()
}
