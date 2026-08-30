package app

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/resolve"
	"github.com/montanaflynn/envc/internal/sshkey"
)

// BaseName is the reserved name of the base layer: entries every environment
// inherits unless its manifest says `base: false`. It is accepted where a
// manifest is read or written (set, unset, get, ls, show, ensure, who) and
// refused where an environment is meant (run, export, sync, diff, allow,
// deny, env add/rm).
const BaseName = "base"

// BaseNotEnvMsg is the usage error for `base` where an environment is required.
const BaseNotEnvMsg = "base is not an environment; it is the layer every environment inherits"

func isBase(env string) bool { return env == BaseName }

// baseExists reports whether .envc/base.yaml is on disk.
func (a *App) baseExists() bool {
	_, err := os.Stat(envfile.BasePath(a.root()))
	return err == nil
}

// baseAccess is the derived access of the base layer: the union of the
// resolved principals of every environment that inherits it, sorted. An
// environment with `base: false` contributes nothing. Access names that do
// not resolve are ExitUsage, naming the environment.
func (a *App) baseAccess() ([]string, error) {
	envs, err := a.EnvList()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, env := range envs {
		f, staged := a.overlay[env]
		if staged && f == nil {
			continue // removed by this call
		}
		if !staged {
			if f, err = envfile.Load(envfile.Path(a.root(), env)); err != nil {
				return nil, exitErr(ExitUsage, err)
			}
		}
		if !f.InheritsBase() {
			continue
		}
		ps, err := a.Roster.Expand(f.Access)
		if err != nil {
			return nil, usagef("%s: %v", envPath(env), err)
		}
		for _, p := range ps {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// noAccessHint is the "no access" usage error for a file that needs
// recipients: an environment says allow; base says allow on an environment.
func noAccessHint(env string) error {
	if isBase(env) {
		return usagef("%s: no environment grants access yet; run `envc allow ENV NAME` on an environment that inherits base", envPath(env))
	}
	return usagef("%s: no access on %s; run `envc allow %s NAME`", envPath(env), env, env)
}

// resealBase brings the base envelope in line with the derived access after
// something that can change it. No-op when base has no secrets or already
// matches. A principal that dropped out of the union gets a new data key
// (re-key); additions update the readers. Base with plaintext secrets is
// left for `envc ensure base`.
//
// The effect is reported (see App.Effects) with its consequence: who can
// newly read base secrets, or who no longer can after a re-key.
func (a *App) resealBase() error {
	if !a.baseExists() {
		return nil
	}
	f, err := a.Load(BaseName)
	if err != nil {
		return err
	}
	if len(f.SecretKeys()) == 0 {
		if f.Crypto != nil {
			return a.rewrapFile(BaseName, f)
		}
		return nil
	}
	if len(f.PlaintextSecretKeys()) > 0 {
		return nil
	}
	rs, err := a.recipients(BaseName, f)
	if err != nil {
		return err
	}
	ids := recipientIDs(rs)
	old := envelopeRecipients(f)
	if f.Crypto != nil && sameIDs(old, ids) {
		return nil
	}
	if readersRemoved(old, ids) {
		return a.reencryptFile(BaseName, f)
	}
	return a.rewrapFile(BaseName, f)
}

// readersRemoved reports whether any old recipient is missing from ids.
func readersRemoved(old, ids []string) bool {
	for _, id := range old {
		if !contains(ids, id) {
			return true
		}
	}
	return false
}

// readersOf names the principals that may read env: its resolved access, or
// for base the derived union.
func (a *App) readersOf(env string, f *envfile.File) []string {
	if isBase(env) {
		ps, err := a.baseAccess()
		if err != nil {
			return nil
		}
		return ps
	}
	ps, err := a.Roster.Expand(f.Access)
	if err != nil {
		return nil
	}
	return ps
}

// readersEffect describes an envelope update from recipients old to ids:
// "update production readers: carol now reads production secrets". Empty
// when nothing changed.
func (a *App) readersEffect(env string, f *envfile.File, old, ids []string) string {
	if old != nil && sameIDs(old, ids) {
		return ""
	}
	prefix := "update " + env + " readers: "
	if gained := a.newReaders(env, f, old); len(gained) > 0 {
		return prefix + readersText(gained, "now reads "+env+" secrets", "now read "+env+" secrets")
	}
	if lost := a.lostReaders(old, ids); len(lost) > 0 {
		return prefix + readersText(lost, "removed", "removed")
	}
	return prefix + "access changed"
}

// rekeyEffect describes a re-key: "re-key production: bob no longer reads
// production secrets".
func (a *App) rekeyEffect(env string, old, ids []string) string {
	if lost := a.lostReaders(old, ids); len(lost) > 0 {
		return "re-key " + env + ": " + readersText(lost, "no longer reads "+env+" secrets", "no longer read "+env+" secrets")
	}
	return "re-key " + env
}

// encryptEffect describes encrypting hand-written plaintext secrets.
func encryptEffect(plain []string) string {
	if len(plain) == 1 {
		return "encrypt 1 plaintext secret: " + plain[0]
	}
	return fmt.Sprintf("encrypt %d plaintext secrets: %s", len(plain), strings.Join(plain, ", "))
}

// principalIDs returns the recipient IDs of one principal's keys.
func (a *App) principalIDs(name string) []string {
	refs, err := a.Roster.KeysFor([]string{name})
	if err != nil {
		return nil
	}
	var ids []string
	for _, ref := range refs {
		var r crypto.Recipient
		if ref.SSH != "" {
			pk, err := sshkey.Parse(ref.SSH)
			if err != nil {
				continue
			}
			if r, err = crypto.RecipientFromSSH(pk); err != nil {
				continue
			}
		} else if r, err = crypto.RecipientFromAge(ref.Age); err != nil {
			continue
		}
		ids = append(ids, r.ID)
	}
	return ids
}

// newReaders names the principals among env's readers that had no key among
// the old recipients: they can read its secrets for the first time.
func (a *App) newReaders(env string, f *envfile.File, old []string) []string {
	var out []string
	for _, p := range a.readersOf(env, f) {
		had := false
		for _, id := range a.principalIDs(p) {
			if contains(old, id) {
				had = true
				break
			}
		}
		if !had {
			out = append(out, p)
		}
	}
	return out
}

// lostReaders names the principals whose keys were among the old recipients
// but are not in the new set. A key that no current principal holds (a
// principal that just left the roster, or a replaced key) is named from
// lostHint.
func (a *App) lostReaders(old, ids []string) []string {
	var out []string
	matched := map[string]bool{}
	names := make([]string, 0, len(a.Roster.Principals))
	for name := range a.Roster.Principals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pids := a.principalIDs(name)
		inOld, inNew := false, false
		for _, id := range pids {
			if contains(old, id) {
				inOld = true
				matched[id] = true
			}
			if contains(ids, id) {
				inNew = true
			}
		}
		if inOld && !inNew {
			out = append(out, name)
		}
	}
	for _, id := range old {
		if !matched[id] && !contains(ids, id) {
			out = append(out, a.lostHint...)
			break
		}
	}
	return out
}

// readersText renders "carol now reads base secrets", "alice, bob now read
// base secrets", "4 principals now read base secrets". An empty list falls
// back to "access changed".
func readersText(names []string, singular, plural string) string {
	switch n := len(names); {
	case n == 0:
		return "access changed"
	case n == 1:
		return names[0] + " " + singular
	case n <= 3:
		return strings.Join(names, ", ") + " " + plural
	default:
		return fmt.Sprintf("%d principals %s", n, plural)
	}
}

// holdsKeyFor reports whether the caller can open env: its data key is
// already cached, or a private key for one of its recipients is available
// without prompting.
func (a *App) holdsKeyFor(env string, f *envfile.File) bool {
	if _, ok := a.keys[env]; ok {
		return true
	}
	rs, err := a.recipients(env, f)
	if err != nil || len(rs) == 0 {
		return false
	}
	_, err = crypto.FindIdentities(a.identityOptions(false), recipientIDs(rs))
	return err == nil
}

// BaseHas reports whether the base layer defines key.
func (a *App) BaseHas(key string) bool {
	if !a.baseExists() {
		return false
	}
	f, err := a.loadLenient(BaseName)
	if err != nil {
		return false
	}
	_, ok := f.Config[key]
	return ok
}

// view is an environment's resolved entries: base entries overridden per key
// by the environment's own. Origin says where each key came from.
type view struct {
	Config map[string]envfile.Entry
	Origin map[string]string // key → BaseName or the environment
	base   *envfile.File     // nil when nothing is inherited
}

// Keys returns the view's keys, sorted.
func (v *view) Keys() []string {
	keys := make([]string, 0, len(v.Config))
	for k := range v.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// baseKeys returns the sorted keys that come from base.
func (v *view) baseKeys() []string {
	var keys []string
	for k, o := range v.Origin {
		if o == BaseName {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// view builds the resolved view of env for its loaded manifest f. No key is
// needed. Base is read leniently: a missing file is an empty layer.
func (a *App) view(env string, f *envfile.File) (*view, error) {
	v := &view{Config: map[string]envfile.Entry{}, Origin: map[string]string{}}
	if !isBase(env) && f.InheritsBase() && a.baseExists() {
		bf, err := a.loadLenient(BaseName)
		if err != nil {
			return nil, err
		}
		if len(bf.Config) > 0 {
			v.base = bf
		}
		for k, e := range bf.Config {
			v.Config[k], v.Origin[k] = e, BaseName
		}
	}
	for k, e := range f.Config {
		v.Config[k], v.Origin[k] = e, env
	}
	return v, nil
}

// Entries returns env's resolved entries and their origin without decrypting.
func (a *App) Entries(env string) (map[string]envfile.Entry, map[string]string, error) {
	f, err := a.Load(env)
	if err != nil {
		return nil, nil, err
	}
	v, err := a.view(env, f)
	if err != nil {
		return nil, nil, err
	}
	return v.Config, v.Origin, nil
}

// viewVars decrypts the view: the environment's own values plus the base
// values it inherits, each MAC-verified and enum/pattern-checked under its
// own file. Both data keys are needed; base's is held by everyone in the
// union, so a reader of env can always open it.
func (a *App) viewVars(env string, f *envfile.File, v *view) (resolve.Vars, error) {
	own, err := a.decryptFile(env, f)
	if err != nil {
		return nil, err
	}
	if v.base == nil {
		return own, nil
	}
	inherited, err := a.decryptFile(BaseName, v.base)
	if err != nil {
		// The reader can open env but not base: base's envelope is behind
		// env's access (a hand edit, or an interrupted ensure). Say so
		// instead of listing fingerprints.
		if errors.Is(err, crypto.ErrNoIdentity) && a.holdsKeyFor(env, f) {
			return nil, &ExitError{Code: ExitDecrypt, Err: fmt.Errorf(
				"cannot decrypt %s: %s inherits base, but base's envelope is behind %s's access; run envc ensure base (or ask someone who can read base)",
				envfile.BaseFile, env, env)}
		}
		return nil, err
	}
	vars := make(resolve.Vars, len(v.Config))
	for _, k := range v.baseKeys() {
		vars[k] = inherited[k]
	}
	for k, val := range own {
		vars[k] = val
	}
	return vars, nil
}

// tryViewVars is viewVars for check: env's own values are given; base values
// are added only if a base key is available without prompting. Missing base
// values are simply absent.
func (a *App) tryViewVars(v *view, own map[string]string) map[string]string {
	vars := make(map[string]string, len(v.Config))
	if v.base != nil {
		bf := v.base
		var bvals map[string]string
		if len(bf.SecretKeys()) == 0 || (bf.Crypto != nil && len(bf.PlaintextSecretKeys()) == 0) {
			bvals = map[string]string{}
			if len(bf.SecretKeys()) > 0 {
				k, ok, err := a.tryDataKey(BaseName, bf)
				if err != nil || !ok {
					bvals = nil
				} else if bvals, err = decryptTokens(BaseName, bf, k); err != nil {
					bvals = nil
				}
			}
		}
		for _, k := range v.baseKeys() {
			e := bf.Config[k]
			if !e.IsSecret() {
				vars[k] = e.Value
			} else if bvals != nil {
				if s, ok := bvals[k]; ok {
					vars[k] = s
				}
			}
		}
	}
	for k, val := range own {
		vars[k] = val
	}
	return vars
}

// wantSnapshot builds the Snapshot a destination should hold for a view.
func wantSnapshot(v *view, vars resolve.Vars) destination.Snapshot {
	snap := make(destination.Snapshot, len(vars))
	for k, val := range vars {
		snap[k] = destination.Entry{Value: val, Secret: v.Config[k].IsSecret()}
	}
	return snap
}

// baseGuard is the usage error for base where an environment is required.
func baseGuard(env string) error {
	if isBase(env) {
		return usagef("%s", BaseNotEnvMsg)
	}
	return nil
}

// baseMissingHint is the usage error for ensure base with no base file.
func baseMissingHint() error {
	return usagef("no %s yet; run `envc set base KEY=VALUE --public|--secret` to create it", envfile.BaseFile)
}

func baseHint(key string) string {
	return fmt.Sprintf("%s is inherited from base; run `envc unset base %s`", key, key)
}
