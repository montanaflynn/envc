package app

import (
	"errors"
	"fmt"

	"github.com/montanaflynn/envc/internal/envfile"
)

// EnsureTarget is what ensure did (or, under DryRun, would do) to one
// environment or to base, as effects in base form ("encrypt 1 plaintext
// secret: KEY", "update production readers: …", "re-key base: …",
// "regenerate .env.production.example").
type EnsureTarget struct {
	Name    string
	Effects []string
}

// EnsureResult is the outcome of Ensure: the targets that changed, the
// problems that remain (unfixable errors and warnings), and under DryRun the
// number of fixes that were not applied.
type EnsureResult struct {
	Targets  []EnsureTarget
	Problems []Problem
	Pending  int
}

// Failures counts the non-warning problems.
func (r EnsureResult) Failures() int {
	n := 0
	for _, p := range r.Problems {
		if !p.Warn {
			n++
		}
	}
	return n
}

// Ensure makes the generated state match the files: for env (or, when env
// is empty, every environment and then base) it validates the manifest and
// reports what it cannot fix, then encrypts plaintext secrets, brings the
// envelope's readers in line with access (re-keying when a reader was
// removed), reseals base after an environment's access changed, and
// regenerates a stale .env.<env>.example. A target with an unfixable error
// is left untouched. Under Options.DryRun nothing is written: the fixes are
// reported as effects and counted in Pending.
func (a *App) Ensure(env string) (EnsureResult, error) {
	res := EnsureResult{Targets: []EnsureTarget{}, Problems: []Problem{}}
	envs, err := a.EnvList()
	if err != nil {
		return res, err
	}
	res.Problems = append(res.Problems, a.checkRoster(envs)...)
	var targets []string
	withBase := false
	switch {
	case env == "":
		targets = envs
		if a.baseExists() {
			targets = append(targets, BaseName)
		}
	case isBase(env):
		if !a.baseExists() {
			return res, baseMissingHint()
		}
		targets = []string{BaseName}
	default:
		if _, err := a.Env(env); err != nil {
			return res, err
		}
		targets = []string{env}
		withBase = true
	}
	for _, t := range targets {
		start := len(a.effects)
		probs, pending, err := a.ensureTarget(t, withBase)
		if err != nil {
			return res, err
		}
		res.Problems = append(res.Problems, probs...)
		res.Pending += pending
		if eff := a.effects[start:]; len(eff) > 0 {
			res.Targets = append(res.Targets, EnsureTarget{Name: t, Effects: append([]string(nil), eff...)})
		}
	}
	return res, nil
}

// ensureTarget validates and fixes one target. withBase adds base's own
// drift to a dry run of a single environment (a real run reseals base as a
// side effect; when every target is ensured, base is its own target).
func (a *App) ensureTarget(env string, withBase bool) ([]Problem, int, error) {
	f, probs, ok := a.inspectEnv(env)
	macBroken := ok && f != nil && a.macBroken[env]
	if !isBase(env) && f != nil {
		probs = append(probs, a.checkDotenv(env)...)
	}
	if !ok {
		if f != nil {
			if blocked := a.blockedFixes(env, f); blocked != "" {
				probs = append(probs, Problem{File: envPath(env), Msg: blocked})
			}
		}
		return probs, 0, nil
	}
	plan, err := a.planFix(env, f)
	if err != nil {
		return probs, 0, err
	}
	stale := !isBase(env) && a.exampleStale(env, f)

	if a.Opts.DryRun {
		pending := 0
		if macBroken {
			a.effect("repair MAC: secrets edited by hand")
			pending++
		}
		for _, e := range plan.effects {
			a.effect(e)
			pending++
		}
		if withBase && !isBase(env) && plan.changes() {
			if bp, err := a.planBaseAfter(env, f); err == nil {
				for _, e := range bp.effects {
					a.effect(e)
					pending++
				}
			}
		}
		if stale {
			a.effect("regenerate " + exampleName(env))
			pending++
		}
		return probs, pending, nil
	}

	if macBroken {
		if err := a.repairMAC(env, f); err != nil {
			return probs, 0, a.ensureKeyError(env, f, err)
		}
		a.effect("repair MAC: secrets edited by hand")
	}
	if plan.changes() {
		var err error
		if plan.rekey {
			err = a.reencryptFile(env, f)
		} else {
			err = a.rewrapFile(env, f)
		}
		if err != nil {
			return probs, 0, a.ensureKeyError(env, f, err)
		}
		if !isBase(env) {
			a.stage(env, f)
			if err := a.resealBase(); err != nil {
				return probs, 0, a.ensureKeyError(BaseName, nil, err)
			}
		}
	}
	if stale {
		if err := a.refreshExample(env, f); err != nil {
			return probs, 0, err
		}
		a.effect("regenerate " + exampleName(env))
	}
	return probs, 0, nil
}

// blockedFixes describes the fixes a target with unfixable problems is
// waiting on, so the report says what to do next: fix the problems listed,
// then run ensure again. Empty when nothing is pending. Reader fixes need
// access to resolve; when it does not, only the rest is listed.
func (a *App) blockedFixes(env string, f *envfile.File) string {
	var pending []string
	if plan, err := a.planFix(env, f); err == nil {
		pending = append(pending, plan.effects...)
	} else if plain := f.PlaintextSecretKeys(); len(plain) > 0 {
		pending = append(pending, encryptEffect(plain))
	}
	if !isBase(env) && a.exampleStale(env, f) {
		pending = append(pending, "regenerate "+exampleName(env))
	}
	if len(pending) == 0 {
		return ""
	}
	return fmt.Sprintf("not fixed: resolve the problem(s) above, then run envc ensure %s again to %s", env, joinSemi(pending))
}

// fixPlan is what ensure would do to one target's envelope.
type fixPlan struct {
	effects []string
	rekey   bool // a reader was removed: new data key
}

func (p fixPlan) changes() bool { return len(p.effects) > 0 }

// planFix computes the envelope fixes for f without needing a key: plaintext
// secrets to encrypt, an envelope to create, drop, update, or re-key.
func (a *App) planFix(env string, f *envfile.File) (fixPlan, error) {
	var p fixPlan
	secrets := f.SecretKeys()
	plain := f.PlaintextSecretKeys()
	if len(secrets) == 0 {
		if f.Crypto != nil {
			p.effects = append(p.effects, "remove "+env+" envelope")
		}
		return p, nil
	}
	rs, err := a.recipients(env, f)
	if err != nil {
		return p, err
	}
	if len(rs) == 0 {
		return p, noAccessHint(env)
	}
	ids := recipientIDs(rs)
	old := envelopeRecipients(f)
	if len(plain) > 0 {
		p.effects = append(p.effects, encryptEffect(plain))
	}
	switch {
	case f.Crypto == nil:
		p.effects = append(p.effects, a.readersEffect(env, f, nil, ids))
	case readersRemoved(old, ids):
		p.rekey = true
		p.effects = append(p.effects, a.rekeyEffect(env, old, ids))
	case !sameIDs(old, ids):
		p.effects = append(p.effects, a.readersEffect(env, f, old, ids))
	}
	return p, nil
}

// planBaseAfter is planFix for base as it would be after env's manifest f
// is saved (dry run of a single environment).
func (a *App) planBaseAfter(env string, f *envfile.File) (fixPlan, error) {
	if !a.baseExists() {
		return fixPlan{}, nil
	}
	bf, err := a.loadLenient(BaseName)
	if err != nil || len(bf.SecretKeys()) == 0 || len(bf.PlaintextSecretKeys()) > 0 {
		return fixPlan{}, err
	}
	a.stage(env, f)
	defer delete(a.overlay, env)
	return a.planFix(BaseName, bf)
}

// repairMAC recomputes the MAC over the tokens that remain after a hand
// edit. Only called when inspectEnv saw every token decrypt under the
// envelope's data key, so a failure here is a key problem, not corruption.
func (a *App) repairMAC(env string, f *envfile.File) error {
	k, err := a.dataKeyFor(env, f, true)
	if err != nil {
		return err
	}
	secrets, err := decryptTokens(env, f, k)
	if err != nil {
		return err
	}
	f.Crypto.MAC = k.MAC(secrets)
	return a.saveFile(env, f)
}

// ensureKeyError turns a decrypt failure during a fix into one that says
// which file could not be opened and who can.
func (a *App) ensureKeyError(env string, f *envfile.File, err error) error {
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != ExitDecrypt {
		return err
	}
	if f == nil {
		if f, _ = a.loadLenient(env); f == nil {
			return err
		}
	}
	readers := a.readersOf(env, f)
	if len(readers) == 0 {
		return err
	}
	return &ExitError{Code: ExitDecrypt, Err: fmt.Errorf("ensure %s: %v; readers who can: %s", env, ee.Err, joinComma(readers))}
}
