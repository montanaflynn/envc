package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/montanaflynn/envc/internal/envfile"
)

// effectsOf returns the effects ensure reported for one target.
func effectsOf(res EnsureResult, name string) []string {
	for _, t := range res.Targets {
		if t.Name == name {
			return t.Effects
		}
	}
	return nil
}

func TestEnsureDryRunWritesNothing(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, ""))
	must(t, a.Set("local", "S", secretVal("s")))

	// Hand edits: bob added, a plaintext secret, a stale template.
	f := r.load("local")
	f.Access = append(f.Access, "bob")
	f.Config["P"] = envfile.Entry{Secret: boolp(true), Value: "plain"}
	r.save("local", f)
	r.write(".env.local.example", "edited\n")
	before := map[string]string{}
	for _, rel := range []string{".envc/environments/local.yaml", ".envc/state/local/envelope.yaml", ".env.local.example"} {
		before[rel] = r.read(rel)
	}

	r.dryRun = true
	d := r.open()
	res, err := d.Ensure("")
	must(t, err)
	want := []string{
		"encrypt 1 plaintext secret: P",
		"update local readers: bob now reads local secrets",
		"regenerate .env.local.example",
	}
	if got := effectsOf(res, "local"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("effects = %q, want %q", got, want)
	}
	if res.Pending != 3 || res.Failures() != 0 {
		t.Fatalf("pending = %d, failures = %d", res.Pending, res.Failures())
	}
	for rel, was := range before {
		if r.read(rel) != was {
			t.Fatalf("dry run changed %s", rel)
		}
	}

	// The real run applies exactly that, and a second pass has nothing to do.
	r.dryRun = false
	a = r.open()
	res, err = a.Ensure("")
	must(t, err)
	if got := effectsOf(res, "local"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("effects = %q, want %q", got, want)
	}
	if res.Pending != 0 || res.Failures() != 0 {
		t.Fatalf("after ensure: %+v", res)
	}
	f = r.load("local")
	if len(f.Crypto.Recipients) != 2 || len(f.PlaintextSecretKeys()) != 0 || r.read(".env.local.example") == "edited\n" {
		t.Fatalf("ensure did not apply: %+v", f)
	}
	r.useKey(bob)
	if v, err := r.open().Get("local", "P"); err != nil || v != "plain" {
		t.Fatalf("bob reads P: %v %q", err, v)
	}
	res, err = r.open().Ensure("")
	must(t, err)
	if len(res.Targets) != 0 || len(res.Problems) != 0 {
		t.Fatalf("second ensure not clean: %+v", res)
	}
}

func TestEnsureBlockedByUnfixableError(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	f := r.load("local")
	f.Access = append(f.Access, "ghost") // unknown name: unfixable
	f.Config["P"] = envfile.Entry{Secret: boolp(true), Value: "plain"}
	r.save("local", f)
	tok := r.read(".envc/environments/local.yaml")

	res, err := r.open().Ensure("local")
	must(t, err)
	if len(res.Targets) != 0 {
		t.Fatalf("blocked target must not be fixed: %+v", res.Targets)
	}
	if !hasProblem(res.Problems, envPath("local"), "access", "ghost") || res.Failures() == 0 {
		t.Fatalf("problems = %v", problemPaths(res.Problems))
	}
	// …but it still says what is waiting and what to do next.
	if !hasProblem(res.Problems, envPath("local"), "", "not fixed: resolve the problem(s) above, then run envc ensure local again to encrypt 1 plaintext secret: P") {
		t.Fatalf("blocked target must name the pending fixes: %v", res.Problems)
	}
	if r.read(".envc/environments/local.yaml") != tok {
		t.Fatal("ensure wrote on top of a broken file")
	}
}

func TestEnsureRekeysHandRemovedReader(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	r.withPrincipal(a, "bob", bob, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	key := r.load("local").Crypto.Key

	f := r.load("local")
	f.Access = []string{"alice"}
	r.save("local", f)
	res, err := r.open().Ensure("local")
	must(t, err)
	if got := effectsOf(res, "local"); len(got) != 1 || got[0] != "re-key local: bob no longer reads local secrets" {
		t.Fatalf("effects = %q", got)
	}
	f = r.load("local")
	if f.Crypto.Key == key || len(f.Crypto.Recipients) != 1 {
		t.Fatal("ensure should have re-keyed")
	}
	r.useKey(bob)
	_, err = r.open().Get("local", "S")
	wantExit(t, err, ExitDecrypt, "")
}

func TestEnsureNoKeyNamesReaders(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, ""))
	must(t, a.Set("local", "S", secretVal("s")))
	f := r.load("local")
	f.Access = append(f.Access, "bob")
	r.save("local", f)

	// Dry run needs no key.
	r.noKey()
	r.dryRun = true
	res, err := r.open().Ensure("local")
	must(t, err)
	if res.Pending != 1 {
		t.Fatalf("dry run without a key: %+v", res)
	}
	// The fix does: exit 2, naming who can.
	r.dryRun = false
	_, err = r.open().Ensure("local")
	wantExit(t, err, ExitDecrypt, "readers who can: alice, bob")
	if got := r.load("local").Crypto.Recipients; len(got) != 1 {
		t.Fatalf("failed fix wrote the envelope: %v", got)
	}
}

func TestEnsureUnknownAndBase(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	_, err := a.Ensure("nope")
	wantExit(t, err, ExitUsage, "unknown environment")
	_, err = a.Ensure(BaseName)
	wantExit(t, err, ExitUsage, "no .envc/base.yaml yet")
}

func TestEnsureUnchangedLeavesFilesAlone(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, rel := range []string{".envc/environments/local.yaml", ".envc/state/local/envelope.yaml", ".env.local.example"} {
		must(t, os.Chtimes(filepath.Join(r.root, rel), old, old))
	}
	res, err := r.open().Ensure("")
	must(t, err)
	if len(res.Targets) != 0 {
		t.Fatalf("clean repo reported effects: %+v", res.Targets)
	}
	for _, rel := range []string{".envc/environments/local.yaml", ".envc/state/local/envelope.yaml", ".env.local.example"} {
		st, err := os.Stat(filepath.Join(r.root, rel))
		must(t, err)
		if !st.ModTime().Equal(old) {
			t.Fatalf("ensure rewrote %s with nothing to do", rel)
		}
	}
}

func TestEnsureRepairsHandBrokenMAC(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	must(t, a.Set("local", "T", secretVal("tt")))

	// Hand-delete T: tokens still decrypt, MAC no longer matches.
	f := r.load("local")
	delete(f.Config, "T")
	r.save("local", f)

	_, err := r.open().Get("local", "S")
	wantExit(t, err, ExitDecrypt, "envc ensure local")

	dry := r.open()
	dry.Opts.DryRun = true
	res, err := dry.Ensure("local")
	must(t, err)
	if effs := effectsOf(res, "local"); len(effs) == 0 || effs[0] != "repair MAC: secrets edited by hand" {
		t.Fatalf("dry-run effects = %q", effs)
	}
	if res.Pending == 0 {
		t.Fatalf("dry-run pending = 0")
	}

	res, err = r.open().Ensure("local")
	must(t, err)
	if effs := effectsOf(res, "local"); len(effs) == 0 || effs[0] != "repair MAC: secrets edited by hand" {
		t.Fatalf("effects = %q", effs)
	}
	if res.Failures() != 0 {
		t.Fatalf("failures: %+v", res.Problems)
	}
	if v, err := r.open().Get("local", "S"); err != nil || v != "s" {
		t.Fatalf("Get after repair: %v %q", err, v)
	}
	res, err = r.open().Ensure("local")
	must(t, err)
	if len(res.Targets) != 0 || res.Pending != 0 || res.Failures() != 0 {
		t.Fatalf("second run not clean: %+v", res)
	}
}

func TestEnsureCorruptTokenNotRepaired(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))

	f := r.load("local")
	e := f.Config["S"]
	e.Value = e.Value[:len(e.Value)-6] + "AAAA]"
	f.Config["S"] = e
	r.save("local", f)

	res, err := r.open().Ensure("local")
	must(t, err)
	if res.Failures() == 0 {
		t.Fatalf("corrupt token not reported: %+v", res)
	}
	for _, tg := range res.Targets {
		for _, e := range tg.Effects {
			if strings.Contains(e, "repair MAC") {
				t.Fatalf("corrupt token was repaired: %q", e)
			}
		}
	}
	_, err = r.open().Get("local", "S")
	wantExit(t, err, ExitDecrypt, "")
}
