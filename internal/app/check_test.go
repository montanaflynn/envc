package app

import (
	"context"
	"github.com/montanaflynn/envc/internal/state"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/roster"
)

func problemPaths(ps []Problem) []string {
	var out []string
	for _, p := range ps {
		s := p.File + ":" + p.Path
		if p.Warn {
			s += " (warn)"
		}
		out = append(out, s)
	}
	return out
}

func hasProblem(ps []Problem, file, path, msg string) bool {
	for _, p := range ps {
		if p.File == file && p.Path == path && strings.Contains(p.Msg, msg) {
			return true
		}
	}
	return false
}

func TestCheckClean(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	must(t, a.Set("local", "P", SetOptions{Secret: boolp(false), HasValue: true, Value: "a", Enum: []string{"a"}}))
	must(t, a.EnvAdd("local", EnvAddOptions{Dotenv: ".env"}))
	_, err := a.Sync(context.Background(), "local", "", false) // else .env is reported missing
	must(t, err)

	ps, err := a.inspect("")
	must(t, err)
	if len(ps) != 0 {
		t.Fatalf("problems: %v", problemPaths(ps))
	}
	// Without a key it is still clean (MAC not checked, no prompt, no notice).
	r.noKey()
	r.stderr.Reset()
	ps, err = r.open().inspect("local")
	must(t, err)
	if len(ps) != 0 || r.stderr.Len() != 0 {
		t.Fatalf("problems: %v stderr=%q", problemPaths(ps), r.stderr.String())
	}
	_, err = a.inspect("nope")
	wantExit(t, err, ExitUsage, "unknown environment")
}

func TestCheckFindsProblems(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, ""))
	must(t, a.Set("local", "S", secretVal("s")))
	must(t, a.Set("local", "L", SetOptions{Secret: boolp(false), HasValue: true, Value: "a", Enum: []string{"a"}}))
	must(t, a.EnvAdd("prod", EnvAddOptions{}))

	// Hand edits: access changed without rewrap, public enum violated, secret
	// pattern violated (needs key), empty required value, unknown access
	// name on prod, unregistered destination, group with unknown member.
	f := r.load("local")
	f.Access = append(f.Access, "bob")
	l := f.Config["L"]
	l.Value = "zzz"
	f.Config["L"] = l
	s := f.Config["S"]
	s.Pattern = "^nomatch"
	f.Config["S"] = s
	f.Config["E"] = envfile.Entry{Secret: boolp(false), Value: ""}
	r.save("local", f)
	p := r.load("prod")
	p.Access = []string{"ghost"}
	r.save("prod", p)
	rs, _ := roster.Load(r.root)
	rs.Sync["prod"] = map[string]roster.DestConfig{"convex": {}}
	rs.Sync["missing"] = map[string]roster.DestConfig{"dotenv": {}}
	rs.Groups["g"] = []string{"nobody"}
	must(t, rs.Save(r.root))

	ps, err := r.open().inspect("")
	must(t, err)
	for _, want := range []struct{ file, path, msg string }{
		{".envc.yaml", "groups.g[0]", "unknown principal"},
		{".envc.yaml", "sync.prod.convex", "unknown destination"},
		{".envc.yaml", "sync.missing", "no .envc/environments/missing.yaml"},
		{".envc/environments/local.yaml", "config.L.enum", "not one of"},
		{".envc/environments/local.yaml", "config.S.pattern", "does not match"},
		{".envc/environments/prod.yaml", "access", "ghost"},
	} {
		if !hasProblem(ps, want.file, want.path, want.msg) {
			t.Errorf("missing problem %s:%s %q in %v", want.file, want.path, want.msg, problemPaths(ps))
		}
	}
	found := false
	for _, p := range ps {
		if p.Path == "config.E.value" && p.Warn {
			found = true
		}
	}
	if !found {
		t.Errorf("empty required value should warn: %v", problemPaths(ps))
	}

	// A target with unfixable problems gets no fixes planned: the hand-added
	// reader is not reported until the enum problem is gone.
	if hasProblem(ps, "local", "", "update local readers") {
		t.Fatalf("blocked target must not plan fixes: %v", problemPaths(ps))
	}
	// Without a key the secret pattern problem disappears; the rest stay.
	r.noKey()
	ps, err = r.open().inspect("local")
	must(t, err)
	if hasProblem(ps, ".envc/environments/local.yaml", "config.S.pattern", "") || !hasProblem(ps, ".envc/environments/local.yaml", "config.L.enum", "") {
		t.Fatalf("no-key check: %v", problemPaths(ps))
	}
}

func TestCheckMACAndDestinations(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "A", secretVal("a")))
	must(t, a.Set("local", "B", secretVal("b")))
	f := r.load("local")
	delete(f.Config, "A")
	r.save("local", f)
	rs, _ := roster.Load(r.root)
	rs.Sync["local"] = map[string]roster.DestConfig{"fake": {"id": "x", "bogus": "y"}}
	must(t, rs.Save(r.root))

	a2 := r.open()
	ps, err := a2.inspect("")
	must(t, err)
	// A hand-deleted secret is no longer a problem: every token still
	// decrypts, so the MAC mismatch is marked repairable for ensure.
	if hasProblem(ps, ".envc/state/local/envelope.yaml", "mac", "") || !hasProblem(ps, ".envc.yaml", "sync.local.fake", "unknown field") {
		t.Fatalf("problems: %v", problemPaths(ps))
	}
	if !a2.macBroken["local"] {
		t.Fatal("hand-broken MAC not marked repairable")
	}
	// Encrypted values whose envelope is gone: check points at the restore
	// command, and every read is ExitDecrypt with the same hint.
	must(t, state.RemoveEnvelope(r.root, "local"))
	ps, _ = r.open().inspect("local")
	if !hasProblem(ps, ".envc/state/local/envelope.yaml", "", "git checkout -- .envc/state/local/envelope.yaml") {
		t.Fatalf("problems: %v", problemPaths(ps))
	}
	_, err = r.open().Get("local", "S")
	wantExit(t, err, ExitDecrypt, "git checkout -- .envc/state/local/envelope.yaml")
	if _, err := os.Stat(filepath.Join(r.root, ".envc/state/local/envelope.yaml")); err == nil {
		t.Fatal("a missing envelope must never be regenerated")
	}
	// Plaintext secrets with no envelope is the hand-written case: a dry run
	// reports the encryption and the new readers; ensure creates the envelope.
	f = r.load("local")
	f.Crypto = nil
	f.Config["B"] = envfile.Entry{Secret: boolp(true), Value: "plain"}
	r.save("local", f)
	ps, _ = r.open().inspect("local")
	if !hasProblem(ps, "local", "", "encrypt 1 plaintext secret: B") || !hasProblem(ps, "local", "", "update local readers: alice now reads local secrets") {
		t.Fatalf("problems: %v", ps)
	}
	if _, err := os.Stat(filepath.Join(r.root, ".envc/state/local/envelope.yaml")); err == nil {
		t.Fatal("dry run wrote the envelope")
	}
	res, err := r.open().Ensure("local")
	must(t, err)
	if len(res.Targets) != 1 || res.Targets[0].Effects[0] != "encrypt 1 plaintext secret: B" {
		t.Fatalf("ensure: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(r.root, ".envc/state/local/envelope.yaml")); err != nil {
		t.Fatal("ensure did not create the envelope")
	}
}

func TestCheckWarnsUnsynced(t *testing.T) {
	r, a, _, _ := syncRepo(t)
	_, err := a.Sync(context.Background(), "prod", "", false)
	must(t, err)
	ps, err := a.inspect("prod")
	must(t, err)
	if len(ps) != 0 {
		t.Fatalf("clean after sync, got %v", problemPaths(ps))
	}
	must(t, a.Set("prod", "PUBLIC", publicVal("changed")))
	must(t, a.Set("prod", "NEW", publicVal("n")))
	ps, err = a.inspect("prod")
	must(t, err)
	for _, name := range []string{"fake", "fake2"} {
		if !hasProblem(ps, ".envc/state/prod/sync.yaml", name, "2 value(s) changed since last sync (NEW, PUBLIC)") {
			t.Fatalf("problems: %v", problemPaths(ps))
		}
	}
	for _, p := range ps {
		if !p.Warn {
			t.Fatalf("unsynced must be a warning: %+v", p)
		}
	}
	// Never synced at all: silent.
	must(t, state.RemoveSync(r.root, "prod"))
	if ps, _ = a.inspect("prod"); len(ps) != 0 {
		t.Fatalf("never synced should not warn: %v", problemPaths(ps))
	}
}

func TestCheckDotenvStale(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, ""))
	must(t, a.EnvAdd("local", EnvAddOptions{Dotenv: ".env"}))
	must(t, a.EnvAdd("prod", EnvAddOptions{}))
	must(t, a.EnvAdd("pub", EnvAddOptions{Dotenv: ".env.pub"}))
	must(t, a.Set("local", "S", secretVal("s")))
	must(t, a.Set("pub", "P", publicVal("p")))

	dotenv := func(ps []Problem, file string) *Problem {
		for i := range ps {
			if ps[i].File == file {
				return &ps[i]
			}
		}
		return nil
	}
	// Never synced: both configured .env files are missing → warnings only.
	ps, err := a.inspect("")
	must(t, err)
	for _, file := range []string{".env", ".env.pub"} {
		p := dotenv(ps, file)
		if p == nil || !p.Warn || !strings.HasPrefix(p.Msg, "missing; run envc sync") {
			t.Fatalf("%s: want missing warning, got %+v (all: %v)", file, p, problemPaths(ps))
		}
	}
	_, err = a.Sync(context.Background(), "local", "", false)
	must(t, err)
	_, err = a.Sync(context.Background(), "pub", "", false)
	must(t, err)
	if ps, _ = a.inspect(""); len(ps) != 0 {
		t.Fatalf("in sync: %v", problemPaths(ps))
	}

	// Hand-edited .env → stale warning.
	r.write(".env", "S=other\n")
	ps, _ = r.open().inspect("local")
	if p := dotenv(ps, ".env"); p == nil || !p.Warn || p.Msg != "stale; run envc sync local" {
		t.Fatalf("stale: %+v", problemPaths(ps))
	}

	// Hand edits show up as pending fixes: bob added by hand → readers
	// update; plaintext on prod → encryption.
	f := r.load("local")
	f.Access = append(f.Access, "bob")
	r.save("local", f)
	p := r.load("prod")
	p.Access = []string{"alice"}
	p.Config["X"] = envfile.Entry{Secret: boolp(true), Value: "plain"}
	r.save("prod", p)
	ps, _ = r.open().inspect("")
	if !hasProblem(ps, "local", "", "update local readers: bob now reads local secrets") {
		t.Fatalf("readers drift must be pending: %v", ps)
	}
	if !hasProblem(ps, "prod", "", "encrypt 1 plaintext secret: X") {
		t.Fatalf("plaintext secret must be pending: %v", ps)
	}

	// Without a key the .env comparison is skipped silently (secrets involved).
	must(t, r.open().rewrap("local"))
	r.noKey()
	ps, _ = r.open().inspect("local")
	if dotenv(ps, ".env") != nil {
		t.Fatalf("no key must not warn about .env: %v", problemPaths(ps))
	}
	// A public-only environment needs no key.
	r.write(".env.pub", "P=changed\n")
	ps, _ = r.open().inspect("pub")
	if p := dotenv(ps, ".env.pub"); p == nil || p.Msg != "stale; run envc sync pub" {
		t.Fatalf("public stale without key: %v", problemPaths(ps))
	}
}
