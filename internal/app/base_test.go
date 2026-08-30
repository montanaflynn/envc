package app

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/state"
)

// baseRepo is newRepo plus: alice on local, bob on production, alice's key
// in the process, and a base layer with one public and one secret entry.
func baseRepo(t *testing.T) (*repo, *App, keyPair, keyPair) {
	t.Helper()
	r := newRepo(t)
	alice, bob := newEd25519(t, ""), newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.EnvAdd("production", EnvAddOptions{}))
	r.withPrincipal(a, "bob", bob, "production")
	must(t, a.Set(BaseName, "APP_NAME", publicVal("envc")))
	must(t, a.Set(BaseName, "SHARED_SECRET", secretVal("s3")))
	return r, a, alice, bob
}

func TestBaseFileAndResolution(t *testing.T) {
	r, a, _, _ := baseRepo(t)

	// The base file exists, has no access key, and the envelope is under state/base.
	raw := r.read(envfile.BaseFile)
	if strings.Contains(raw, "access") || !strings.Contains(raw, "APP_NAME") || !strings.Contains(raw, "ENC[envc1,") {
		t.Fatalf("base.yaml = %q", raw)
	}
	if _, err := os.Stat(state.EnvelopePath(r.root, BaseName)); err != nil {
		t.Fatal(err)
	}

	// Both environments resolve the base entries; an override wins per key.
	for _, env := range []string{"local", "production"} {
		if env == "production" {
			continue // alice cannot read production; covered below with bob
		}
		vars, err := a.Resolve(env)
		must(t, err)
		if vars["APP_NAME"] != "envc" || vars["SHARED_SECRET"] != "s3" {
			t.Fatalf("%s resolved = %v", env, vars)
		}
	}
	must(t, a.Set("local", "APP_NAME", publicVal("local-name")))
	vars, err := a.Resolve("local")
	must(t, err)
	if vars["APP_NAME"] != "local-name" || vars["SHARED_SECRET"] != "s3" {
		t.Fatalf("override: %v", vars)
	}
	if v, err := a.Get("local", "SHARED_SECRET"); err != nil || v != "s3" {
		t.Fatalf("get inherited: %v %q", err, v)
	}
	if v, err := a.Get("local", "APP_NAME"); err != nil || v != "local-name" {
		t.Fatalf("get override: %v %q", err, v)
	}
	entries, origin, err := a.Entries("local")
	must(t, err)
	if origin["APP_NAME"] != "local" || origin["SHARED_SECRET"] != BaseName || entries["SHARED_SECRET"].IsSecret() != true {
		t.Fatalf("entries=%v origin=%v", entries, origin)
	}

	// unset the override → inherits again; unset an inherited-only key → usage error.
	must(t, a.Unset("local", "APP_NAME"))
	if v, _ := a.Get("local", "APP_NAME"); v != "envc" {
		t.Fatalf("after unset: %q", v)
	}
	wantExit(t, a.Unset("local", "APP_NAME"), ExitUsage, "inherited from base; run `envc unset base APP_NAME`")
	if !a.BaseHas("APP_NAME") || a.BaseHas("NOPE") {
		t.Fatal("BaseHas")
	}
	_, err = a.Get("local", "NOPE")
	wantExit(t, err, ExitUsage, "no key NOPE")

	// show/ls of the environment itself do not gain base entries in the manifest.
	if _, ok := r.load("local").Config["SHARED_SECRET"]; ok {
		t.Fatal("base entry leaked into the manifest")
	}
}

func TestBaseReservedAndRejected(t *testing.T) {
	r, a, _, _ := baseRepo(t)
	wantExit(t, a.EnvAdd(BaseName, EnvAddOptions{}), ExitUsage, BaseNotEnvMsg)
	wantExit(t, a.EnvRemove(BaseName, true), ExitUsage, BaseNotEnvMsg)
	wantExit(t, a.Allow(BaseName, []string{"alice"}), ExitUsage, BaseNotEnvMsg)
	wantExit(t, a.Deny(BaseName, []string{"alice"}), ExitUsage, BaseNotEnvMsg)
	_, err := a.Resolve(BaseName)
	wantExit(t, err, ExitUsage, BaseNotEnvMsg)
	_, err = a.Sync(nil, BaseName, "", false)
	wantExit(t, err, ExitUsage, BaseNotEnvMsg)
	_, err = a.Diff(nil, BaseName, "")
	wantExit(t, err, ExitUsage, BaseNotEnvMsg)
	_, err = a.inspect(BaseName) // ensure accepts base
	must(t, err)
	_, err = a.Example(BaseName)
	wantExit(t, err, ExitUsage, BaseNotEnvMsg)
	if _, err := os.Stat(ExamplePath(r.root, BaseName)); err == nil {
		t.Fatal("base must not get a template")
	}

	// access: and base: are unknown fields in the base layer.
	r.write(envfile.BaseFile, "access: [alice]\nconfig: {}\n")
	_, err = r.open().Load(BaseName)
	wantExit(t, err, ExitUsage, "access")
	r.write(envfile.BaseFile, "base: false\nconfig: {}\n")
	_, err = r.open().Load(BaseName)
	wantExit(t, err, ExitUsage, "base")

	// ensure base without a base file points at set.
	must(t, os.Remove(filepath.Join(r.root, filepath.FromSlash(envfile.BaseFile))))
	must(t, state.Remove(r.root, BaseName))
	wantExit(t, r.open().rewrap(BaseName), ExitUsage, "no .envc/base.yaml yet")
	wantExit(t, r.open().rekey(BaseName), ExitUsage, "no .envc/base.yaml yet")
}

func TestBaseNeedsSomeAccess(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	must(t, a.PrincipalAddKeys("alice", "", []string{alice.pub}, ""))
	must(t, a.Set(BaseName, "APP_NAME", publicVal("x"))) // public needs no access
	wantExit(t, a.Set(BaseName, "S", secretVal("s")), ExitUsage, "no environment grants access yet")
	must(t, a.Allow("local", []string{"alice"}))
	must(t, a.Set(BaseName, "S", secretVal("s")))
}

func TestBaseAccessIsTheUnion(t *testing.T) {
	r, a, alice, bob := baseRepo(t)
	bf := r.load(BaseName)
	if len(bf.Crypto.Recipients) != 2 {
		t.Fatalf("base recipients = %v, want alice+bob", bf.Crypto.Recipients)
	}
	w, err := a.Who(BaseName)
	must(t, err)
	if !w.Derived || !reflect.DeepEqual(w.Principals, []string{"alice", "bob"}) || len(w.Access) != 0 {
		t.Fatalf("who base = %+v", w)
	}

	// bob, who can read only production, reads base and resolves production.
	r.useKey(bob)
	b := r.open()
	if v, err := b.Get(BaseName, "SHARED_SECRET"); err != nil || v != "s3" {
		t.Fatalf("bob get base: %v %q", err, v)
	}
	vars, err := b.Resolve("production")
	must(t, err)
	if vars["SHARED_SECRET"] != "s3" || vars["APP_NAME"] != "envc" {
		t.Fatalf("bob resolve production = %v", vars)
	}

	// deny bob on production: the union shrinks and base is reencrypted.
	r.useKey(alice)
	keyBefore, tokBefore := bf.Crypto.Key, bf.Config["SHARED_SECRET"].Value
	must(t, a.Deny("production", []string{"bob"}))
	bf = r.load(BaseName)
	if len(bf.Crypto.Recipients) != 1 || bf.Crypto.Key == keyBefore || bf.Config["SHARED_SECRET"].Value == tokBefore {
		t.Fatal("deny should reencrypt base to the new union")
	}
	r.useKey(bob)
	_, err = r.open().Get(BaseName, "SHARED_SECRET")
	wantExit(t, err, ExitDecrypt, "")

	// allow bob again: base rewraps (same token).
	r.useKey(alice)
	tokBefore = bf.Config["SHARED_SECRET"].Value
	must(t, a.Allow("production", []string{"bob"}))
	bf = r.load(BaseName)
	if len(bf.Crypto.Recipients) != 2 || bf.Config["SHARED_SECRET"].Value != tokBefore {
		t.Fatal("allow should rewrap base without changing tokens")
	}
	r.useKey(bob)
	if v, err := r.open().Get(BaseName, "SHARED_SECRET"); err != nil || v != "s3" {
		t.Fatalf("bob after re-allow: %v %q", err, v)
	}

	// env rm production: bob leaves the union.
	r.useKey(alice)
	must(t, a.EnvRemove("production", true))
	if bf = r.load(BaseName); len(bf.Crypto.Recipients) != 1 {
		t.Fatalf("after env rm: %v", bf.Crypto.Recipients)
	}

	// group and principal edits reach base too.
	must(t, a.EnvAdd("staging", EnvAddOptions{}))
	must(t, a.GroupSet("ops", []string{"bob"}))
	must(t, a.Allow("staging", []string{"ops"}))
	if bf = r.load(BaseName); len(bf.Crypto.Recipients) != 2 {
		t.Fatalf("allow group: %v", bf.Crypto.Recipients)
	}
	_, err = a.GroupRemoveMember("ops", "bob")
	must(t, err)
	if bf = r.load(BaseName); len(bf.Crypto.Recipients) != 1 {
		t.Fatalf("group rm-member: %v", bf.Crypto.Recipients)
	}
	must(t, a.Set("staging", "X", publicVal("1")))
	_, err = a.PrincipalRemove("bob")
	must(t, err)
	if bf = r.load(BaseName); len(bf.Crypto.Recipients) != 1 {
		t.Fatalf("principal rm: %v", bf.Crypto.Recipients)
	}
}

func TestCheckBaseUnion(t *testing.T) {
	r, a, _, _ := baseRepo(t)
	probs, err := a.inspect("")
	must(t, err)
	if len(probs) != 0 {
		t.Fatalf("clean repo: %v", probs)
	}
	// Hand-break the union: an extra recipient in the base envelope.
	bf := r.load(BaseName)
	bf.Crypto.Recipients = append(bf.Crypto.Recipients, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	must(t, bf.Crypto.Save(r.root, BaseName))
	probs, err = r.open().inspect("")
	must(t, err)
	if !hasProblem(probs, BaseName, "", "re-key base") {
		t.Fatalf("problems = %v", probs)
	}
	res, err := r.open().Ensure(BaseName)
	must(t, err)
	if len(res.Targets) != 1 || res.Targets[0].Effects[0] != "re-key base" {
		t.Fatalf("ensure base: %+v", res)
	}
	if probs, _ = r.open().inspect(""); len(probs) != 0 {
		t.Fatalf("after ensure base: %v", probs)
	}
	// A hand-edited environment access list shrinks the union: ensure re-keys base.
	f := r.load("local")
	f.Access = []string{}
	r.save("local", f)
	probs, _ = r.open().inspect("")
	if !hasProblem(probs, BaseName, "", "re-key base: alice no longer reads base secrets") {
		t.Fatalf("problems = %v", probs)
	}
}

func TestBaseExampleLines(t *testing.T) {
	r, a, _, _ := baseRepo(t)
	ex := r.read(".env.local.example")
	if !strings.Contains(ex, "# from base\nAPP_NAME=envc\n") || !strings.Contains(ex, "# secret\n# from base\nSHARED_SECRET=\n") {
		t.Fatalf(".env.local.example = %q", ex)
	}
	// A base change refreshes every environment's template.
	must(t, a.Set(BaseName, "APP_NAME", publicVal("renamed")))
	if ex = r.read(".env.local.example"); !strings.Contains(ex, "APP_NAME=renamed") {
		t.Fatalf("local template not refreshed: %q", ex)
	}
	if ex = r.read(".env.production.example"); !strings.Contains(ex, "APP_NAME=renamed") {
		t.Fatalf("production template not refreshed: %q", ex)
	}
	// An override loses the marker.
	must(t, a.Set("local", "APP_NAME", publicVal("mine")))
	if ex = r.read(".env.local.example"); strings.Contains(ex, "# from base\nAPP_NAME") || !strings.Contains(ex, "APP_NAME=mine") {
		t.Fatalf("override template = %q", ex)
	}
	probs, err := a.inspect("")
	must(t, err)
	if len(probs) != 0 {
		t.Fatalf("check: %v", probs)
	}
}

func TestBaseOptOut(t *testing.T) {
	r, a, alice, _ := baseRepo(t)
	carol := newEd25519(t, "")
	must(t, a.EnvAdd("ci", EnvAddOptions{}))
	f := r.load("ci")
	f.Inherit = boolp(false)
	r.save("ci", f)
	r.withPrincipal(a, "carol", carol, "ci")
	must(t, a.Set("ci", "CI_ONLY", publicVal("1")))

	// ci resolves only its own entries and contributes nothing to base.
	vars, err := a.Resolve("ci")
	must(t, err)
	if _, ok := vars["APP_NAME"]; ok || vars["CI_ONLY"] != "1" {
		t.Fatalf("ci resolved = %v", vars)
	}
	if _, origin, _ := a.Entries("ci"); origin["APP_NAME"] != "" {
		t.Fatalf("ci origin = %v", origin)
	}
	if ex := r.read(".env.ci.example"); strings.Contains(ex, "from base") || strings.Contains(ex, "APP_NAME") {
		t.Fatalf("ci template = %q", ex)
	}
	w, _ := a.Who(BaseName)
	if reflect.DeepEqual(w.Principals, []string{"alice", "bob", "carol"}) {
		t.Fatal("carol must not be in the base union")
	}
	if bf := r.load(BaseName); len(bf.Crypto.Recipients) != 2 {
		t.Fatalf("base recipients = %v", bf.Crypto.Recipients)
	}
	r.useKey(carol)
	_, err = r.open().Get(BaseName, "SHARED_SECRET")
	wantExit(t, err, ExitDecrypt, "")
	if _, err := r.open().Get("ci", "APP_NAME"); err == nil {
		t.Fatal("ci must not inherit APP_NAME")
	}
	wantExit(t, r.open().Unset("ci", "APP_NAME"), ExitUsage, "no key APP_NAME")
	if probs, err := r.open().inspect(""); err != nil || len(probs) != 0 {
		t.Fatalf("check: %v %v", probs, err)
	}

	// Flip to inherit: rewrap ci re-derives the union.
	r.useKey(newEd25519(t, "")) // nobody: manifest edits need no key
	f = r.load("ci")
	f.Inherit = boolp(true)
	r.save("ci", f)
	r.useKey(carol)
	wantExit(t, r.open().rewrap("ci"), ExitDecrypt, "") // carol cannot open base yet
	r.useKey(alice)
	must(t, r.open().rewrap("ci"))
	if bf := r.load(BaseName); len(bf.Crypto.Recipients) != 3 {
		t.Fatalf("base recipients after opt-in = %v", bf.Crypto.Recipients)
	}
	r.useKey(carol)
	if v, err := r.open().Get(BaseName, "SHARED_SECRET"); err != nil || v != "s3" {
		t.Fatalf("carol after opt-in: %v %q", err, v)
	}

	// Anything but a bool is a parse error.
	r.write(".envc/environments/ci.yaml", "access: [carol]\nbase: maybe\nconfig: {}\n")
	_, err = r.open().Load("ci")
	wantExit(t, err, ExitUsage, "into bool")
}

// wantEffects asserts the effects a recorded, in order.
func wantEffects(t *testing.T, a *App, want ...string) {
	t.Helper()
	if got := a.Effects(); !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
		t.Fatalf("effects = %q, want %q", got, want)
	}
}

func TestBaseEffects(t *testing.T) {
	r, a, _, _ := baseRepo(t)
	carol := newEd25519(t, "")
	must(t, a.PrincipalAddKeys("carol", "", []string{carol.pub}, ""))
	must(t, a.Allow("production", []string{"alice"})) // so alice can rewrap it below
	must(t, a.Set("production", "S", secretVal("1")))

	// allow: production rewrapped, then base, naming who gained it.
	a = r.open()
	must(t, a.Allow("production", []string{"carol"}))
	wantEffects(t, a, "update production readers: carol now reads production secrets", "update base readers: carol now reads base secrets")

	// nothing changed: no lines at all.
	a = r.open()
	must(t, a.Allow("production", []string{"carol"}))
	wantEffects(t, a)

	// deny: both re-keyed, naming who lost it.
	a = r.open()
	must(t, a.Deny("production", []string{"carol"}))
	wantEffects(t, a, "re-key production: carol no longer reads production secrets", "re-key base: carol no longer reads base secrets")

	// dry run reports the same as a real run would, from the staged manifest.
	opts := r.options()
	opts.DryRun = true
	d, err := Open(opts)
	must(t, err)
	must(t, d.Allow("production", []string{"carol"}))
	wantEffects(t, d, "update production readers: carol now reads production secrets", "update base readers: carol now reads base secrets")
	if bf := r.load(BaseName); len(bf.Crypto.Recipients) != 2 {
		t.Fatalf("dry run wrote base: %v", bf.Crypto.Recipients)
	}

	// hand-edited access, then ensure ENV: base follows and says so.
	f := r.load("production")
	f.Access = append(f.Access, "carol")
	r.save("production", f)
	a = r.open()
	res, err := a.Ensure("production")
	must(t, err)
	if len(res.Targets) != 1 || res.Targets[0].Name != "production" {
		t.Fatalf("ensure production: %+v", res)
	}
	wantEffects(t, a, "update production readers: carol now reads production secrets", "update base readers: carol now reads base secrets")

	// principal rm reseals base (it did not before) and names the leaver.
	a = r.open()
	_, err = a.PrincipalRemove("carol")
	must(t, err)
	wantEffects(t, a, "re-key production: carol no longer reads production secrets", "re-key base: carol no longer reads base secrets")
	if bf := r.load(BaseName); len(bf.Crypto.Recipients) != 2 {
		t.Fatalf("principal rm left base at %v", bf.Crypto.Recipients)
	}
	r.useKey(carol)
	_, err = r.open().Get(BaseName, "SHARED_SECRET")
	wantExit(t, err, ExitDecrypt, "")

	// env rm: bob's only environment goes, so bob leaves base.
	r, a, _, _ = baseRepo(t)
	a = r.open()
	must(t, a.EnvRemove("production", true))
	wantEffects(t, a, "re-key base: bob no longer reads base secrets")

	// no base secrets: no base line at all.
	must(t, r.open().Unset(BaseName, "SHARED_SECRET"))
	must(t, a.EnvAdd("production", EnvAddOptions{}))
	a = r.open()
	must(t, a.Allow("production", []string{"bob"}))
	wantEffects(t, a)
}

func TestBaseBehindEnvAccess(t *testing.T) {
	r, a, _, _ := baseRepo(t)
	carol := newEd25519(t, "")
	must(t, a.PrincipalAddKeys("carol", "", []string{carol.pub}, ""))
	must(t, a.Allow("production", []string{"alice"}))
	must(t, a.Set("production", "S", secretVal("1")))

	// Add carol to production's access and rewrap only production, leaving
	// base behind (an interrupted rewrap looks like this).
	f := r.load("production")
	f.Access = append(f.Access, "carol")
	must(t, a.rewrapFile("production", f))

	r.useKey(carol)
	_, err := r.open().Resolve("production")
	wantExit(t, err, ExitDecrypt, "production inherits base, but base's envelope is behind production's access; run envc ensure base")
	// Not in local's access at all: the generic message, not the drift one.
	_, err = r.open().Resolve("local")
	wantExit(t, err, ExitDecrypt, "no usable private key")
	if strings.Contains(err.Error(), "behind") {
		t.Fatalf("generic case got the drift message: %v", err)
	}
}

func TestWhoInheritsBase(t *testing.T) {
	r, a, _, _ := baseRepo(t)
	w, err := a.Who("local")
	must(t, err)
	if !w.InheritsBase {
		t.Fatal("local inherits base with secrets: want InheritsBase")
	}
	must(t, a.EnvAdd("ci", EnvAddOptions{}))
	f := r.load("ci")
	f.Inherit = boolp(false)
	r.save("ci", f)
	must(t, a.Allow("ci", []string{"alice"}))
	if w, _ = a.Who("ci"); w.InheritsBase {
		t.Fatal("base: false must not report InheritsBase")
	}
	must(t, a.Unset(BaseName, "SHARED_SECRET"))
	if w, _ = r.open().Who("local"); w.InheritsBase {
		t.Fatal("base without secrets must not report InheritsBase")
	}
}
