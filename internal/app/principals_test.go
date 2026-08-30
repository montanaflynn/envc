package app

import (
	"context"
	"reflect"
	"testing"

	"github.com/montanaflynn/envc/internal/roster"
)

func TestPrincipalAddKeys(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "alice@mac")
	alice2 := newEd25519(t, "alice@old")
	a := r.open()

	wantExit(t, a.PrincipalAddKeys("Alice", "", []string{alice.pub}, ""), ExitUsage, "invalid principal name")
	wantExit(t, a.PrincipalAddKeys("alice", "", []string{"ssh-ecdsa AAAA"}, ""), ExitUsage, "")
	wantExit(t, a.PrincipalAddKeys("alice", "", nil, ""), ExitUsage, "no keys")
	wantExit(t, a.PrincipalAddKeys("alice", "", nil, "age1bogus"), ExitUsage, "age")

	must(t, a.PrincipalAddKeys("alice", "alice", []string{alice.pub, alice.pub}, ""))
	rs, err := roster.Load(r.root)
	must(t, err)
	p := rs.Principals["alice"]
	if p.GitHub != "alice" || len(p.Keys) != 1 || p.Keys[0] != alice.pub {
		t.Fatalf("principal = %+v", p)
	}
	// Adding a second key merges; group with same name refused.
	must(t, a.GroupSet("eng", []string{"alice"}))
	wantExit(t, a.PrincipalAddKeys("eng", "", []string{alice.pub}, ""), ExitUsage, "is a group")
	must(t, a.PrincipalAddKeys("alice", "", []string{alice2.pub}, ""))
	rs, _ = roster.Load(r.root)
	if len(rs.Principals["alice"].Keys) != 2 {
		t.Fatalf("keys = %v", rs.Principals["alice"].Keys)
	}
}

func TestPrincipalAddKeyRewrapsEnvs(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	laptop := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.EnvAdd("prod", EnvAddOptions{}))
	must(t, a.Set("local", "S", secretVal("s")))
	must(t, a.Set("prod", "P", publicVal("p")))

	must(t, a.PrincipalAddKeys("alice", "", []string{laptop.pub}, ""))
	f := r.load("local")
	if len(f.Crypto.Recipients) != 2 {
		t.Fatalf("recipients = %v", f.Crypto.Recipients)
	}
	if r.load("prod").Crypto != nil {
		t.Fatal("public-only env got an envelope")
	}
	r.useKey(laptop)
	if v, err := r.open().Get("local", "S"); err != nil || v != "s" {
		t.Fatalf("new key cannot read: %v %q", err, v)
	}
	// Re-adding the same key is a no-op (no key needed).
	r.noKey()
	must(t, r.open().PrincipalAddKeys("alice", "", []string{laptop.pub}, ""))
}

func TestPrincipalRemove(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	must(t, a.PrincipalAddKeys("alice", "", []string{alice.pub}, ""))
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, ""))
	must(t, a.GroupSet("eng", []string{"alice", "bob"}))
	must(t, a.EnvAdd("prod", EnvAddOptions{}))
	must(t, a.EnvAdd("other", EnvAddOptions{}))
	must(t, a.Allow("local", []string{"eng"}))
	must(t, a.Allow("prod", []string{"alice", "bob"}))
	must(t, a.Allow("other", []string{"alice"}))
	must(t, a.Set("local", "S", secretVal("s")))
	must(t, a.Set("prod", "S", secretVal("s")))
	tokLocal := r.load("local").Config["S"].Value

	_, err := a.PrincipalRemove("ghost")
	wantExit(t, err, ExitUsage, "unknown principal")

	envs, err := a.PrincipalRemove("bob")
	must(t, err)
	if !reflect.DeepEqual(envs, []string{"local", "prod"}) {
		t.Fatalf("envs = %v", envs)
	}
	rs, _ := roster.Load(r.root)
	if rs.IsPrincipal("bob") || !reflect.DeepEqual(rs.Groups["eng"], []string{"alice"}) {
		t.Fatalf("roster = %+v", rs)
	}
	local := r.load("local")
	if local.Config["S"].Value == tokLocal || len(local.Crypto.Recipients) != 1 {
		t.Fatal("local should be reencrypted to alice only")
	}
	if got := r.load("prod").Access; !reflect.DeepEqual(got, []string{"alice"}) {
		t.Fatalf("prod access = %v", got)
	}
	r.useKey(bob)
	_, err = r.open().Get("prod", "S")
	wantExit(t, err, ExitDecrypt, "")
}

func TestPrincipalSyncErrors(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	_, err := a.PrincipalSync(context.Background(), "ghost", false, false)
	wantExit(t, err, ExitUsage, "unknown principal")
	must(t, a.PrincipalAddKeys("alice", "", []string{newEd25519(t, "").pub}, ""))
	_, err = a.PrincipalSync(context.Background(), "alice", false, false)
	wantExit(t, err, ExitUsage, "no github")
	// --all with nobody on GitHub: nothing to do.
	changes, err := a.PrincipalSync(context.Background(), "", true, false)
	must(t, err)
	if len(changes) != 0 {
		t.Fatalf("changes = %v", changes)
	}
}

func TestGroups(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	must(t, a.PrincipalAddKeys("alice", "", []string{alice.pub}, ""))
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, ""))

	wantExit(t, a.GroupSet("alice", []string{"bob"}), ExitUsage, "is a principal")
	wantExit(t, a.GroupSet("eng", []string{"ghost"}), ExitUsage, "not a principal")
	wantExit(t, a.GroupSet("Eng", []string{"alice"}), ExitUsage, "invalid group name")
	must(t, a.GroupSet("eng", []string{"alice", "alice"}))
	must(t, a.Allow("local", []string{"eng"}))
	must(t, a.Set("local", "S", secretVal("s")))
	tok := r.load("local").Config["S"].Value

	// add-member rewraps: token unchanged, bob can read.
	_, err := a.GroupAddMember("nope", "bob")
	wantExit(t, err, ExitUsage, "unknown group")
	_, err = a.GroupAddMember("eng", "ghost")
	wantExit(t, err, ExitUsage, "not a principal")
	envs, err := a.GroupAddMember("eng", "bob")
	must(t, err)
	if !reflect.DeepEqual(envs, []string{"local"}) {
		t.Fatalf("envs = %v", envs)
	}
	f := r.load("local")
	if f.Config["S"].Value != tok || len(f.Crypto.Recipients) != 2 {
		t.Fatal("add-member should rewrap only")
	}
	envs, err = a.GroupAddMember("eng", "bob")
	must(t, err)
	if len(envs) != 0 {
		t.Fatalf("re-add touched %v", envs)
	}
	r.useKey(bob)
	if v, err := r.open().Get("local", "S"); err != nil || v != "s" {
		t.Fatalf("bob: %v %q", err, v)
	}

	// rm-member reencrypts.
	r.useKey(alice)
	_, err = a.GroupRemoveMember("eng", "ghost")
	wantExit(t, err, ExitUsage, "not a member")
	envs, err = a.GroupRemoveMember("eng", "bob")
	must(t, err)
	f = r.load("local")
	if !reflect.DeepEqual(envs, []string{"local"}) || f.Config["S"].Value == tok || len(f.Crypto.Recipients) != 1 {
		t.Fatalf("rm-member: envs=%v recipients=%v", envs, f.Crypto.Recipients)
	}
	rs, _ := roster.Load(r.root)
	if !reflect.DeepEqual(rs.Groups["eng"], []string{"alice"}) {
		t.Fatalf("group = %v", rs.Groups["eng"])
	}

	// GroupSet on an existing group with a removed member reencrypts.
	tok = f.Config["S"].Value
	must(t, a.GroupSet("eng", []string{"bob"}))
	if r.load("local").Config["S"].Value == tok {
		t.Fatal("GroupSet removing a member should reencrypt")
	}

	// rm refuses while listed.
	wantExit(t, a.GroupRemove("eng"), ExitUsage, "still on access")
	wantExit(t, a.GroupRemove("nope"), ExitUsage, "unknown group")
	r.useKey(bob)
	must(t, r.open().Allow("local", []string{"bob"}))
	must(t, r.open().Deny("local", []string{"eng"}))
	wantExit(t, r.open().Deny("local", []string{"eng"}), ExitUsage, "not on access")
	must(t, r.open().GroupRemove("eng"))
	rs, _ = roster.Load(r.root)
	if rs.IsGroup("eng") {
		t.Fatal("group not removed")
	}
}
