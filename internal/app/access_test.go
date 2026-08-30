package app

import (
	"reflect"
	"testing"

	"github.com/montanaflynn/envc/internal/sshkey"
)

func TestAllowDeny(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	must(t, a.PrincipalAddKeys("alice", "", []string{alice.pub}, ""))
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, ""))
	must(t, a.GroupSet("eng", []string{"alice"}))

	wantExit(t, a.Allow("local", []string{"nobody"}), ExitUsage, "nobody")
	wantExit(t, a.Allow("local", nil), ExitUsage, "")
	must(t, a.Allow("local", []string{"eng", "alice"}))
	must(t, a.Allow("local", []string{"eng"})) // idempotent
	if got := r.load("local").Access; !reflect.DeepEqual(got, []string{"eng", "alice"}) {
		t.Fatalf("access = %v", got)
	}
	must(t, a.Set("local", "S", secretVal("s")))

	must(t, a.Allow("local", []string{"bob"}))
	f := r.load("local")
	if len(f.Crypto.Recipients) != 2 {
		t.Fatalf("recipients = %v", f.Crypto.Recipients)
	}
	tok := f.Config["S"].Value
	key := f.Crypto.Key

	wantExit(t, a.Deny("local", []string{"carol"}), ExitUsage, "not on access")
	must(t, a.Deny("local", []string{"bob"}))
	f = r.load("local")
	if len(f.Crypto.Recipients) != 1 || f.Config["S"].Value == tok || f.Crypto.Key == key {
		t.Fatal("deny should reencrypt")
	}
	r.useKey(bob)
	_, err := r.open().Get("local", "S")
	wantExit(t, err, ExitDecrypt, "")

	r.useKey(alice)
	// Deny on a file without secrets just saves.
	must(t, a.Unset("local", "S"))
	must(t, a.Deny("local", []string{"alice"}))
	if f := r.load("local"); !reflect.DeepEqual(f.Access, []string{"eng"}) || f.Crypto != nil {
		t.Fatalf("got %+v", f)
	}
}

func TestDenyNoKeyDoesNotWrite(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	r.withPrincipal(a, "bob", bob, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	r.noKey()
	wantExit(t, r.open().Deny("local", []string{"alice"}), ExitDecrypt, "")
	if got := r.load("local").Access; !reflect.DeepEqual(got, []string{"alice", "bob"}) {
		t.Fatalf("access changed on failure: %v", got)
	}
	// Denying the last reader with secrets present is a usage error.
	r.useKey(alice)
	wantExit(t, r.open().Deny("local", []string{"alice", "bob"}), ExitUsage, "no access")
}

func TestWho(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "alice@mac")
	bob := newRSA(t, "")
	a := r.open()
	must(t, a.PrincipalAddKeys("alice", "", []string{alice.pub}, ""))
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"))
	must(t, a.GroupSet("eng", []string{"bob", "alice"}))
	must(t, a.Allow("local", []string{"eng"}))

	w, err := a.Who("local")
	must(t, err)
	if !reflect.DeepEqual(w.Access, []string{"eng"}) || !reflect.DeepEqual(w.Principals, []string{"alice", "bob"}) {
		t.Fatalf("who = %+v", w)
	}
	pk, _ := sshkey.Parse(alice.pub)
	if !reflect.DeepEqual(w.Keys["alice"], []string{sshkey.Fingerprint(pk)}) {
		t.Fatalf("alice keys = %v", w.Keys["alice"])
	}
	if len(w.Keys["bob"]) != 2 || w.Keys["bob"][1][:4] != "age1" {
		t.Fatalf("bob keys = %v", w.Keys["bob"])
	}
}
