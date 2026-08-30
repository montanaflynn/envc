package app

import (
	"strings"
	"testing"

	"github.com/montanaflynn/envc/internal/crypto"
)

func TestSetPublicNeedsNoKeyOrAccess(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	must(t, a.Set("local", "LOG_LEVEL", publicVal("debug")))
	f := r.load("local")
	if f.Config["LOG_LEVEL"].Value != "debug" || f.Config["LOG_LEVEL"].IsSecret() || f.Crypto != nil {
		t.Fatalf("got %+v crypto=%v", f.Config["LOG_LEVEL"], f.Crypto)
	}
	v, err := a.Get("local", "LOG_LEVEL")
	must(t, err)
	if v != "debug" {
		t.Fatalf("Get = %q", v)
	}
}

func TestSetErrors(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	wantExit(t, a.Set("local", "1BAD", publicVal("x")), ExitUsage, "invalid key name")
	wantExit(t, a.Set("local", "NEW", SetOptions{HasValue: true, Value: "x"}), ExitUsage, "--secret or --public")
	wantExit(t, a.Set("local", "NEW", SetOptions{Secret: boolp(false)}), ExitUsage, "value is required")
	wantExit(t, a.Set("local", "S", secretVal("x")), ExitUsage, "no access")
	wantExit(t, a.Set("nope", "S", secretVal("x")), ExitUsage, "unknown environment")
}

func TestSetSecretCreatesEnvelopeAndRoundTrips(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "alice")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")

	must(t, a.Set("local", "DATABASE_URL", secretVal("postgres://x")))
	f := r.load("local")
	e := f.Config["DATABASE_URL"]
	if !crypto.IsToken(e.Value) || !e.IsSecret() {
		t.Fatalf("value not encrypted: %+v", e)
	}
	if f.Crypto == nil || len(f.Crypto.Recipients) != 1 || f.Crypto.Key == "" || f.Crypto.MAC == "" {
		t.Fatalf("bad envelope %+v", f.Crypto)
	}

	// Fresh App: unwrap from disk.
	b := r.open()
	v, err := b.Get("local", "DATABASE_URL")
	must(t, err)
	if v != "postgres://x" {
		t.Fatalf("Get = %q", v)
	}

	// Second secret reuses the key; both decrypt; MAC covers both.
	must(t, b.Set("local", "API_KEY", secretVal("k")))
	vars, err := r.open().Decrypt("local")
	must(t, err)
	if vars["API_KEY"] != "k" || vars["DATABASE_URL"] != "postgres://x" {
		t.Fatalf("Decrypt = %v", vars)
	}
	f2 := r.load("local")
	if f2.Crypto.Key != f.Crypto.Key {
		t.Fatal("adding a secret should not rewrap the data key")
	}
}

func TestSetUpdateKeepsSecretFlag(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("one")))
	must(t, a.Set("local", "S", SetOptions{HasValue: true, Value: "two"}))
	f := r.load("local")
	if !f.Config["S"].IsSecret() || !crypto.IsToken(f.Config["S"].Value) {
		t.Fatalf("flag not kept: %+v", f.Config["S"])
	}
	v, err := r.open().Get("local", "S")
	must(t, err)
	if v != "two" {
		t.Fatalf("Get = %q", v)
	}
}

func TestSetMetadataOnly(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "LOG_LEVEL", publicVal("warn")))
	must(t, a.Set("local", "S", secretVal("sk")))

	// Description on a secret: no key needed.
	r.noKey()
	b := r.open()
	must(t, b.Set("local", "S", SetOptions{Description: strp("the key")}))
	f := r.load("local")
	if f.Config["S"].Description != "the key" || !crypto.IsToken(f.Config["S"].Value) {
		t.Fatalf("got %+v", f.Config["S"])
	}
	// Enum on a public value validated against the current value.
	wantExit(t, b.Set("local", "LOG_LEVEL", SetOptions{Enum: []string{"debug", "info"}}), ExitUsage, "not one of")
	must(t, b.Set("local", "LOG_LEVEL", SetOptions{Enum: []string{"warn", "info"}}))
	// Clearing enum with an empty slice.
	must(t, b.Set("local", "LOG_LEVEL", SetOptions{Enum: []string{}}))
	if f := r.load("local"); len(f.Config["LOG_LEVEL"].Enum) != 0 {
		t.Fatalf("enum not cleared: %+v", f.Config["LOG_LEVEL"])
	}
	// Pattern on a secret needs a key to validate.
	wantExit(t, b.Set("local", "S", SetOptions{Pattern: strp("sk.*")}), ExitDecrypt, "")
	r.useKey(alice)
	must(t, r.open().Set("local", "S", SetOptions{Pattern: strp("sk.*")}))
	wantExit(t, r.open().Set("local", "S", SetOptions{Pattern: strp("^pk")}), ExitUsage, "does not match")
}

func TestSetValidatesEnumAndPattern(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	must(t, a.Set("local", "LOG_LEVEL", SetOptions{Secret: boolp(false), HasValue: true, Value: "warn", Enum: []string{"debug", "warn"}}))
	wantExit(t, a.Set("local", "LOG_LEVEL", SetOptions{HasValue: true, Value: "trace"}), ExitUsage, "not one of")
	wantExit(t, a.Set("local", "URL", SetOptions{Secret: boolp(false), HasValue: true, Value: "http://x", Pattern: strp("^https://")}), ExitUsage, "pattern")
	wantExit(t, a.Set("local", "URL", SetOptions{Secret: boolp(false), HasValue: true, Value: "x", Pattern: strp("(")}), ExitUsage, "invalid regexp")
	if _, ok := r.load("local").Config["URL"]; ok {
		t.Fatal("invalid value was written")
	}
}

func TestSetFlipSecretPublic(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "A", secretVal("a")))
	must(t, a.Set("local", "B", secretVal("b")))

	// secret → public, keeping the value: MAC recomputed over B only.
	must(t, a.Set("local", "A", SetOptions{Secret: boolp(false)}))
	f := r.load("local")
	if f.Config["A"].Value != "a" || f.Config["A"].IsSecret() {
		t.Fatalf("A = %+v", f.Config["A"])
	}
	vars, err := r.open().Decrypt("local")
	must(t, err)
	if vars["A"] != "a" || vars["B"] != "b" {
		t.Fatalf("Decrypt = %v", vars)
	}
	// Last secret → public drops the envelope.
	must(t, a.Set("local", "B", SetOptions{Secret: boolp(false)}))
	if f := r.load("local"); f.Crypto != nil {
		t.Fatal("crypto block should be dropped")
	}
	// public → secret with no value re-encrypts the existing plaintext.
	must(t, a.Set("local", "B", SetOptions{Secret: boolp(true)}))
	f = r.load("local")
	if !crypto.IsToken(f.Config["B"].Value) || f.Crypto == nil {
		t.Fatalf("B = %+v", f.Config["B"])
	}
	if v, _ := r.open().Get("local", "B"); v != "b" {
		t.Fatalf("B = %q", v)
	}
}

func TestUnset(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "P", publicVal("p")))
	must(t, a.Set("local", "A", secretVal("a")))
	must(t, a.Set("local", "B", secretVal("b")))

	wantExit(t, a.Unset("local", "NOPE"), ExitUsage, "no key NOPE")
	must(t, a.Unset("local", "P"))
	must(t, a.Unset("local", "A"))
	f := r.load("local")
	if _, ok := f.Config["A"]; ok {
		t.Fatal("A still present")
	}
	vars, err := r.open().Decrypt("local")
	must(t, err)
	if len(vars) != 1 || vars["B"] != "b" {
		t.Fatalf("Decrypt = %v", vars)
	}
	must(t, a.Unset("local", "B"))
	if f := r.load("local"); f.Crypto != nil {
		t.Fatal("crypto block should be dropped when no secrets remain")
	}
}

func TestGetMissingAndNoKey(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	must(t, a.Set("local", "P", publicVal("p")))
	_, err := a.Get("local", "X")
	wantExit(t, err, ExitUsage, "no key X")

	r.noKey()
	b := r.open()
	if v, err := b.Get("local", "P"); err != nil || v != "p" {
		t.Fatalf("public get without key: %v %q", err, v)
	}
	_, err = b.Get("local", "S")
	wantExit(t, err, ExitDecrypt, "cannot decrypt .envc/environments/local.yaml")
	if !strings.Contains(err.Error(), "recipients") {
		t.Fatalf("error should name recipients: %v", err)
	}
	_, err = b.Decrypt("local")
	wantExit(t, err, ExitDecrypt, "")
}

func TestDecryptChecksPublicEnumAndPlaintext(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "L", SetOptions{Secret: boolp(false), HasValue: true, Value: "a", Enum: []string{"a", "b"}}))
	must(t, a.Set("local", "S", secretVal("s")))

	// Hand-edit the public value out of its enum.
	f := r.load("local")
	e := f.Config["L"]
	e.Value = "zzz"
	f.Config["L"] = e
	must(t, f.Save(r.root+"/.envc/environments/local.yaml"))
	_, err := r.open().Decrypt("local")
	wantExit(t, err, ExitUsage, "config.L.enum")

	// Hand-edit a secret to plaintext: Decrypt refuses, Rewrap fixes.
	e = f.Config["L"]
	e.Value = "a"
	f.Config["L"] = e
	s := f.Config["S"]
	s.Value = "plain"
	f.Config["S"] = s
	must(t, f.Save(r.root+"/.envc/environments/local.yaml"))
	_, err = r.open().Decrypt("local")
	wantExit(t, err, ExitUsage, "envc ensure")
}

func TestDryRunSetWritesNothing(t *testing.T) {
	r := newRepo(t)
	r.dryRun = true
	a := r.open()
	must(t, a.Set("local", "P", publicVal("p")))
	if _, ok := r.load("local").Config["P"]; ok {
		t.Fatal("dry-run wrote the file")
	}
}

// get KEY validates only KEY: an unrelated key's enum/pattern violation must
// not hide this value. Decrypt/Resolve still validate the whole file.
func TestGetValidatesOnlyRequestedKey(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("sk-1")))
	must(t, a.Set("local", "L", SetOptions{Secret: boolp(false), HasValue: true, Value: "a", Enum: []string{"a", "b"}}))

	// Hand-edit L outside its enum.
	f := r.load("local")
	e := f.Config["L"]
	e.Value = "zzz"
	f.Config["L"] = e
	r.save("local", f)

	if v, err := a.Get("local", "S"); err != nil || v != "sk-1" {
		t.Fatalf("Get S with unrelated violation: %v %q", err, v)
	}
	_, err := a.Get("local", "L")
	wantExit(t, err, ExitUsage, "not one of")
	_, err = a.Decrypt("local")
	wantExit(t, err, ExitUsage, "config.L.enum")

	// The requested secret's own pattern is still enforced.
	f = r.load("local")
	e = f.Config["S"]
	e.Pattern = "^pk"
	f.Config["S"] = e
	r.save("local", f)
	_, err = a.Get("local", "S")
	wantExit(t, err, ExitUsage, "does not match")
}

// A metadata-only set on a secret must not re-encrypt its token (a fresh
// nonce would show up as a spurious ciphertext change in git).
func TestSetMetadataOnlyKeepsToken(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("sk-1")))
	f := r.load("local")
	tok, mac, key := f.Config["S"].Value, f.Crypto.MAC, f.Crypto.Key

	must(t, a.Set("local", "S", SetOptions{Pattern: strp("sk.*")}))
	must(t, a.Set("local", "S", SetOptions{Enum: []string{"sk-1", "sk-2"}}))
	must(t, a.Set("local", "S", SetOptions{Description: strp("d")}))
	f = r.load("local")
	if f.Config["S"].Value != tok {
		t.Fatal("metadata-only set re-encrypted the token")
	}
	if f.Crypto.MAC != mac || f.Crypto.Key != key {
		t.Fatalf("metadata-only set churned the envelope: %+v", f.Crypto)
	}
	if f.Config["S"].Pattern != "sk.*" || len(f.Config["S"].Enum) != 2 || f.Config["S"].Description != "d" {
		t.Fatalf("metadata not applied: %+v", f.Config["S"])
	}
	if v, err := r.open().Get("local", "S"); err != nil || v != "sk-1" {
		t.Fatalf("Get: %v %q", err, v)
	}
	// Setting a value (even the same one) does mint a new token.
	must(t, a.Set("local", "S", SetOptions{HasValue: true, Value: "sk-1"}))
	if r.load("local").Config["S"].Value == tok {
		t.Fatal("set with a value kept the old token")
	}
}

func TestPatternAnchored(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "N", SetOptions{Secret: boolp(false), HasValue: true, Value: "123", Pattern: strp("[0-9]+")}))
	err := a.Set("local", "N", SetOptions{HasValue: true, Value: "a1b"})
	wantExit(t, err, ExitUsage, "pattern")
	err = a.Set("local", "U", SetOptions{Secret: boolp(false), HasValue: true, Value: "xpostgres://h", Pattern: strp("postgres(ql)?://.*")})
	wantExit(t, err, ExitUsage, "pattern")
	must(t, a.Set("local", "U", SetOptions{Secret: boolp(false), HasValue: true, Value: "postgres://h", Pattern: strp("postgres(ql)?://.*")}))
}
