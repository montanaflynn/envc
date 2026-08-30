package app

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/sshkey"
)

func TestDataKeyErrors(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	_, err := a.DataKey("local")
	wantExit(t, err, ExitDecrypt, "no envelope")

	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))

	// Wrong key → ErrNoIdentity (FindIdentities filters on fingerprint).
	r.useKey(bob)
	_, err = r.open().DataKey("local")
	wantExit(t, err, ExitDecrypt, "")
	if !errors.Is(err, crypto.ErrNoIdentity) {
		t.Fatalf("want ErrNoIdentity, got %v", err)
	}

	// Malformed ENVC_PRIVATE_KEY → decrypt error naming the source.
	r.env["ENVC_PRIVATE_KEY"] = "garbage"
	_, err = r.open().DataKey("local")
	wantExit(t, err, ExitDecrypt, "ENVC_PRIVATE_KEY")

	// Tampered envelope.
	r.useKey(alice)
	f := r.load("local")
	f.Crypto.Key = "AAAA"
	r.save("local", f)
	_, err = r.open().DataKey("local")
	wantExit(t, err, ExitDecrypt, "")
}

func TestDataKeyViaFileAndHome(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))

	r.noKey()
	r.write("home/.ssh/id_ed25519", alice.priv)
	if v, err := r.open().Get("local", "S"); err != nil || v != "s" {
		t.Fatalf("~/.ssh/id_ed25519 via HOME: %v %q", err, v)
	}
	r.write("keyfile", alice.priv)
	r.env["HOME"] = t.TempDir()
	r.env["ENVC_PRIVATE_KEY_FILE"] = r.root + "/keyfile"
	if v, err := r.open().Get("local", "S"); err != nil || v != "s" {
		t.Fatalf("ENVC_PRIVATE_KEY_FILE: %v %q", err, v)
	}
}

func TestRSAKeyWorks(t *testing.T) {
	r := newRepo(t)
	kp := newRSA(t, "rsa")
	r.useKey(kp)
	a := r.open()
	r.withPrincipal(a, "ci", kp, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	if v, err := r.open().Get("local", "S"); err != nil || v != "s" {
		t.Fatalf("rsa: %v %q", err, v)
	}
}

func TestMACTamperDetected(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "A", secretVal("a")))
	must(t, a.Set("local", "B", secretVal("b")))

	// Swap tokens between keys is caught by AES-GCM AAD; swapping the MAC
	// bytes is caught by verifyMAC. Simulate a hand-deleted secret: MAC no
	// longer covers the set.
	f := r.load("local")
	delete(f.Config, "A")
	r.save("local", f)
	_, err := r.open().Decrypt("local")
	wantExit(t, err, ExitDecrypt, "")
	if !errors.Is(err, crypto.ErrBadMAC) {
		t.Fatalf("want ErrBadMAC, got %v", err)
	}
	// Reencrypt and Rewrap refuse too.
	wantExit(t, r.open().rekey("local"), ExitDecrypt, "")
	wantExit(t, r.open().rewrap("local"), ExitDecrypt, "")
}

func TestRewrap(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	bob := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.PrincipalAddKeys("bob", "", []string{bob.pub}, ""))

	// No secrets: rewrap is a no-op that keeps no envelope.
	must(t, a.rewrap("local"))
	if r.load("local").Crypto != nil {
		t.Fatal("envelope without secrets")
	}

	// Hand-written plaintext secret, no envelope: rewrap encrypts it.
	f := r.load("local")
	f.Config["S"] = envfile.Entry{Secret: boolp(true), Value: "plain"}
	r.save("local", f)
	must(t, a.rewrap("local"))
	f = r.load("local")
	if !crypto.IsToken(f.Config["S"].Value) || f.Crypto == nil {
		t.Fatalf("plaintext not encrypted: %+v", f)
	}
	if r.stderr.Len() != 0 {
		t.Fatalf("app wrote to stderr: %q", r.stderr.String())
	}
	key1, mac1 := f.Crypto.Key, f.Crypto.MAC

	// Same recipients: rewrap still wraps afresh (see TestRewrapAlwaysRewraps)
	// but the data key, tokens and MAC are untouched.
	must(t, a.rewrap("local"))
	if g := r.load("local"); g.Crypto.Key == key1 || g.Crypto.MAC != mac1 || g.Config["S"].Value != f.Config["S"].Value {
		t.Fatalf("rewrap with unchanged recipients: %+v", g.Crypto)
	}

	// Hand-edit access to add bob: rewrap adds him; bob can now read; tokens unchanged.
	tok := f.Config["S"].Value
	f = r.load("local")
	f.Access = append(f.Access, "bob")
	r.save("local", f)
	must(t, r.open().rewrap("local"))
	f = r.load("local")
	if len(f.Crypto.Recipients) != 2 || f.Config["S"].Value != tok {
		t.Fatalf("after rewrap: %+v", f.Crypto)
	}
	r.useKey(bob)
	if v, err := r.open().Get("local", "S"); err != nil || v != "plain" {
		t.Fatalf("bob: %v %q", err, v)
	}

	// Plaintext secret added by hand next to encrypted ones: rewrap encrypts
	// it and warns that the MAC was not verified.
	f = r.load("local")
	f.Config["T"] = envfile.Entry{Secret: boolp(true), Value: "t"}
	r.save("local", f)
	r.stderr.Reset()
	must(t, r.open().rewrap("local"))
	if r.stderr.Len() != 0 {
		t.Fatalf("app wrote to stderr: %q", r.stderr.String())
	}
	vars, err := r.open().Decrypt("local")
	must(t, err)
	if vars["T"] != "t" || vars["S"] != "plain" {
		t.Fatalf("Decrypt = %v", vars)
	}

	// Empty access with secrets: usage error.
	f = r.load("local")
	f.Access = []string{}
	r.save("local", f)
	wantExit(t, r.open().rewrap("local"), ExitUsage, "no access")
	// Unknown access name.
	f.Access = []string{"ghost"}
	r.save("local", f)
	wantExit(t, r.open().rewrap("local"), ExitUsage, "ghost")
}

func TestReencrypt(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	before := r.load("local")
	k1, err := a.DataKey("local")
	must(t, err)

	must(t, a.rekey("local"))
	after := r.load("local")
	if after.Config["S"].Value == before.Config["S"].Value || after.Crypto.Key == before.Crypto.Key || after.Crypto.MAC == before.Crypto.MAC {
		t.Fatal("reencrypt did not rotate")
	}
	k2, err := a.DataKey("local")
	must(t, err)
	if k1 == k2 {
		t.Fatal("cache not updated")
	}
	if v, err := r.open().Get("local", "S"); err != nil || v != "s" {
		t.Fatalf("after reencrypt: %v %q", err, v)
	}
	// Without secrets it behaves like rewrap.
	must(t, a.Unset("local", "S"))
	must(t, a.rekey("local"))
	if r.load("local").Crypto != nil {
		t.Fatal("envelope without secrets")
	}
}

// fingerprint returns the recipient ID of an SSH public key line.
func fingerprint(t *testing.T, pub string) string {
	t.Helper()
	pk, err := sshkey.Parse(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshkey.Fingerprint(pk)
}

// A hand edit that removes a reader from both access and the envelope recipients
// leaves the envelope key wrapped to them; the explicit rewrap must not take the
// recipients list at its word.
func TestRewrapAlwaysRewraps(t *testing.T) {
	r := newRepo(t)
	alice, bob := newEd25519(t, ""), newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	r.withPrincipal(a, "bob", bob, "local")
	must(t, a.Set("local", "S", secretVal("s")))

	f := r.load("local")
	f.Access = []string{"alice"}
	f.Crypto.Recipients = remove(f.Crypto.Recipients, fingerprint(t, bob.pub))
	r.save("local", f)
	keyBefore, tok := f.Crypto.Key, f.Config["S"].Value

	// The edit is consistent, so check is clean, yet the envelope key still opens
	// for bob (envc's own identity filter hides that; age does not).
	probs, err := r.open().inspect("local")
	must(t, err)
	if len(probs) != 0 {
		t.Fatalf("check: %v", probs)
	}
	bobOpens := func() bool {
		t.Helper()
		f := r.load("local")
		wrapped, err := base64.StdEncoding.DecodeString(f.Crypto.Key)
		must(t, err)
		ids, err := crypto.FindIdentities(crypto.IdentityOptions{
			Getenv: func(k string) string { return map[string]string{"ENVC_PRIVATE_KEY": bob.priv}[k] },
			Home:   t.TempDir(),
		}, nil)
		must(t, err)
		_, err = crypto.Unwrap(wrapped, ids)
		return err == nil
	}
	if !bobOpens() {
		t.Fatal("precondition: the envelope key should still open for bob after the hand edit")
	}

	r.useKey(alice)
	must(t, r.open().rewrap("local"))
	f = r.load("local")
	if f.Crypto.Key == keyBefore {
		t.Fatal("rewrap kept the envelope key")
	}
	if f.Config["S"].Value != tok {
		t.Fatal("rewrap re-encrypted the token")
	}
	if len(f.Crypto.Recipients) != 1 || f.Crypto.Recipients[0] != fingerprint(t, alice.pub) {
		t.Fatalf("recipients = %v", f.Crypto.Recipients)
	}
	if bobOpens() {
		t.Fatal("removed reader can still unwrap the envelope key after rewrap")
	}
	r.useKey(bob)
	_, err = r.open().Get("local", "S")
	wantExit(t, err, ExitDecrypt, "")
	r.useKey(alice)
	if v, err := r.open().Get("local", "S"); err != nil || v != "s" {
		t.Fatalf("alice: %v %q", err, v)
	}
}

// One invocation touching several environments wrapped to the same
// passphrase-protected key asks for the passphrase once (README → Encryption).
func TestPassphrasePromptedOncePerInvocation(t *testing.T) {
	r := newRepo(t)
	const passphrase = "hunter2"
	alice := newEncryptedEd25519(t, passphrase)
	plain := newEd25519(t, "")
	// Build the envs with an unencrypted helper key so setup never prompts.
	r.useKey(plain)
	a := r.open()
	must(t, a.EnvAdd("prod", EnvAddOptions{}))
	must(t, a.PrincipalAddKeys("alice", "", []string{alice.pub}, ""))
	must(t, a.PrincipalAddKeys("helper", "", []string{plain.pub}, ""))
	for _, env := range []string{"local", "prod"} {
		must(t, a.Allow(env, []string{"alice", "helper"}))
		must(t, a.Set(env, "S", secretVal("secret-"+env)))
	}

	// Now alice's encrypted key is the only identity, found under ~/.ssh.
	r.noKey()
	r.write(filepath.Join("home", ".ssh", "id_ed25519"), alice.priv)
	prompts := 0
	opts := r.options()
	opts.IsTTY = true
	opts.Prompt = func(text string) (string, error) {
		prompts++
		if text != "Passphrase for ~/.ssh/id_ed25519: " {
			t.Errorf("prompt = %q", text)
		}
		return passphrase, nil
	}
	b, err := Open(opts)
	must(t, err)
	for _, env := range []string{"local", "prod"} {
		v, err := b.Get(env, "S")
		if err != nil || v != "secret-"+env {
			t.Fatalf("Get(%s): %v %q", env, err, v)
		}
	}
	if prompts != 1 {
		t.Fatalf("prompted %d times across two environments, want 1", prompts)
	}
	// A bulk operation that reseals every environment asks once too.
	prompts = 0
	c, err := Open(opts)
	must(t, err)
	if _, err := c.PrincipalRemove("helper"); err != nil {
		t.Fatal(err)
	}
	if prompts != 1 {
		t.Fatalf("prompted %d times for principal rm across two environments, want 1", prompts)
	}
}
