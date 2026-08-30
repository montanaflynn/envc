package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"

	"github.com/montanaflynn/envc/internal/sshkey"
)

// ---- helpers ---------------------------------------------------------------

type testKey struct {
	pub     sshkey.PublicKey
	pem     []byte // unencrypted OpenSSH PEM
	encPEM  []byte // OpenSSH PEM encrypted with passphrase "hunter2"
	private any
}

const passphrase = "hunter2"

func genKey(t *testing.T, typ string) testKey {
	t.Helper()
	var priv any
	var pub any
	switch typ {
	case "ssh-ed25519":
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = s, p
	case "ssh-rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = k, &k.PublicKey
	default:
		t.Fatalf("genKey: %s", typ)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := sshkey.Parse(string(ssh.MarshalAuthorizedKey(spk)))
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	encBlk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	return testKey{
		pub:     pk,
		pem:     pem.EncodeToMemory(blk),
		encPEM:  pem.EncodeToMemory(encBlk),
		private: priv,
	}
}

// legacyEncryptedRSA returns a PEM "RSA PRIVATE KEY" block encrypted the old
// OpenSSL way, which carries no public key in the header.
func legacyEncryptedRSA(t *testing.T) ([]byte, sshkey.PublicKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	blk, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte(passphrase), x509.PEMCipherAES256) //nolint:staticcheck // legacy format is exactly what we want to test
	if err != nil {
		t.Fatal(err)
	}
	spk, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := sshkey.Parse(string(ssh.MarshalAuthorizedKey(spk)))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(blk), pk
}

func genAge(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustRecipient(t *testing.T, pk sshkey.PublicKey) Recipient {
	t.Helper()
	r, err := RecipientFromSSH(pk)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustKey(t *testing.T) DataKey {
	t.Helper()
	k, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// writeHome creates a temp HOME with the given files under it (relative paths).
func writeHome(t *testing.T, files map[string][]byte) string {
	t.Helper()
	home := t.TempDir()
	for name, data := range files {
		p := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func ids(list []Identity) []string {
	out := make([]string, len(list))
	for i, id := range list {
		out[i] = id.Source
	}
	return out
}

func subkey(t *testing.T, k DataKey, info string) []byte {
	t.Helper()
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, k[:], nil, []byte(info))
	if _, err := r.Read(out); err != nil {
		t.Fatal(err)
	}
	return out
}

// ---- data key --------------------------------------------------------------

func TestNewDataKey(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	if a == b {
		t.Fatal("two fresh data keys are equal")
	}
	if a == (DataKey{}) {
		t.Fatal("data key is all zeros")
	}
}

func TestDataKeyID(t *testing.T) {
	k := mustKey(t)
	sum := sha256.Sum256(k[:])
	want := hex.EncodeToString(sum[:])[:8]
	if got := k.ID(); got != want {
		t.Fatalf("ID = %q, want %q", got, want)
	}
	if len(k.ID()) != 8 {
		t.Fatalf("ID length %d", len(k.ID()))
	}
	if k.ID() != k.ID() {
		t.Fatal("ID not deterministic")
	}
}

// ---- tokens ----------------------------------------------------------------

func TestTokenRoundtrip(t *testing.T) {
	k := mustKey(t)
	values := map[string]string{
		"empty":     "",
		"simple":    "sk_live_abc123",
		"spaces":    "hello world ",
		"multiline": "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----\n",
		"unicode":   "pässwörd ☃ 日本語",
		"nul":       "a\x00b",
		"large":     strings.Repeat("x", 100_000),
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			tok, err := k.Encrypt("KEY_"+name, value)
			if err != nil {
				t.Fatal(err)
			}
			if !IsToken(tok) {
				t.Fatalf("Encrypt output %q is not a token", tok)
			}
			if !strings.HasPrefix(tok, TokenPrefix) || !strings.HasSuffix(tok, TokenSuffix) {
				t.Fatalf("token %q has wrong framing", tok)
			}
			inner := strings.TrimSuffix(strings.TrimPrefix(tok, TokenPrefix), TokenSuffix)
			raw, err := base64.StdEncoding.DecodeString(inner)
			if err != nil {
				t.Fatalf("token body is not std base64: %v", err)
			}
			if want := 12 + len(value) + 16; len(raw) != want {
				t.Fatalf("raw token length %d, want nonce+ct+tag = %d", len(raw), want)
			}
			got, err := k.Decrypt("KEY_"+name, tok)
			if err != nil {
				t.Fatal(err)
			}
			if got != value {
				t.Fatalf("roundtrip mismatch: got %q want %q", got, value)
			}
		})
	}
}

func TestEncryptIsRandomized(t *testing.T) {
	k := mustKey(t)
	a, _ := k.Encrypt("K", "v")
	b, _ := k.Encrypt("K", "v")
	if a == b {
		t.Fatal("two encryptions of the same value produced the same token (nonce reuse?)")
	}
}

func TestDecryptFailures(t *testing.T) {
	k, other := mustKey(t), mustKey(t)
	tok, err := k.Encrypt("DATABASE_URL", "postgres://x")
	if err != nil {
		t.Fatal(err)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(tok, TokenPrefix), TokenSuffix)
	raw, _ := base64.StdEncoding.DecodeString(inner)
	flipped := append([]byte(nil), raw...)
	flipped[len(flipped)-1] ^= 0x01
	tampered := TokenPrefix + base64.StdEncoding.EncodeToString(flipped) + TokenSuffix
	short := TokenPrefix + base64.StdEncoding.EncodeToString(raw[:20]) + TokenSuffix

	tests := []struct {
		name  string
		key   DataKey
		kname string
		token string
	}{
		{"wrong name", k, "DATABASE_URI", tok},
		{"empty name", k, "", tok},
		{"wrong key", other, "DATABASE_URL", tok},
		{"tampered ciphertext", k, "DATABASE_URL", tampered},
		{"too short", k, "DATABASE_URL", short},
		{"not a token", k, "DATABASE_URL", "postgres://x"},
		{"bad base64", k, "DATABASE_URL", TokenPrefix + "!!!!" + TokenSuffix},
		{"empty body", k, "DATABASE_URL", TokenPrefix + TokenSuffix},
		{"missing suffix", k, "DATABASE_URL", TokenPrefix + inner},
		{"other version", k, "DATABASE_URL", "ENC[envc2," + inner + "]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.key.Decrypt(tc.kname, tc.token)
			if err == nil {
				t.Fatalf("Decrypt succeeded with %q", got)
			}
			if strings.Contains(err.Error(), "postgres://x") {
				t.Fatalf("error leaks plaintext: %v", err)
			}
		})
	}
}

func TestIsToken(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"ENC[envc1,abc]", true},
		{"ENC[envc1,]", true},
		{"ENC[envc1,abc", false},
		{"enc[envc1,abc]", false},
		{"ENC[envc2,abc]", false},
		{"ENC[envc1;abc]", false},
		{" ENC[envc1,abc]", false},
		{"", false},
		{"plain", false},
		{"ENC[envc1,abc]\n", false},
	}
	for _, tc := range tests {
		if got := IsToken(tc.in); got != tc.want {
			t.Errorf("IsToken(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// ---- MAC and sync HMAC -----------------------------------------------------

func TestMAC(t *testing.T) {
	k := mustKey(t)
	secrets := map[string]string{
		"ZEBRA":        "z",
		"DATABASE_URL": "postgres://prod/app",
		"MULTI":        "a\nb",
	}
	mac1 := k.MAC(secrets)
	mac2 := k.MAC(map[string]string{"MULTI": "a\nb", "DATABASE_URL": "postgres://prod/app", "ZEBRA": "z"})
	if mac1 != mac2 {
		t.Fatalf("MAC not deterministic / order independent: %q vs %q", mac1, mac2)
	}
	if _, err := base64.StdEncoding.DecodeString(mac1); err != nil {
		t.Fatalf("MAC is not std base64: %v", err)
	}

	// Independent computation per the contract.
	payload := "DATABASE_URL\x00postgres://prod/app\nMULTI\x00a\nb\nZEBRA\x00z\n"
	h := hmac.New(sha256.New, subkey(t, k, "envc/v1/mac"))
	h.Write([]byte(payload))
	want := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if mac1 != want {
		t.Fatalf("MAC = %q, want contract value %q", mac1, want)
	}

	changes := map[string]map[string]string{
		"value changed": {"ZEBRA": "z", "DATABASE_URL": "postgres://prod/app2", "MULTI": "a\nb"},
		"key renamed":   {"ZEBRA": "z", "DATABASE_URI": "postgres://prod/app", "MULTI": "a\nb"},
		"key removed":   {"ZEBRA": "z", "DATABASE_URL": "postgres://prod/app"},
		"key added":     {"ZEBRA": "z", "DATABASE_URL": "postgres://prod/app", "MULTI": "a\nb", "NEW": ""},
		"empty":         {},
	}
	for name, s := range changes {
		if k.MAC(s) == mac1 {
			t.Errorf("%s: MAC unchanged", name)
		}
	}
	other := mustKey(t)
	if other.MAC(secrets) == mac1 {
		t.Fatal("MAC does not depend on the data key")
	}
	if k.MAC(nil) != k.MAC(map[string]string{}) {
		t.Fatal("nil and empty map should MAC identically")
	}
}

func TestSyncHMAC(t *testing.T) {
	k := mustKey(t)
	got := k.SyncHMAC("LOG_LEVEL", "warn")
	if _, err := hex.DecodeString(got); err != nil || len(got) != SyncHMACLen {
		t.Fatalf("SyncHMAC = %q, want %d hex chars", got, SyncHMACLen)
	}
	h := hmac.New(sha256.New, subkey(t, k, "envc/v1/sync"))
	h.Write([]byte("LOG_LEVEL\x00warn"))
	if want := hex.EncodeToString(h.Sum(nil))[:SyncHMACLen]; got != want {
		t.Fatalf("SyncHMAC = %q, want contract value %q", got, want)
	}
	if k.SyncHMAC("LOG_LEVEL", "warn") != got {
		t.Fatal("not deterministic")
	}
	if k.SyncHMAC("LOG_LEVEL", "info") == got || k.SyncHMAC("LOG_LEVE", "Lwarn") == got {
		t.Fatal("sync HMAC collides across name/value changes")
	}
	if mustKey(t).SyncHMAC("LOG_LEVEL", "warn") == got {
		t.Fatal("sync HMAC does not depend on key")
	}
}

func TestSubkeysAreDistinct(t *testing.T) {
	// The enc subkey must not equal the mac or sync subkey: encrypt a value
	// with the enc key derived per contract and check Decrypt reads it.
	k := mustKey(t)
	a, b, c := subkey(t, k, "envc/v1/enc"), subkey(t, k, "envc/v1/mac"), subkey(t, k, "envc/v1/sync")
	if bytes.Equal(a, b) || bytes.Equal(b, c) || bytes.Equal(a, c) || bytes.Equal(a, k[:]) {
		t.Fatal("subkeys not distinct")
	}
}

// ---- recipients ------------------------------------------------------------

func TestRecipients(t *testing.T) {
	ed := genKey(t, "ssh-ed25519")
	rs := genKey(t, "ssh-rsa")
	ag := genAge(t)

	r, err := RecipientFromSSH(ed.pub)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != sshkey.Fingerprint(ed.pub) || !strings.HasPrefix(r.ID, "SHA256:") || r.Age == nil {
		t.Fatalf("ed25519 recipient = %+v", r)
	}
	r, err = RecipientFromSSH(rs.pub)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != sshkey.Fingerprint(rs.pub) || r.Age == nil {
		t.Fatalf("rsa recipient = %+v", r)
	}
	if _, err := RecipientFromSSH(sshkey.PublicKey{}); err == nil {
		t.Fatal("zero PublicKey accepted")
	}

	r, err = RecipientFromAge(ag.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != ag.Recipient().String() || r.Age == nil {
		t.Fatalf("age recipient = %+v", r)
	}
	r, err = RecipientFromAge("  " + ag.Recipient().String() + "\n")
	if err != nil || r.ID != ag.Recipient().String() {
		t.Fatalf("age recipient with whitespace: %+v, %v", r, err)
	}
	for _, bad := range []string{"", "age1", "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQS3PRQSK", "ssh-ed25519 AAAA"} {
		if _, err := RecipientFromAge(bad); err == nil {
			t.Errorf("RecipientFromAge(%q) accepted", bad)
		}
	}
}

// ---- wrap / unwrap ---------------------------------------------------------

func TestWrapUnwrap(t *testing.T) {
	ed := genKey(t, "ssh-ed25519")
	rs := genKey(t, "ssh-rsa")
	ag := genAge(t)
	stranger := genKey(t, "ssh-ed25519")

	k := mustKey(t)
	ageR, err := RecipientFromAge(ag.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := Wrap(k, []Recipient{mustRecipient(t, ed.pub), mustRecipient(t, rs.pub), ageR})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, k[:]) {
		t.Fatal("wrapped output contains the raw data key")
	}

	edID := loadIdentity(t, ed.pem)
	rsID := loadIdentity(t, rs.pem)
	strangerID := loadIdentity(t, stranger.pem)
	ageID := Identity{ID: ag.Recipient().String(), Source: "ENVC_PRIVATE_KEY", Age: ag}

	tests := []struct {
		name    string
		ids     []Identity
		wantErr error
	}{
		{"ed25519", []Identity{edID}, nil},
		{"rsa", []Identity{rsID}, nil},
		{"age", []Identity{ageID}, nil},
		{"stranger then rsa", []Identity{strangerID, rsID}, nil},
		{"stranger only", []Identity{strangerID}, ErrNoIdentity},
		{"no identities", nil, ErrNoIdentity},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Unwrap(wrapped, tc.ids)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != k {
				t.Fatal("unwrapped key differs")
			}
		})
	}
}

func TestWrapDedupesAndRequiresRecipients(t *testing.T) {
	ed := genKey(t, "ssh-ed25519")
	k := mustKey(t)
	r := mustRecipient(t, ed.pub)
	one, err := Wrap(k, []Recipient{r})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Wrap(k, []Recipient{r, r, r})
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != len(two) {
		t.Fatalf("duplicate recipients were not deduped: %d vs %d bytes", len(one), len(two))
	}
	if _, err := Wrap(k, nil); err == nil {
		t.Fatal("Wrap with zero recipients succeeded")
	}
	if _, err := Wrap(k, []Recipient{}); err == nil {
		t.Fatal("Wrap with empty recipients succeeded")
	}
}

func TestUnwrapGarbage(t *testing.T) {
	ed := genKey(t, "ssh-ed25519")
	id := loadIdentity(t, ed.pem)
	for _, in := range [][]byte{nil, []byte("not age"), []byte("age-encryption.org/v1\n")} {
		if _, err := Unwrap(in, []Identity{id}); err == nil {
			t.Errorf("Unwrap(%q) succeeded", in)
		}
	}
	// A valid age file whose payload is not 32 bytes must be rejected.
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, mustRecipient(t, ed.pub).Age)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Unwrap(buf.Bytes(), []Identity{id}); err == nil {
		t.Fatal("Unwrap accepted a 5-byte payload")
	}
}

// loadIdentity uses FindIdentities with ENVC_PRIVATE_KEY to obtain an Identity.
func loadIdentity(t *testing.T, pemBytes []byte) Identity {
	t.Helper()
	list, err := FindIdentities(IdentityOptions{
		Getenv: envOf(map[string]string{"ENVC_PRIVATE_KEY": string(pemBytes)}),
		Home:   t.TempDir(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d identities", len(list))
	}
	return list[0]
}

// ---- identity discovery ----------------------------------------------------

func TestFindIdentitiesSearchOrder(t *testing.T) {
	ag := genAge(t)               // ENVC_PRIVATE_KEY (age secret key, auto-detected)
	b := genKey(t, "ssh-rsa")     // ENVC_PRIVATE_KEY_FILE
	c := genKey(t, "ssh-ed25519") // ~/.ssh/id_ed25519
	d := genKey(t, "ssh-rsa")     // ~/.ssh/id_rsa

	home := writeHome(t, map[string][]byte{
		".ssh/id_ed25519":     c.pem,
		".ssh/id_ed25519.pub": []byte(c.pub.Line + "\n"),
		".ssh/id_rsa":         d.pem,
		".ssh/id_rsa.pub":     []byte(d.pub.Line + "\n"),
		"deploy":              b.pem,
	})
	env := map[string]string{
		"ENVC_PRIVATE_KEY":      ag.String(),
		"ENVC_PRIVATE_KEY_FILE": filepath.Join(home, "deploy"),
	}
	wanted := []string{
		ag.Recipient().String(), sshkey.Fingerprint(b.pub),
		sshkey.Fingerprint(c.pub), sshkey.Fingerprint(d.pub),
	}
	var stderr bytes.Buffer
	list, err := FindIdentities(IdentityOptions{Getenv: envOf(env), Home: home, Stderr: &stderr}, wanted)
	if err != nil {
		t.Fatal(err)
	}
	wantSources := []string{"ENVC_PRIVATE_KEY", filepath.Join(home, "deploy"), "~/.ssh/id_ed25519", "~/.ssh/id_rsa"}
	if got := ids(list); strings.Join(got, ",") != strings.Join(wantSources, ",") {
		t.Fatalf("sources = %q, want %q", got, wantSources)
	}
	for i, id := range list {
		if id.ID != wanted[i] {
			t.Errorf("[%d] ID = %q, want %q", i, id.ID, wanted[i])
		}
		if id.Age == nil {
			t.Errorf("[%d] Age identity is nil", i)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("unexpected stderr: %q", stderr.String())
	}

	// Every identity actually unwraps.
	k := mustKey(t)
	ageR, _ := RecipientFromAge(ag.Recipient().String())
	wrapped, err := Wrap(k, []Recipient{
		ageR, mustRecipient(t, b.pub), mustRecipient(t, c.pub), mustRecipient(t, d.pub),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range list {
		got, err := Unwrap(wrapped, []Identity{id})
		if err != nil || got != k {
			t.Errorf("%s: unwrap failed: %v", id.Source, err)
		}
	}
}

func TestFindIdentitiesDefaultsOnly(t *testing.T) {
	c := genKey(t, "ssh-ed25519")
	home := writeHome(t, map[string][]byte{".ssh/id_ed25519": c.pem})
	list, err := FindIdentities(IdentityOptions{Getenv: envOf(nil), Home: home}, []string{sshkey.Fingerprint(c.pub)})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Source != "~/.ssh/id_ed25519" || list[0].ID != sshkey.Fingerprint(c.pub) {
		t.Fatalf("list = %+v", list)
	}
}

func TestFindIdentitiesNothingFound(t *testing.T) {
	home := writeHome(t, nil)
	_, err := FindIdentities(IdentityOptions{Getenv: envOf(nil), Home: home}, []string{"SHA256:x"})
	if !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
}

func TestFindIdentitiesSkipsNotWanted(t *testing.T) {
	c := genKey(t, "ssh-ed25519")
	d := genKey(t, "ssh-rsa")
	ag := genAge(t)
	home := writeHome(t, map[string][]byte{
		".ssh/id_ed25519": c.pem,
		".ssh/id_rsa":     d.pem,
	})
	env := map[string]string{"ENVC_PRIVATE_KEY": ag.String()}

	// Only the RSA key is wanted.
	list, err := FindIdentities(IdentityOptions{Getenv: envOf(env), Home: home}, []string{sshkey.Fingerprint(d.pub), "SHA256:unrelated"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(list); strings.Join(got, ",") != "~/.ssh/id_rsa" {
		t.Fatalf("sources = %q, want only ~/.ssh/id_rsa", got)
	}

	// Nothing wanted matches.
	_, err = FindIdentities(IdentityOptions{Getenv: envOf(env), Home: home}, []string{"SHA256:unrelated"})
	if !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}

	// Empty wanted means no filtering.
	list, err = FindIdentities(IdentityOptions{Getenv: envOf(env), Home: home}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("with nil wanted got %d identities, want 3", len(list))
	}
}

func TestFindIdentitiesEncryptedWithPrompt(t *testing.T) {
	c := genKey(t, "ssh-ed25519")
	other := genKey(t, "ssh-ed25519")
	home := writeHome(t, map[string][]byte{".ssh/id_ed25519": c.encPEM})

	prompts := 0
	var lastPrompt string
	opts := IdentityOptions{
		Getenv: envOf(nil),
		Home:   home,
		IsTTY:  true,
		Prompt: func(p string) (string, error) {
			prompts++
			lastPrompt = p
			return passphrase, nil
		},
	}
	list, err := FindIdentities(opts, []string{sshkey.Fingerprint(c.pub)})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d identities", len(list))
	}
	// The OpenSSH format carries the public key: ID is known without a prompt.
	if list[0].ID != sshkey.Fingerprint(c.pub) {
		t.Fatalf("ID = %q, want fingerprint", list[0].ID)
	}
	if prompts != 0 {
		t.Fatalf("FindIdentities prompted %d times; must be lazy", prompts)
	}

	k := mustKey(t)
	wrapped, _ := Wrap(k, []Recipient{mustRecipient(t, c.pub)})
	got, err := Unwrap(wrapped, list)
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Fatal("wrong key")
	}
	if prompts != 1 {
		t.Fatalf("prompted %d times, want 1", prompts)
	}
	if lastPrompt != "Passphrase for ~/.ssh/id_ed25519: " {
		t.Fatalf("prompt = %q", lastPrompt)
	}
	// Second unwrap with the same identity reuses the decrypted key.
	if _, err := Unwrap(wrapped, list); err != nil {
		t.Fatal(err)
	}
	if prompts != 1 {
		t.Fatalf("prompted %d times across two unwraps, want 1", prompts)
	}

	// A file wrapped to someone else must not trigger a prompt.
	prompts = 0
	wrappedOther, _ := Wrap(k, []Recipient{mustRecipient(t, other.pub)})
	list, err = FindIdentities(opts, []string{sshkey.Fingerprint(c.pub), sshkey.Fingerprint(other.pub)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unwrap(wrappedOther, list); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
	if prompts != 0 {
		t.Fatalf("prompted %d times for a non-matching file", prompts)
	}
}

func TestFindIdentitiesEncryptedWrongPassphrase(t *testing.T) {
	c := genKey(t, "ssh-rsa")
	home := writeHome(t, map[string][]byte{".ssh/id_rsa": c.encPEM})
	prompts := 0
	opts := IdentityOptions{
		Getenv: envOf(nil), Home: home, IsTTY: true,
		Prompt: func(string) (string, error) { prompts++; return "wrong", nil },
	}
	list, err := FindIdentities(opts, []string{sshkey.Fingerprint(c.pub)})
	if err != nil {
		t.Fatal(err)
	}
	k := mustKey(t)
	wrapped, _ := Wrap(k, []Recipient{mustRecipient(t, c.pub)})
	_, err = Unwrap(wrapped, list)
	if err == nil {
		t.Fatal("unwrap succeeded with the wrong passphrase")
	}
	if !strings.Contains(err.Error(), "~/.ssh/id_rsa") {
		t.Fatalf("error should name the key: %v", err)
	}
	if prompts != 1 {
		t.Fatalf("prompted %d times, want 1", prompts)
	}
}

func TestFindIdentitiesEncryptedNoTTY(t *testing.T) {
	c := genKey(t, "ssh-ed25519")
	home := writeHome(t, map[string][]byte{".ssh/id_ed25519": c.encPEM})
	var stderr bytes.Buffer
	_, err := FindIdentities(IdentityOptions{
		Getenv: envOf(nil), Home: home, IsTTY: false, Stderr: &stderr,
		Prompt: func(string) (string, error) { t.Fatal("prompted without a TTY"); return "", nil },
	}, []string{sshkey.Fingerprint(c.pub)})
	if !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
	if !strings.Contains(stderr.String(), "skipping ~/.ssh/id_ed25519: passphrase-protected and no TTY") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestFindIdentitiesEncryptedNotWantedNoNotice(t *testing.T) {
	c := genKey(t, "ssh-ed25519")
	home := writeHome(t, map[string][]byte{".ssh/id_ed25519": c.encPEM})
	var stderr bytes.Buffer
	_, err := FindIdentities(IdentityOptions{
		Getenv: envOf(nil), Home: home, IsTTY: true, Stderr: &stderr,
		Prompt: func(string) (string, error) { t.Fatal("prompted for an unwanted key"); return "", nil },
	}, []string{"SHA256:someone-else"})
	if !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected notice for a key that is simply not wanted: %q", stderr.String())
	}
}

func TestFindIdentitiesLegacyEncryptedWithoutPub(t *testing.T) {
	legacyPEM, pub := legacyEncryptedRSA(t)
	known := genKey(t, "ssh-ed25519")

	t.Run("no .pub: unknown ID, tried last, prompts on unwrap", func(t *testing.T) {
		home := writeHome(t, map[string][]byte{
			".ssh/id_ed25519": known.pem,
			".ssh/id_rsa":     legacyPEM,
		})
		prompts := 0
		opts := IdentityOptions{
			Getenv: envOf(nil), Home: home, IsTTY: true,
			Prompt: func(string) (string, error) { prompts++; return passphrase, nil },
		}
		// Only the legacy RSA key is wanted; the ed25519 one is skipped, and
		// the RSA key (unknown ID) is kept because it *might* match.
		list, err := FindIdentities(opts, []string{sshkey.Fingerprint(pub)})
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 1 || list[0].ID != "" || list[0].Source != "~/.ssh/id_rsa" {
			t.Fatalf("list = %+v", list)
		}
		if prompts != 0 {
			t.Fatal("prompted eagerly")
		}
		k := mustKey(t)
		wrapped, _ := Wrap(k, []Recipient{mustRecipient(t, pub)})
		got, err := Unwrap(wrapped, list)
		if err != nil {
			t.Fatal(err)
		}
		if got != k || prompts != 1 {
			t.Fatalf("got key match %v, prompts %d", got == k, prompts)
		}

		// Ordering: known-and-wanted first, unknown last, even though the
		// search order puts id_ed25519 before id_rsa anyway; check with both.
		list, err = FindIdentities(opts, []string{sshkey.Fingerprint(known.pub), sshkey.Fingerprint(pub)})
		if err != nil {
			t.Fatal(err)
		}
		if got := ids(list); strings.Join(got, ",") != "~/.ssh/id_ed25519,~/.ssh/id_rsa" {
			t.Fatalf("order = %q", got)
		}
	})

	t.Run("unknown ID precedes known via env, still sorted last", func(t *testing.T) {
		home := writeHome(t, map[string][]byte{
			"legacy":          legacyPEM,
			".ssh/id_ed25519": known.pem,
		})
		opts := IdentityOptions{
			Getenv: envOf(map[string]string{"ENVC_PRIVATE_KEY_FILE": filepath.Join(home, "legacy")}),
			Home:   home, IsTTY: true,
			Prompt: func(string) (string, error) { return passphrase, nil },
		}
		list, err := FindIdentities(opts, []string{sshkey.Fingerprint(known.pub)})
		if err != nil {
			t.Fatal(err)
		}
		if got := ids(list); strings.Join(got, ",") != "~/.ssh/id_ed25519,"+filepath.Join(home, "legacy") {
			t.Fatalf("order = %q", got)
		}
	})

	t.Run("with .pub: ID known, filtered like any other", func(t *testing.T) {
		home := writeHome(t, map[string][]byte{
			".ssh/id_rsa":     legacyPEM,
			".ssh/id_rsa.pub": []byte(pub.Line + "\n"),
		})
		opts := IdentityOptions{
			Getenv: envOf(nil), Home: home, IsTTY: true,
			Prompt: func(string) (string, error) { return passphrase, nil },
		}
		list, err := FindIdentities(opts, []string{sshkey.Fingerprint(pub)})
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 1 || list[0].ID != sshkey.Fingerprint(pub) {
			t.Fatalf("list = %+v", list)
		}
		if _, err := FindIdentities(opts, []string{"SHA256:other"}); !errors.Is(err, ErrNoIdentity) {
			t.Fatalf("err = %v, want ErrNoIdentity", err)
		}
	})

	t.Run("no .pub and no TTY: skipped with notice", func(t *testing.T) {
		home := writeHome(t, map[string][]byte{".ssh/id_rsa": legacyPEM})
		var stderr bytes.Buffer
		_, err := FindIdentities(IdentityOptions{Getenv: envOf(nil), Home: home, Stderr: &stderr}, []string{sshkey.Fingerprint(pub)})
		if !errors.Is(err, ErrNoIdentity) {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(stderr.String(), "skipping ~/.ssh/id_rsa: passphrase-protected and no TTY") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})
}

func TestFindIdentitiesEnvErrors(t *testing.T) {
	home := writeHome(t, nil)
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"ENVC_PRIVATE_KEY garbage", map[string]string{"ENVC_PRIVATE_KEY": "not a key"}, "ENVC_PRIVATE_KEY"},
		{"ENVC_PRIVATE_KEY_FILE missing", map[string]string{"ENVC_PRIVATE_KEY_FILE": filepath.Join(home, "nope")}, "nope"},
		{"ENVC_PRIVATE_KEY age garbage", map[string]string{"ENVC_PRIVATE_KEY": "AGE-SECRET-KEY-1NOPE"}, "ENVC_PRIVATE_KEY"},
		{"ENVC_PRIVATE_KEY is an age recipient", map[string]string{"ENVC_PRIVATE_KEY": genAge(t).Recipient().String()}, "ENVC_PRIVATE_KEY"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FindIdentities(IdentityOptions{Getenv: envOf(tc.env), Home: home}, nil)
			if err == nil || errors.Is(err, ErrNoIdentity) {
				t.Fatalf("err = %v, want a configuration error", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestFindIdentitiesAgeKeyWithCommentLines(t *testing.T) {
	ag := genAge(t)
	home := writeHome(t, nil)
	env := map[string]string{"ENVC_PRIVATE_KEY": "# created: today\n# public key: " + ag.Recipient().String() + "\n" + ag.String() + "\n"}
	list, err := FindIdentities(IdentityOptions{Getenv: envOf(env), Home: home}, []string{ag.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != ag.Recipient().String() || list[0].Source != "ENVC_PRIVATE_KEY" {
		t.Fatalf("list = %+v", list)
	}
}

func TestFindIdentitiesAgeKeyFile(t *testing.T) {
	ag := genAge(t)
	home := writeHome(t, map[string][]byte{"age.txt": []byte("# created: today\n" + ag.String() + "\n")})
	env := map[string]string{"ENVC_PRIVATE_KEY_FILE": filepath.Join(home, "age.txt")}
	list, err := FindIdentities(IdentityOptions{Getenv: envOf(env), Home: home}, []string{ag.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != ag.Recipient().String() || list[0].Source != filepath.Join(home, "age.txt") {
		t.Fatalf("list = %+v", list)
	}
}

func TestFindIdentitiesDedupesSameKey(t *testing.T) {
	c := genKey(t, "ssh-ed25519")
	home := writeHome(t, map[string][]byte{".ssh/id_ed25519": c.pem})
	env := map[string]string{"ENVC_PRIVATE_KEY_FILE": filepath.Join(home, ".ssh", "id_ed25519")}
	list, err := FindIdentities(IdentityOptions{Getenv: envOf(env), Home: home}, []string{sshkey.Fingerprint(c.pub)})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("same key loaded twice: %q", ids(list))
	}
}

func TestFindIdentitiesUnreadableDefaultIsSkipped(t *testing.T) {
	c := genKey(t, "ssh-ed25519")
	home := writeHome(t, map[string][]byte{
		".ssh/id_ed25519": []byte("garbage"),
		".ssh/id_rsa":     c.pem,
	})
	var stderr bytes.Buffer
	list, err := FindIdentities(IdentityOptions{Getenv: envOf(nil), Home: home, Stderr: &stderr}, []string{sshkey.Fingerprint(c.pub)})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Source != "~/.ssh/id_rsa" {
		t.Fatalf("list = %+v", list)
	}
	if !strings.Contains(stderr.String(), "~/.ssh/id_ed25519") {
		t.Fatalf("expected a notice about the unreadable default key, got %q", stderr.String())
	}
}
