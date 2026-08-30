// Package crypto implements the envc v1 envelope: a per-file data key, HKDF
// subkeys, AES-GCM value tokens, the envelope MAC, sync HMACs, and age-based
// wrapping of the data key to SSH / age recipients.
//
// See README → Encryption for exact byte layouts.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/montanaflynn/envc/internal/sshkey"
)

const (
	TokenPrefix = "ENC[envc1,"
	TokenSuffix = "]"
	Version     = 1
)

// HKDF info strings for the three subkeys (README → Encryption).
const (
	infoEnc  = "envc/v1/enc"
	infoMAC  = "envc/v1/mac"
	infoSync = "envc/v1/sync"
)

const (
	nonceSize = 12
	tagSize   = 16
)

// ErrNoIdentity means no usable private key was found for the file's recipients.
// app maps it to exit code 2.
var ErrNoIdentity = errors.New("no usable private key for this file")

// ErrBadMAC means the file MAC did not verify after decrypt.
var ErrBadMAC = errors.New("secret values do not match the envelope mac; file was edited without envc")

// DataKey is the per-file 32-byte root key.
type DataKey [32]byte

// NewDataKey returns a fresh random key.
func NewDataKey() (DataKey, error) {
	var k DataKey
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return DataKey{}, fmt.Errorf("generate data key: %w", err)
	}
	return k, nil
}

// subkey derives one of the three 32-byte HKDF-SHA256 subkeys.
func (k DataKey) subkey(info string) []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, k[:], nil, []byte(info))
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF-SHA256 cannot fail for a 32-byte read.
		panic("hkdf: " + err.Error())
	}
	return out
}

func (k DataKey) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.subkey(infoEnc))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ID is the first 8 hex chars of SHA-256(data_key). Stored in sync records.
func (k DataKey) ID() string {
	sum := sha256.Sum256(k[:])
	return hex.EncodeToString(sum[:4])
}

// Encrypt produces an ENC[envc1,…] token for value, bound to the config key name.
func (k DataKey) Encrypt(name, value string) (string, error) {
	aead, err := k.aead()
	if err != nil {
		return "", fmt.Errorf("encrypt %s: %w", name, err)
	}
	buf := make([]byte, nonceSize, nonceSize+len(value)+tagSize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("encrypt %s: nonce: %w", name, err)
	}
	buf = aead.Seal(buf, buf[:nonceSize], []byte(value), []byte(name))
	return TokenPrefix + base64.StdEncoding.EncodeToString(buf) + TokenSuffix, nil
}

// Decrypt reverses Encrypt. Fails if the token was produced under a different
// name or key.
func (k DataKey) Decrypt(name, token string) (string, error) {
	if !IsToken(token) {
		return "", fmt.Errorf("decrypt %s: value is not an %s…%s token", name, TokenPrefix, TokenSuffix)
	}
	inner := token[len(TokenPrefix) : len(token)-len(TokenSuffix)]
	raw, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return "", fmt.Errorf("decrypt %s: malformed token: %w", name, err)
	}
	if len(raw) < nonceSize+tagSize {
		return "", fmt.Errorf("decrypt %s: malformed token: too short", name)
	}
	aead, err := k.aead()
	if err != nil {
		return "", fmt.Errorf("decrypt %s: %w", name, err)
	}
	plain, err := aead.Open(nil, raw[:nonceSize], raw[nonceSize:], []byte(name))
	if err != nil {
		return "", fmt.Errorf("decrypt %s: authentication failed (wrong key, wrong key name, or edited token)", name)
	}
	return string(plain), nil
}

// IsToken reports whether s looks like ENC[envc1,…].
func IsToken(s string) bool {
	return len(s) >= len(TokenPrefix)+len(TokenSuffix) &&
		strings.HasPrefix(s, TokenPrefix) &&
		strings.HasSuffix(s, TokenSuffix)
}

// MAC computes the envelope mac (base64std) over the decrypted secrets map.
func (k DataKey) MAC(secrets map[string]string) string {
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	h := hmac.New(sha256.New, k.subkey(infoMAC))
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write([]byte(secrets[n]))
		h.Write([]byte{'\n'})
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// SyncHMACLen is the number of hex characters kept from the sync HMAC:
// 64 bits, enough to detect a changed value, short enough to read in a diff.
const SyncHMACLen = 16

// SyncHMAC computes the sync record value for one KEY=value pair: the first
// SyncHMACLen hex chars of HMAC-SHA256(sync subkey, KEY \0 value).
func (k DataKey) SyncHMAC(name, value string) string {
	h := hmac.New(sha256.New, k.subkey(infoSync))
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))[:SyncHMACLen]
}

// Recipient is something a data key can be wrapped to.
type Recipient struct {
	ID  string // "SHA256:…" for SSH keys, "age1…" for age
	Age age.Recipient
}

// RecipientFromSSH builds a Recipient from a parsed SSH public key.
func RecipientFromSSH(pk sshkey.PublicKey) (Recipient, error) {
	if pk.Key == nil {
		return Recipient{}, errors.New("ssh recipient: empty public key")
	}
	var r age.Recipient
	var err error
	switch pk.Key.Type() {
	case ssh.KeyAlgoED25519:
		r, err = agessh.NewEd25519Recipient(pk.Key)
	case ssh.KeyAlgoRSA:
		r, err = agessh.NewRSARecipient(pk.Key)
	default:
		return Recipient{}, fmt.Errorf("ssh recipient: unsupported key type %s: age cannot encrypt to %s keys", pk.Key.Type(), pk.Key.Type())
	}
	if err != nil {
		return Recipient{}, fmt.Errorf("ssh recipient %s: %w", sshkey.Fingerprint(pk), err)
	}
	return Recipient{ID: sshkey.Fingerprint(pk), Age: r}, nil
}

// RecipientFromAge parses an age1… recipient string.
func RecipientFromAge(s string) (Recipient, error) {
	s = strings.TrimSpace(s)
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return Recipient{}, fmt.Errorf("age recipient %q: %w", s, err)
	}
	return Recipient{ID: r.String(), Age: r}, nil
}

// Wrap age-encrypts the data key to every recipient. Returns raw age ciphertext
// (caller base64-encodes for YAML).
func Wrap(k DataKey, rs []Recipient) ([]byte, error) {
	seen := make(map[string]bool, len(rs))
	ageRs := make([]age.Recipient, 0, len(rs))
	for _, r := range rs {
		if r.Age == nil {
			return nil, fmt.Errorf("wrap data key: recipient %q has no age recipient", r.ID)
		}
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		ageRs = append(ageRs, r.Age)
	}
	if len(ageRs) == 0 {
		return nil, errors.New("wrap data key: no recipients")
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, ageRs...)
	if err != nil {
		return nil, fmt.Errorf("wrap data key: %w", err)
	}
	if _, err := w.Write(k[:]); err != nil {
		return nil, fmt.Errorf("wrap data key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("wrap data key: %w", err)
	}
	return buf.Bytes(), nil
}

// Unwrap decrypts a Wrap output with any of the identities.
func Unwrap(wrapped []byte, ids []Identity) (DataKey, error) {
	if len(ids) == 0 {
		return DataKey{}, ErrNoIdentity
	}
	ageIDs := make([]age.Identity, 0, len(ids))
	for _, id := range ids {
		if id.Age == nil {
			continue
		}
		ageIDs = append(ageIDs, sourcedIdentity{id})
	}
	if len(ageIDs) == 0 {
		return DataKey{}, ErrNoIdentity
	}
	r, err := age.Decrypt(bytes.NewReader(wrapped), ageIDs...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return DataKey{}, fmt.Errorf("unwrap data key: %w", ErrNoIdentity)
		}
		return DataKey{}, fmt.Errorf("unwrap data key: %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, 64))
	if err != nil {
		return DataKey{}, fmt.Errorf("unwrap data key: %w", err)
	}
	if len(plain) != len(DataKey{}) {
		return DataKey{}, fmt.Errorf("unwrap data key: got %d bytes, want %d", len(plain), len(DataKey{}))
	}
	var k DataKey
	copy(k[:], plain)
	return k, nil
}

// sourcedIdentity annotates non-"incorrect identity" errors (e.g. a wrong
// passphrase) with the key's source so the user knows which file failed.
type sourcedIdentity struct{ id Identity }

func (s sourcedIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	fk, err := s.id.Age.Unwrap(stanzas)
	if err != nil && !errors.Is(err, age.ErrIncorrectIdentity) && s.id.Source != "" {
		return nil, fmt.Errorf("%s: %w", s.id.Source, err)
	}
	return fk, err
}

// Identity is a private key that can unwrap.
type Identity struct {
	ID     string // matches Recipient.ID; may be "" when unknown (e.g. encrypted key without .pub)
	Source string // human description, e.g. "~/.ssh/id_ed25519" or "ENVC_PRIVATE_KEY"
	Age    age.Identity
}

// IdentityOptions controls discovery.
type IdentityOptions struct {
	Getenv func(string) string
	Home   string    // home directory; "" → os.UserHomeDir
	Stdin  io.Reader // used only if Prompt is nil and IsTTY
	Stderr io.Writer // discovery notices (the passphrase prompt itself uses /dev/tty)
	IsTTY  bool      // may we prompt for a passphrase?
	// Prompt, if set, replaces the /dev/tty passphrase prompt (tests).
	Prompt func(prompt string) (string, error)
}

// FindIdentities returns identities to try, in README search order:
// ENVC_PRIVATE_KEY (contents) → ENVC_PRIVATE_KEY_FILE → ~/.ssh/id_ed25519 → ~/.ssh/id_rsa.
// The two env vars accept either an SSH private key (PEM) or an age secret
// key (AGE-SECRET-KEY-1…); the format is detected from the contents.
//
// wanted is the envelope's recipients. Keys whose ID is known and not in
// wanted are skipped without prompting. Passphrase-protected keys are loaded
// lazily: the prompt happens inside Unwrap, only if the key is needed. In
// non-TTY mode an encrypted key is skipped with a notice on Stderr.
//
// Returns ErrNoIdentity if nothing usable was found.
func FindIdentities(opts IdentityOptions, wanted []string) ([]Identity, error) {
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Home == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("find identities: %w", err)
		}
		opts.Home = home
	}
	// An empty wanted list means "no filter": every discovered key is returned.
	var want map[string]bool
	if len(wanted) > 0 {
		want = make(map[string]bool, len(wanted))
		for _, w := range wanted {
			want[w] = true
		}
	}

	f := &finder{opts: opts, want: want, seen: map[string]bool{}}

	// 1. ENVC_PRIVATE_KEY: private key contents (SSH or age).
	if v := opts.Getenv("ENVC_PRIVATE_KEY"); strings.TrimSpace(v) != "" {
		if err := f.addKey([]byte(v), "ENVC_PRIVATE_KEY", nil); err != nil {
			return nil, fmt.Errorf("ENVC_PRIVATE_KEY: %w", err)
		}
	}
	// 2. ENVC_PRIVATE_KEY_FILE: path to a private key (SSH or age).
	if p := strings.TrimSpace(opts.Getenv("ENVC_PRIVATE_KEY_FILE")); p != "" {
		keyBytes, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("ENVC_PRIVATE_KEY_FILE: %w", err)
		}
		pub, _ := os.ReadFile(p + ".pub")
		if err := f.addKey(keyBytes, p, pub); err != nil {
			return nil, fmt.Errorf("ENVC_PRIVATE_KEY_FILE %s: %w", p, err)
		}
	}
	// 3./4. Default key files. Missing is normal; unreadable gets a notice.
	for _, name := range []string{"id_ed25519", "id_rsa"} {
		path := filepath.Join(opts.Home, ".ssh", name)
		display := "~/.ssh/" + name
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(opts.Stderr, "envc: skipping %s: %v\n", display, err)
			}
			continue
		}
		pub, _ := os.ReadFile(path + ".pub")
		if err := f.addSSH(pemBytes, display, pub); err != nil {
			fmt.Fprintf(opts.Stderr, "envc: skipping %s: %v\n", display, err)
		}
	}

	// Known-and-wanted identities first, unknown-ID ones last. Stable, so the
	// search order is preserved within each group.
	sort.SliceStable(f.found, func(i, j int) bool {
		return f.found[i].ID != "" && f.found[j].ID == ""
	})
	if len(f.found) == 0 {
		return nil, ErrNoIdentity
	}
	return f.found, nil
}

// finder accumulates identities during FindIdentities.
type finder struct {
	opts  IdentityOptions
	want  map[string]bool // nil → accept everything
	seen  map[string]bool // IDs already added
	found []Identity
}

func (f *finder) wanted(id string) bool {
	return f.want == nil || f.want[id]
}

func (f *finder) add(id Identity) {
	if id.ID != "" {
		if f.seen[id.ID] {
			return
		}
		f.seen[id.ID] = true
	}
	f.found = append(f.found, id)
}

// canPrompt reports whether a passphrase may be requested. IsTTY gates it;
// Prompt only replaces the mechanism.
func (f *finder) canPrompt() bool {
	return f.opts.IsTTY
}

// passphraseFunc returns a callback that prompts at most once for source.
func (f *finder) passphraseFunc(source string) func() ([]byte, error) {
	var (
		done bool
		out  []byte
		err  error
	)
	return func() ([]byte, error) {
		if done {
			return out, err
		}
		done = true
		var s string
		s, err = f.prompt("Passphrase for " + source + ": ")
		if err != nil {
			return nil, err
		}
		out = []byte(s)
		return out, nil
	}
}

// prompt reads a passphrase: via opts.Prompt if set, else from the terminal.
func (f *finder) prompt(text string) (string, error) {
	if f.opts.Prompt != nil {
		return f.opts.Prompt(text)
	}
	return TTYPrompt(text)
}

// TTYPrompt reads a passphrase without echo from the controlling terminal. It
// is the prompt used when IdentityOptions.Prompt is nil. Both the prompt and
// the read go to /dev/tty, so it works with stdin and stdout piped, and
// Stderr stays free for notices that callers may buffer.
func TTYPrompt(text string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open terminal for passphrase: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, text)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return string(b), nil
}

// addKey loads private key material in either supported format, detected
// from the contents: an age secret key (AGE-SECRET-KEY-1…) or an SSH private
// key (PEM). pubBytes and source are passed through to addSSH.
func (f *finder) addKey(keyBytes []byte, source string, pubBytes []byte) error {
	if isAgeSecretKey(keyBytes) {
		return f.addAge(string(keyBytes), source)
	}
	return f.addSSH(keyBytes, source, pubBytes)
}

// isAgeSecretKey reports whether the first non-comment, non-blank line looks
// like an age identity.
func isAgeSecretKey(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.HasPrefix(strings.ToUpper(line), "AGE-SECRET-KEY-1")
	}
	return false
}

// addAge parses an AGE-SECRET-KEY-1… identity. Comment lines (as written by
// age-keygen) are tolerated.
func (f *finder) addAge(text, source string) error {
	secret := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if secret != "" {
			return errors.New("expected exactly one AGE-SECRET-KEY-1… line")
		}
		secret = line
	}
	if secret == "" {
		return errors.New("no AGE-SECRET-KEY-1… line found")
	}
	id, err := age.ParseX25519Identity(secret)
	if err != nil {
		return err
	}
	rid := id.Recipient().String()
	if !f.wanted(rid) {
		return nil
	}
	f.add(Identity{ID: rid, Source: source, Age: id})
	return nil
}

// addSSH loads one private key (PEM). pubBytes is the optional contents of
// the matching .pub file, used for encrypted keys without an embedded public
// key. source is the human name used in prompts and notices.
func (f *finder) addSSH(pemBytes []byte, source string, pubBytes []byte) error {
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	if err == nil {
		return f.addUnencryptedSSH(raw, pemBytes, source)
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return fmt.Errorf("parse private key: %w", err)
	}

	// Encrypted. Learn the public key from the header or the .pub file.
	pub := missing.PublicKey
	if pub == nil && len(pubBytes) > 0 {
		if pk, perr := sshkey.Parse(string(pubBytes)); perr == nil {
			pub = pk.Key
		}
	}
	id := ""
	if pub != nil {
		switch pub.Type() {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA:
		default:
			return fmt.Errorf("unsupported key type %s: age cannot decrypt with %s keys", pub.Type(), pub.Type())
		}
		id = ssh.FingerprintSHA256(pub)
		if !f.wanted(id) {
			return nil // not for this file; do not prompt or notify
		}
		if f.seen[id] {
			return nil
		}
	}
	if !f.canPrompt() {
		fmt.Fprintf(f.opts.Stderr, "envc: skipping %s: passphrase-protected and no TTY\n", source)
		return nil
	}
	pass := f.passphraseFunc(source)
	var ident age.Identity
	if pub != nil {
		ident, err = agessh.NewEncryptedSSHIdentity(pub, pemBytes, pass)
		if err != nil {
			return err
		}
	} else {
		ident = &lazyIdentity{pemBytes: pemBytes, passphrase: pass}
	}
	f.add(Identity{ID: id, Source: source, Age: ident})
	return nil
}

func (f *finder) addUnencryptedSSH(raw any, pemBytes []byte, source string) error {
	var pub any
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		pub = k.Public()
	case ed25519.PrivateKey:
		pub = k.Public()
	case *rsa.PrivateKey:
		pub = k.Public()
	default:
		return fmt.Errorf("unsupported key type %T: age can only decrypt with ssh-ed25519 and ssh-rsa keys", raw)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	id := ssh.FingerprintSHA256(spk)
	if !f.wanted(id) {
		return nil
	}
	ident, err := agessh.ParseIdentity(pemBytes)
	if err != nil {
		return err
	}
	f.add(Identity{ID: id, Source: source, Age: ident})
	return nil
}

// lazyIdentity is an encrypted SSH key whose public key is unknown (legacy
// PEM without a .pub file). It prompts on first use and then delegates to the
// decrypted identity.
type lazyIdentity struct {
	pemBytes   []byte
	passphrase func() ([]byte, error)

	inner age.Identity
	err   error
}

func (l *lazyIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if l.inner == nil && l.err == nil {
		l.inner, l.err = l.load()
	}
	if l.err != nil {
		return nil, l.err
	}
	return l.inner.Unwrap(stanzas)
}

func (l *lazyIdentity) load() (age.Identity, error) {
	pass, err := l.passphrase()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain passphrase: %w", err)
	}
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(l.pemBytes, pass)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH key file: %w", err)
	}
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		return agessh.NewEd25519Identity(*k)
	case ed25519.PrivateKey:
		return agessh.NewEd25519Identity(k)
	case *rsa.PrivateKey:
		return agessh.NewRSAIdentity(k)
	}
	return nil, fmt.Errorf("unsupported key type %T: age can only decrypt with ssh-ed25519 and ssh-rsa keys", raw)
}
