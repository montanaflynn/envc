package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/state"

	// Register the shipped destinations so check/sync see them.
	_ "github.com/montanaflynn/envc/internal/destination/dotenv"
	_ "github.com/montanaflynn/envc/internal/destination/github"
	_ "github.com/montanaflynn/envc/internal/destination/vercel"
)

// keyPair is an in-process SSH key: private PEM (OpenSSH format) and the
// authorized_keys line.
type keyPair struct {
	priv string
	pub  string
}

func newEd25519(t *testing.T, comment string) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return marshalPair(t, priv, pub, comment)
}

// newEncryptedEd25519 is newEd25519 with the private key passphrase-protected
// (OpenSSH format, which embeds the public key).
func newEncryptedEd25519(t *testing.T, passphrase string) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{priv: string(pem.EncodeToMemory(block)), pub: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk)))}
}

func newRSA(t *testing.T, comment string) keyPair {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return marshalPair(t, priv, &priv.PublicKey, comment)
}

func marshalPair(t *testing.T, priv, pub any, comment string) keyPair {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		t.Fatal(err)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk)))
	if comment != "" {
		line += " " + comment
	}
	return keyPair{priv: string(pem.EncodeToMemory(block)), pub: line}
}

// repo is a temp envc repo plus the injected environment.
type repo struct {
	t      *testing.T
	root   string
	env    map[string]string
	stderr *bytes.Buffer
	dryRun bool
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &repo{t: t, root: root, env: map[string]string{"HOME": home}, stderr: &bytes.Buffer{}}
	if err := Init(root, r.options()); err != nil {
		t.Fatal(err)
	}
	// Every test starts with a local environment.
	a, err := Open(r.options())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnvAdd("local", EnvAddOptions{}); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *repo) options() Options {
	return Options{
		Root:   r.root,
		Stderr: r.stderr,
		Getenv: func(k string) string { return r.env[k] },
		Now:    func() time.Time { return time.Date(2026, 8, 29, 23, 0, 0, 0, time.UTC) },
		DryRun: r.dryRun,
	}
}

// useKey makes kp the process identity (ENVC_PRIVATE_KEY).
func (r *repo) useKey(kp keyPair) { r.env["ENVC_PRIVATE_KEY"] = kp.priv }

// noKey removes every identity.
func (r *repo) noKey() {
	delete(r.env, "ENVC_PRIVATE_KEY")
	delete(r.env, "ENVC_PRIVATE_KEY_FILE")
}

func (r *repo) open() *App {
	r.t.Helper()
	a, err := Open(r.options())
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

// load reads the manifest and attaches its envelope (if any), without the
// missing-envelope check that App.Load applies.
func (r *repo) load(env string) *envfile.File {
	r.t.Helper()
	var f *envfile.File
	var err error
	if env == BaseName {
		f, err = envfile.LoadBase(envfile.BasePath(r.root))
	} else {
		f, err = envfile.Load(envfile.Path(r.root, env))
	}
	if err != nil {
		r.t.Fatal(err)
	}
	if f.Crypto, err = state.LoadEnvelope(r.root, env); err != nil {
		r.t.Fatal(err)
	}
	return f
}

// save writes the manifest and its envelope (or removes the envelope when
// f.Crypto is nil), bypassing validation: tests use it to hand-edit files.
func (r *repo) save(env string, f *envfile.File) {
	r.t.Helper()
	if f.Crypto != nil {
		must(r.t, f.Crypto.Save(r.root, env))
	} else {
		must(r.t, state.RemoveEnvelope(r.root, env))
	}
	path := envfile.Path(r.root, env)
	if env == BaseName {
		path = envfile.BasePath(r.root)
	}
	must(r.t, f.Save(path))
}

func (r *repo) write(rel, content string) {
	r.t.Helper()
	p := filepath.Join(r.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *repo) read(rel string) string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.root, rel))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

// gitRemote makes root a git repository whose origin is url, which is where
// `env add --github` pins the repository from.
func (r *repo) gitRemote(url string) {
	r.t.Helper()
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", url}} {
		cmd := exec.Command("git", append([]string{"-C", r.root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			r.t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// withPrincipal adds a principal with one key and grants it on env.
func (r *repo) withPrincipal(a *App, name string, kp keyPair, env string) {
	r.t.Helper()
	if err := a.PrincipalAddKeys(name, "", []string{kp.pub}, ""); err != nil {
		r.t.Fatal(err)
	}
	if err := a.Allow(env, []string{name}); err != nil {
		r.t.Fatal(err)
	}
}

func boolp(b bool) *bool    { return &b }
func strp(s string) *string { return &s }
func secretVal(v string) SetOptions {
	return SetOptions{Secret: boolp(true), HasValue: true, Value: v}
}
func publicVal(v string) SetOptions {
	return SetOptions{Secret: boolp(false), HasValue: true, Value: v}
}

// wantExit asserts err is an *ExitError with code and (optionally) a substring.
func wantExit(t *testing.T, err error, code int, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want exit %d error containing %q, got nil", code, contains)
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("want *ExitError, got %T: %v", err, err)
	}
	if ee.Code != code {
		t.Fatalf("want exit %d, got %d: %v", code, ee.Code, err)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("want error containing %q, got %q", contains, err.Error())
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// --- Init / Open / Env / Load -------------------------------------------------

func TestInit(t *testing.T) {
	root := t.TempDir()
	r := &repo{t: t, root: root, env: map[string]string{}, stderr: &bytes.Buffer{}}
	r.write(".gitignore", "node_modules\n.env\n")
	must(t, Init(root, r.options()))

	if _, err := os.Stat(filepath.Join(root, ".envc.yaml")); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(filepath.Join(root, ".envc")); len(entries) != 0 {
		t.Fatalf("init must not create environments, got %v", entries)
	}
	gi := r.read(".gitignore")
	if gi != "node_modules\n.env\n.env.local\n*.agekey\n" {
		t.Fatalf("gitignore = %q", gi)
	}
	wantExit(t, Init(root, r.options()), ExitUsage, "already exists")
}

func TestInitCreatesGitignore(t *testing.T) {
	r := newRepo(t)
	if got := r.read(".gitignore"); got != ".env\n.env.local\n*.agekey\n" {
		t.Fatalf("gitignore = %q", got)
	}
}

func TestInitDryRunWritesNothing(t *testing.T) {
	root := t.TempDir()
	must(t, Init(root, Options{DryRun: true}))
	if _, err := os.Stat(filepath.Join(root, ".envc.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run wrote .envc.yaml: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	_, err := Open(Options{Root: t.TempDir()})
	wantExit(t, err, ExitUsage, "envc init")

	r := newRepo(t)
	r.write(".envc.yaml", "nope: [")
	_, err = Open(r.options())
	wantExit(t, err, ExitUsage, "")
}

func TestEnv(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	got, err := a.Env("local")
	must(t, err)
	if got != "local" {
		t.Fatalf("Env(\"local\") = %q", got)
	}
	_, err = a.Env("production")
	wantExit(t, err, ExitUsage, "known: local")
	_, err = a.Env("../etc")
	wantExit(t, err, ExitUsage, "invalid environment name")

	_, err = a.Env("")
	wantExit(t, err, ExitUsage, "environment is required")
}

func TestLoad(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	_, err := a.Load("staging")
	wantExit(t, err, ExitUsage, "unknown environment")
	r.write(".envc/environments/local.yaml", "bogus: 1\n")
	_, err = a.Load("local")
	wantExit(t, err, ExitUsage, "")
}
