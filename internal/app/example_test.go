package app

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const exampleManifest = `access: []
config:
  NEXT_PUBLIC_APP_URL:
    description: Public site URL
    secret: false
    value: https://my-app.vercel.app
  LOG_LEVEL:
    description: Server log verbosity
    secret: false
    value: warn
    enum: [debug, info, warn, error]
  DATABASE_URL:
    description: Postgres connection string
    secret: true
    value: hunter2
    pattern: 'postgres(ql)?://.*'
  GREETING:
    description: |-
      Two lines
      of description
    secret: false
    value: hello world
    required: false
`

const exampleWant = "# .env template for local, written by envc. Secrets are blank; do not edit — it is regenerated from .envc/environments/local.yaml.\n" +
	"# Copy any line into .env.local to override it for `envc run`.\n" +
	"\n" +
	"# Postgres connection string\n" +
	"# secret\n" +
	"# pattern: postgres(ql)?://.*\n" +
	"DATABASE_URL=\n" +
	"\n" +
	"# Two lines\n" +
	"# of description\n" +
	"# optional\n" +
	"GREETING=\"hello world\"\n" +
	"\n" +
	"# Server log verbosity\n" +
	"# enum: debug, info, warn, error\n" +
	"LOG_LEVEL=warn\n" +
	"\n" +
	"# Public site URL\n" +
	"NEXT_PUBLIC_APP_URL=https://my-app.vercel.app\n"

// A hand-written manifest with a plaintext secret, no envelope, no key: the
// template still renders and the secret is blank.
func TestExampleGolden(t *testing.T) {
	r := newRepo(t)
	r.noKey()
	r.write(".envc/environments/local.yaml", exampleManifest)
	got, err := r.open().Example("local")
	must(t, err)
	if got != exampleWant {
		t.Fatalf("example =\n%s\nwant\n%s", got, exampleWant)
	}
	if strings.Contains(got, "hunter2") {
		t.Fatal("plaintext secret leaked into the template")
	}
}

// With a real envelope and no key available, Example still works.
func TestExampleNeedsNoKey(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("top-secret")))
	must(t, a.Set("local", "P", publicVal("plain")))
	r.noKey()
	got, err := r.open().Example("local")
	must(t, err)
	if !strings.Contains(got, "\n# secret\nS=\n") || !strings.Contains(got, "\nP=plain\n") || strings.Contains(got, "top-secret") {
		t.Fatalf("example =\n%s", got)
	}
}

func TestExampleUsesConfiguredOverride(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	must(t, a.EnvAdd("local", EnvAddOptions{Dotenv: ".env", Override: ".env.me"}))
	got, err := r.open().Example("local")
	must(t, err)
	if !strings.Contains(got, "# Copy any line into .env.me to override it") {
		t.Fatalf("example =\n%s", got)
	}
}

func TestExampleUnknownEnv(t *testing.T) {
	r := newRepo(t)
	_, err := r.open().Example("nope")
	wantExit(t, err, ExitUsage, "unknown environment")
}

func TestExampleFileLifecycle(t *testing.T) {
	r := newRepo(t) // env add local → template exists
	p := ExamplePath(r.root, "local")
	if got := r.read(".env.local.example"); !strings.HasPrefix(got, "# .env template for local") {
		t.Fatalf("env add did not write the template: %q", got)
	}
	a := r.open()
	must(t, a.Set("local", "P", publicVal("a")))
	if got := r.read(".env.local.example"); !strings.Contains(got, "\nP=a\n") {
		t.Fatalf("set did not refresh: %q", got)
	}
	must(t, a.Unset("local", "P"))
	if got := r.read(".env.local.example"); strings.Contains(got, "P=") {
		t.Fatalf("unset did not refresh: %q", got)
	}

	// Unchanged content: the file is not rewritten.
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	must(t, os.Chtimes(p, old, old))
	must(t, a.rewrap("local"))
	if st, err := os.Stat(p); err != nil || !st.ModTime().Equal(old) {
		t.Fatalf("unchanged template was rewritten (mtime %v)", st.ModTime())
	}

	// DryRun writes nothing.
	r.dryRun = true
	must(t, r.open().Set("local", "Q", publicVal("b")))
	if got := r.read(".env.local.example"); strings.Contains(got, "Q=") {
		t.Fatal("dry-run set wrote the template")
	}
	r.dryRun = false

	must(t, a.EnvAdd("prod", EnvAddOptions{}))
	if _, err := os.Stat(ExamplePath(r.root, "prod")); err != nil {
		t.Fatalf("env add prod: %v", err)
	}
	must(t, r.open().EnvRemove("prod", false))
	if _, err := os.Stat(ExamplePath(r.root, "prod")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("env rm left the template: %v", err)
	}
}

func TestExampleNotWrittenByReads(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	must(t, a.Set("local", "P", publicVal("a")))
	must(t, os.Remove(ExamplePath(r.root, "local")))
	if _, err := a.Get("local", "P"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Resolve("local"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RunEnv("local", true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.inspect("local"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ExamplePath(r.root, "local")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a read recreated the template: %v", err)
	}
}

func TestEnsureExampleMissingAndStale(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	must(t, a.Set("local", "P", publicVal("a")))
	clean := func() {
		ps, err := a.inspect("local")
		must(t, err)
		if len(ps) != 0 {
			t.Fatalf("check: %+v", ps)
		}
	}
	clean()

	must(t, os.Remove(ExamplePath(r.root, "local")))
	ps, err := a.inspect("local")
	must(t, err)
	if !hasProblem(ps, "local", "", "regenerate .env.local.example") {
		t.Fatalf("dry run after delete: %+v", ps)
	}
	if _, err := os.Stat(ExamplePath(r.root, "local")); err == nil {
		t.Fatal("dry run wrote the template")
	}
	res, err := a.Ensure("local")
	must(t, err)
	if len(res.Targets) != 1 || len(res.Targets[0].Effects) != 1 || res.Targets[0].Effects[0] != "regenerate .env.local.example" {
		t.Fatalf("ensure after delete: %+v", res)
	}
	clean()

	r.write(".env.local.example", "P=edited\n")
	ps, err = a.inspect("local")
	must(t, err)
	if !hasProblem(ps, "local", "", "regenerate .env.local.example") || ps[0].Warn {
		t.Fatalf("dry run after edit: %+v", ps)
	}
	_, err = a.Ensure("local")
	must(t, err)
	clean()
}

func TestSyncRefreshesExample(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	must(t, a.EnvAdd("local", EnvAddOptions{Dotenv: ".env"}))
	must(t, a.Set("local", "P", publicVal("a")))
	must(t, os.Remove(ExamplePath(r.root, "local")))
	results, err := a.Sync(context.Background(), "local", "", false)
	must(t, err)
	must(t, results[0].Err)
	if got := r.read(".env.local.example"); !strings.Contains(got, "\nP=a\n") {
		t.Fatalf("sync did not refresh: %q", got)
	}
}
