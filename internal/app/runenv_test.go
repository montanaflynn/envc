package app

import (
	"reflect"
	"testing"
)

func TestRunEnvPrecedence(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "DATABASE_URL", secretVal("postgres://file")))
	must(t, a.Set("local", "LOG_LEVEL", publicVal("debug")))
	must(t, a.Set("local", "MULTI", publicVal("a\nb")))
	must(t, a.Set("local", "ONLY_FILE", publicVal("1")))

	// No override file: resolved values + environ.
	got, err := a.RunEnv("local", false, []string{"LOG_LEVEL=fromenv", "PATH=/bin", "=bad", "NOEQ"})
	must(t, err)
	want := []string{"DATABASE_URL=postgres://file", "LOG_LEVEL=fromenv", "MULTI=a\nb", "ONLY_FILE=1", "PATH=/bin"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RunEnv = %q", got)
	}

	// ./.env.local overrides the file but not the environ.
	r.write(".env.local", "LOG_LEVEL=trace\nDATABASE_URL=\"postgres://local\"\nEXTRA=x\n")
	got, err = a.RunEnv("local", false, []string{"LOG_LEVEL=fromenv"})
	must(t, err)
	want = []string{"DATABASE_URL=postgres://local", "EXTRA=x", "LOG_LEVEL=fromenv", "MULTI=a\nb", "ONLY_FILE=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RunEnv = %q", got)
	}
	// --pure skips it.
	got, err = a.RunEnv("local", true, nil)
	must(t, err)
	if !reflect.DeepEqual(got, []string{"DATABASE_URL=postgres://file", "LOG_LEVEL=debug", "MULTI=a\nb", "ONLY_FILE=1"}) {
		t.Fatalf("pure = %q", got)
	}

	// Configured override path wins over ./.env.local.
	must(t, a.EnvAdd("local", EnvAddOptions{Dotenv: ".env", Override: "custom.local"}))
	r.write("custom.local", "LOG_LEVEL=custom\n")
	got, err = a.RunEnv("local", false, nil)
	must(t, err)
	if got[1] != "LOG_LEVEL=custom" || len(got) != 4 {
		t.Fatalf("custom override = %q", got)
	}
	// Broken override file is a usage error.
	r.write("custom.local", "LOG_LEVEL=\"unterminated\n")
	_, err = a.RunEnv("local", false, nil)
	wantExit(t, err, ExitUsage, "custom.local")
}

func TestRunEnvNoKey(t *testing.T) {
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	r.withPrincipal(a, "alice", alice, "local")
	must(t, a.Set("local", "S", secretVal("s")))
	r.noKey()
	_, err := r.open().RunEnv("local", false, nil)
	wantExit(t, err, ExitDecrypt, "")
}
