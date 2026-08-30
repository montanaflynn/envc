package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/roster"
	"github.com/montanaflynn/envc/internal/state"
)

// syncRepo builds a repo with alice, a secret and a public value on prod, and
// two fake destinations "a" and "b" (ids prefixed by the test name).
func syncRepo(t *testing.T) (*repo, *App, *fakeDest, *fakeDest) {
	t.Helper()
	r := newRepo(t)
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	must(t, a.EnvAdd("prod", EnvAddOptions{}))
	r.withPrincipal(a, "alice", alice, "prod")
	must(t, a.Set("prod", "SECRET", secretVal("s3")))
	must(t, a.Set("prod", "PUBLIC", publicVal("pub")))
	fa, fb := resetFake(t.Name()+"/a"), resetFake(t.Name()+"/b")
	fa.hidden, fb.hidden = true, true
	a.Roster.Sync["prod"] = map[string]roster.DestConfig{
		"fake":  {"id": fa.id},
		"fake2": {"id": fb.id},
	}
	must(t, a.saveRoster())
	return r, a, fa, fb
}

func init() {
	// A second registered name so a single env can carry two fakes.
	destination.Register("fake2", func(env destination.Env, raw map[string]any) (destination.Destination, error) {
		return destination.New("fake", env, raw)
	})
}

func TestSyncWritesDestinationsAndSyncRecords(t *testing.T) {
	r, a, fa, fb := syncRepo(t)
	results, err := a.Sync(context.Background(), "prod", "", false)
	must(t, err)
	if len(results) != 2 || results[0].Destination != "fake" || results[1].Destination != "fake2" {
		t.Fatalf("results = %+v", results)
	}
	for _, res := range results {
		if res.Err != nil || !reflect.DeepEqual(res.Report.Created, []string{"PUBLIC", "SECRET"}) {
			t.Fatalf("result = %+v", res)
		}
	}
	if fa.live["SECRET"] != (destination.Entry{Value: "s3", Secret: true}) || fb.live["PUBLIC"] != (destination.Entry{Value: "pub"}) {
		t.Fatalf("live = %v / %v", fa.live, fb.live)
	}
	rec, err := state.LoadSync(r.root, "prod")
	must(t, err)
	k, _ := a.DataKey("prod")
	for _, name := range []string{"fake", "fake2"} {
		d := rec[name]
		if d.KeyID != k.ID() || d.At.Year() != 2026 || d.Keys["SECRET"] != k.SyncHMAC("SECRET", "s3") || d.Keys["PUBLIC"] != k.SyncHMAC("PUBLIC", "pub") {
			t.Fatalf("sync record %s = %+v", name, d)
		}
	}
	// Second sync: unchanged.
	results, _ = a.Sync(context.Background(), "prod", "fake", true)
	if len(results) != 1 || !reflect.DeepEqual(results[0].Report.Unchanged, []string{"PUBLIC", "SECRET"}) || !fa.lastOpts.Prune {
		t.Fatalf("results = %+v opts=%+v", results, fa.lastOpts)
	}
}

func TestSyncErrors(t *testing.T) {
	r, a, fa, _ := syncRepo(t)
	_, err := a.Sync(context.Background(), "local", "", false)
	wantExit(t, err, ExitUsage, "no destinations configured")
	_, err = a.Sync(context.Background(), "prod", "vercel", false)
	wantExit(t, err, ExitUsage, `"vercel" is not configured`)

	fa.applyErr = errors.New("boom")
	results, err := a.Sync(context.Background(), "prod", "", false)
	must(t, err)
	if results[0].Err == nil || results[1].Err != nil {
		t.Fatalf("results = %+v", results)
	}
	rec, _ := state.LoadSync(r.root, "prod")
	if _, ok := rec["fake"]; ok {
		t.Fatal("sync record written for failed destination")
	}
	if _, ok := rec["fake2"]; !ok {
		t.Fatal("sync record missing for successful destination")
	}

	r.noKey()
	_, err = r.open().Sync(context.Background(), "prod", "", false)
	wantExit(t, err, ExitDecrypt, "")
}

func TestSyncDryRunAndReadsBack(t *testing.T) {
	r, _, fa, fb := syncRepo(t)
	r.dryRun = true
	results, err := r.open().Sync(context.Background(), "prod", "", false)
	must(t, err)
	if results[0].Err != nil || !fa.lastOpts.DryRun || len(fa.live) != 0 {
		t.Fatalf("dry-run applied: %+v live=%v", results[0], fa.live)
	}
	if rec, _ := state.LoadSync(r.root, "prod"); len(rec) != 0 {
		t.Fatal("dry-run wrote sync records")
	}

	// A destination that reads back secrets (dotenv-like) gets no sync record.
	r.dryRun = false
	fb.readsBack = true
	_, err = r.open().Sync(context.Background(), "prod", "", false)
	must(t, err)
	rec, _ := state.LoadSync(r.root, "prod")
	if _, ok := rec["fake2"]; ok {
		t.Fatal("sync record written for a secret-reading destination")
	}
	if _, ok := rec["fake"]; !ok {
		t.Fatal("sync record missing for fake")
	}
}

func TestSyncPublicOnlyEnvUsesZeroKey(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	must(t, a.Set("local", "P", publicVal("p")))
	f := resetFake(t.Name())
	a.Roster.Sync["local"] = map[string]roster.DestConfig{"fake": {"id": f.id}}
	must(t, a.saveRoster())
	results, err := a.Sync(context.Background(), "local", "", false)
	must(t, err)
	if results[0].Err != nil {
		t.Fatal(results[0].Err)
	}
	rec, _ := state.LoadSync(r.root, "local")
	if rec["fake"].KeyID != "" || rec["fake"].Keys["P"] == "" {
		t.Fatalf("sync record = %+v", rec["fake"])
	}
	// And diff agrees.
	res, err := a.Diff(context.Background(), "local", "")
	must(t, err)
	if res[0].Keys["P"] != DiffOK {
		t.Fatalf("diff = %v", res[0].Keys)
	}
}

func TestSyncWithRealDotenv(t *testing.T) {
	r := newRepo(t)
	a := r.open()
	must(t, a.EnvAdd("local", EnvAddOptions{Dotenv: ".env"}))
	must(t, a.Set("local", "P", publicVal("a b")))
	results, err := a.Sync(context.Background(), "local", "", false)
	must(t, err)
	if results[0].Err != nil {
		t.Fatal(results[0].Err)
	}
	if got := r.read(".env"); got != "# generated by envc — do not edit; put overrides in .env.local\nP=\"a b\"\n" {
		t.Fatalf(".env = %q", got)
	}
	if rec, _ := state.LoadSync(r.root, "local"); len(rec) != 0 {
		t.Fatal("dotenv wrote a sync record")
	}
	res, err := a.Diff(context.Background(), "local", "")
	must(t, err)
	if res[0].Keys["P"] != DiffOK {
		t.Fatalf("diff = %v", res[0].Keys)
	}
}
