package app

import (
	"context"
	"errors"
	"testing"

	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/roster"
	"github.com/montanaflynn/envc/internal/state"
)

func diffKeys(t *testing.T, a *App, only string) map[string]DiffState {
	t.Helper()
	res, err := a.Diff(context.Background(), "prod", only)
	must(t, err)
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	return res[0].Keys
}

func TestDiffTable(t *testing.T) {
	r, a, fa, _ := syncRepo(t)

	// never synced
	keys := diffKeys(t, a, "fake")
	if keys["SECRET"] != DiffNeverSynced || keys["PUBLIC"] != DiffNeverSynced {
		t.Fatalf("before sync: %v", keys)
	}
	_, err := a.Sync(context.Background(), "prod", "", false)
	must(t, err)

	// ok / ok (unverifiable)
	keys = diffKeys(t, a, "fake")
	if keys["PUBLIC"] != DiffOK || keys["SECRET"] != DiffUnverifiable {
		t.Fatalf("after sync: %v", keys)
	}
	if a.mustDiffResult(t, "fake").Drifted() {
		t.Fatal("clean sync reported drift")
	}

	// extra
	fa.live["EXTRA"] = destination.Entry{Value: "x"}
	keys = diffKeys(t, a, "fake")
	if keys["EXTRA"] != DiffExtra || len(keys) != 3 {
		t.Fatalf("extra: %v", keys)
	}
	if a.mustDiffResult(t, "fake").Drifted() {
		t.Fatal("extra should not drift")
	}

	// changed at destination
	fa.live["PUBLIC"] = destination.Entry{Value: "edited"}
	if keys = diffKeys(t, a, "fake"); keys["PUBLIC"] != DiffChangedRemote {
		t.Fatalf("remote edit: %v", keys)
	}
	// missing at destination
	delete(fa.live, "PUBLIC")
	if keys = diffKeys(t, a, "fake"); keys["PUBLIC"] != DiffMissing {
		t.Fatalf("missing: %v", keys)
	}

	// changed in file
	must(t, a.Set("prod", "SECRET", SetOptions{HasValue: true, Value: "new"}))
	must(t, a.Set("prod", "NEWKEY", publicVal("n")))
	keys = diffKeys(t, a, "fake")
	if keys["SECRET"] != DiffChangedFile || keys["NEWKEY"] != DiffNeverSynced {
		t.Fatalf("file edit: %v", keys)
	}

	// reencrypt carries the sync record to the new key: nothing looks changed.
	_, err = a.Sync(context.Background(), "prod", "", false)
	must(t, err)
	must(t, a.rekey("prod"))
	keys = diffKeys(t, a, "fake")
	if keys["SECRET"] != DiffUnverifiable || keys["PUBLIC"] != DiffOK || keys["NEWKEY"] != DiffOK {
		t.Fatalf("after reencrypt: %v", keys)
	}
	k2, _ := a.DataKey("prod")
	rec, _ := state.LoadSync(r.root, "prod")
	if rec["fake"].KeyID != k2.ID() || rec["fake"].Keys["PUBLIC"] != k2.SyncHMAC("PUBLIC", "pub") {
		t.Fatalf("sync record not rekeyed: %+v", rec["fake"])
	}

	// A record made under some other key (a reencrypt on another branch) is
	// stale; one sync refreshes it without destination changes.
	d := rec["fake"]
	d.KeyID = "deadbeef"
	rec["fake"] = d
	must(t, rec.Save(r.root, "prod"))
	keys = diffKeys(t, a, "fake")
	if keys["SECRET"] != DiffStaleSync || keys["PUBLIC"] != DiffStaleSync {
		t.Fatalf("stale: %v", keys)
	}
	results, err := a.Sync(context.Background(), "prod", "fake", false)
	must(t, err)
	if len(results[0].Report.Updated) != 0 || len(results[0].Report.Created) != 0 {
		t.Fatalf("sync after reencrypt wrote: %+v", results[0].Report)
	}
	if keys = diffKeys(t, a, "fake"); keys["SECRET"] != DiffUnverifiable {
		t.Fatalf("after refresh: %v", keys)
	}

	// A record for a different destination does not count.
	rec, _ = state.LoadSync(r.root, "prod")
	delete(rec, "fake2")
	must(t, rec.Save(r.root, "prod"))
	if keys = diffKeys(t, a, "fake2"); keys["PUBLIC"] != DiffNeverSynced {
		t.Fatalf("fake2: %v", keys)
	}

	// No sync record at all is "never synced", not an error.
	must(t, state.RemoveSync(r.root, "prod"))
	if keys = diffKeys(t, a, "fake"); keys["PUBLIC"] != DiffNeverSynced {
		t.Fatalf("no record: %v", keys)
	}
}

func (a *App) mustDiffResult(t *testing.T, only string) DiffResult {
	t.Helper()
	res, err := a.Diff(context.Background(), "prod", only)
	must(t, err)
	return res[0]
}

func TestDiffReadsBackIgnoresSyncRecord(t *testing.T) {
	_, a, fa, _ := syncRepo(t)
	fa.readsBack = true
	fa.hidden = false
	fa.live = destination.Snapshot{"SECRET": {Value: "s3"}, "PUBLIC": {Value: "old"}}
	keys := diffKeys(t, a, "fake")
	if keys["SECRET"] != DiffOK || keys["PUBLIC"] != DiffChangedRemote {
		t.Fatalf("reads-back: %v", keys)
	}
}

func TestDiffErrors(t *testing.T) {
	_, a, fa, fb := syncRepo(t)
	_, err := a.Diff(context.Background(), "local", "")
	wantExit(t, err, ExitUsage, "no destinations")

	fa.liveErr = errors.New("api down")
	res, err := a.Diff(context.Background(), "prod", "")
	must(t, err)
	if res[0].Err == nil || res[1].Err != nil {
		t.Fatalf("res = %+v", res)
	}
	fb.liveErr = errors.New("api down")
	res, err = a.Diff(context.Background(), "prod", "")
	wantExit(t, err, ExitDrift, "every destination failed")
	if len(res) != 2 || res[0].Err == nil || res[1].Err == nil {
		t.Fatalf("res = %+v", res)
	}

	// Unregistered destination in the roster.
	a.Roster.Sync["prod"] = map[string]roster.DestConfig{"nope": {}}
	res, err = a.Diff(context.Background(), "prod", "")
	if err == nil || res[0].Err == nil {
		t.Fatalf("unknown destination: %v %+v", err, res)
	}
}

// A destination that folds names (GitHub) satisfies a wanted key with any
// case-insensitive match instead of reporting it missing plus an extra.
func TestDiffCaseInsensitiveNames(t *testing.T) {
	_, a, fa, _ := syncRepo(t)
	must(t, a.Set("prod", "lower", publicVal("v")))
	_, err := a.Sync(context.Background(), "prod", "fake", false)
	must(t, err)
	// The destination stored the name uppercased.
	fa.live["LOWER"] = fa.live["lower"]
	delete(fa.live, "lower")

	keys := diffKeys(t, a, "fake")
	if keys["lower"] != DiffMissing || keys["LOWER"] != DiffExtra {
		t.Fatalf("exact-name destination: %v", keys)
	}

	fa.foldNames = true
	keys = diffKeys(t, a, "fake")
	if keys["lower"] != DiffOK {
		t.Fatalf("folded: %v", keys)
	}
	if _, ok := keys["LOWER"]; ok {
		t.Fatalf("folded match still reported extra: %v", keys)
	}
	if a.mustDiffResult(t, "fake").Drifted() {
		t.Fatal("folded match reported drift")
	}

	// An exact match wins over a folded one; the other spelling stays extra.
	fa.live["lower"] = destination.Entry{Value: "other"}
	keys = diffKeys(t, a, "fake")
	if keys["lower"] != DiffChangedRemote || keys["LOWER"] != DiffExtra {
		t.Fatalf("exact + folded: %v", keys)
	}
	// Unrelated names are still extras.
	fa.live["UNRELATED"] = destination.Entry{Value: "x"}
	if keys = diffKeys(t, a, "fake"); keys["UNRELATED"] != DiffExtra {
		t.Fatalf("unrelated: %v", keys)
	}
}
