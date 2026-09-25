package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/state"
)

// Diff compares file vs each destination. See README → sync.yaml, diff semantics table.
// Every configured destination gets a DiffResult; one whose Live fails has Err
// set. The aggregate error is non-nil only when every destination failed.
func (a *App) Diff(ctx context.Context, env, only string) ([]DiffResult, error) {
	ctx = ctxOrBackground(ctx)
	if err := baseGuard(env); err != nil {
		return nil, err
	}
	names, err := a.destNames(env, only)
	if err != nil {
		return nil, err
	}
	f, err := a.Load(env)
	if err != nil {
		return nil, err
	}
	v, err := a.view(env, f)
	if err != nil {
		return nil, err
	}
	vars, err := a.viewVars(env, f, v)
	if err != nil {
		return nil, err
	}
	rk, keyID, err := a.syncKey(env, f)
	if err != nil {
		return nil, err
	}
	synced, err := state.LoadSync(a.root(), env)
	if err != nil {
		return nil, exitErr(ExitDrift, err)
	}
	want := wantSnapshot(v, vars)

	results := make([]DiffResult, 0, len(names))
	failed := 0
	for _, name := range names {
		res := DiffResult{Destination: name, Keys: map[string]DiffState{}}
		d, err := a.newDestination(env, name)
		if err != nil {
			res.Err = err
			failed++
			results = append(results, res)
			continue
		}
		live, err := d.Live(ctx)
		if err != nil {
			res.Err = fmt.Errorf("%s: live: %w", name, err)
			failed++
			results = append(results, res)
			continue
		}
		rec, hasRecord := synced[name]
		live, extras := matchLive(want, live, caseInsensitiveNames(d))
		for key, entry := range want {
			res.Keys[key] = diffKey(key, entry.Value, live, readsBackSecrets(d), hasRecord, rec, rk, keyID)
		}
		for _, key := range extras {
			res.Keys[key] = DiffExtra
		}
		results = append(results, res)
	}
	if failed > 0 && failed == len(results) {
		return results, &ExitError{Code: ExitDrift, Err: errors.New("diff: every destination failed")}
	}
	return results, nil
}

// caseInsensitiveNames reports whether d stores names case-insensitively.
func caseInsensitiveNames(d destination.Destination) bool {
	ci, ok := d.(destination.CaseInsensitiveNames)
	return ok && ci.CaseInsensitiveNames()
}

// matchLive pairs live entries with wanted keys. The returned snapshot is
// keyed by the wanted spelling; extras are live names no wanted key claims.
// With fold, a live name equal to the key under EqualFold satisfies it (an
// exact match wins when both exist).
func matchLive(want, live destination.Snapshot, fold bool) (destination.Snapshot, []string) {
	matched := make(destination.Snapshot, len(want))
	claimed := map[string]bool{}
	for key := range want {
		name, ok := key, false
		if _, exact := live[key]; exact {
			ok = true
		} else if fold {
			for ln := range live {
				if !claimed[ln] && strings.EqualFold(ln, key) {
					name, ok = ln, true
					break
				}
			}
		}
		if ok {
			matched[key] = live[name]
			claimed[name] = true
		}
	}
	var extras []string
	for ln := range live {
		if !claimed[ln] {
			extras = append(extras, ln)
		}
	}
	return matched, extras
}

// diffKey computes one key's state (README diff semantics table). Destinations
// that read back secrets (dotenv) are compared directly and never consult
// the sync record, since sync writes none for them. A hidden value is
// checked by the host's last-updated time against the one recorded at sync,
// and is unverifiable when either is missing.
func diffKey(key, value string, live destination.Snapshot, readsBack bool, hasRecord bool, rec state.Destination, rk crypto.DataKey, keyID string) DiffState {
	if !readsBack {
		if !hasRecord {
			return DiffNeverSynced
		}
		if rec.KeyID != keyID {
			return DiffStaleSync
		}
		mac, ok := rec.Keys[key]
		if !ok {
			return DiffNeverSynced
		}
		if mac != rk.SyncHMAC(key, value) {
			return DiffChangedFile
		}
	}
	entry, ok := live[key]
	if !ok {
		return DiffMissing
	}
	if !readsBack && entry.Secret && entry.Value == "" {
		synced, ok := rec.Updated[key]
		switch {
		case !ok || entry.Updated.IsZero():
			return DiffUnverifiable
		case !entry.Updated.Equal(synced):
			return DiffChangedRemote
		}
		return DiffOK
	}
	if entry.Value != value {
		return DiffChangedRemote
	}
	return DiffOK
}
