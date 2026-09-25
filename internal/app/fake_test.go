package app

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/montanaflynn/envc/internal/destination"
)

// fakeDest is an in-memory destination registered as "fake". Tests configure
// sync.<env>.fake: {id: NAME} and look the instance up with getFake(NAME).
type fakeDest struct {
	mu        sync.Mutex
	id        string
	live      destination.Snapshot
	hidden    bool // Live blanks secret values (github/vercel behavior)
	readsBack bool // implements SecretReader → true (dotenv behavior)
	foldNames bool // CaseInsensitiveNames → true (github behavior)
	stamps    bool // Apply sets Entry.Updated on what it writes (github/vercel behavior)
	clock     int  // seconds past stampEpoch of the last stamped write
	liveErr   error
	applyErr  error
	applies   int
	lastWant  destination.Snapshot
	lastOpts  destination.ApplyOptions
}

var (
	fakesMu sync.Mutex
	fakes   = map[string]*fakeDest{}
)

func getFake(id string) *fakeDest {
	fakesMu.Lock()
	defer fakesMu.Unlock()
	f, ok := fakes[id]
	if !ok {
		f = &fakeDest{id: id, live: destination.Snapshot{}}
		fakes[id] = f
	}
	return f
}

func resetFake(id string) *fakeDest {
	fakesMu.Lock()
	delete(fakes, id)
	fakesMu.Unlock()
	return getFake(id)
}

func init() {
	destination.Register("fake", func(env destination.Env, raw map[string]any) (destination.Destination, error) {
		id, _ := raw["id"].(string)
		if id == "" {
			return nil, errors.New("fake: id is required")
		}
		for k := range raw {
			if k != "id" {
				return nil, errors.New("fake: unknown field " + k)
			}
		}
		f := getFake(id)
		if f.readsBack {
			return &fakeReader{f}, nil
		}
		return f, nil
	})
}

func (f *fakeDest) Name() string { return "fake" }

func (f *fakeDest) CaseInsensitiveNames() bool { return f.foldNames }

func (f *fakeDest) Live(ctx context.Context) (destination.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.liveErr != nil {
		return nil, f.liveErr
	}
	out := make(destination.Snapshot, len(f.live))
	for k, e := range f.live {
		if f.hidden && e.Secret {
			e.Value = ""
		}
		out[k] = e
	}
	return out, nil
}

func (f *fakeDest) Apply(ctx context.Context, want destination.Snapshot, opts destination.ApplyOptions) (destination.Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	f.lastWant = want
	f.lastOpts = opts
	if f.applyErr != nil {
		return destination.Report{}, f.applyErr
	}
	var rep destination.Report
	for k, e := range want {
		cur, ok := f.live[k]
		switch {
		case !ok:
			rep.Created = append(rep.Created, k)
		case cur.Value == e.Value && cur.Secret == e.Secret:
			rep.Unchanged = append(rep.Unchanged, k)
		default:
			rep.Updated = append(rep.Updated, k)
		}
	}
	for k := range f.live {
		if _, ok := want[k]; !ok {
			if opts.Prune {
				rep.Pruned = append(rep.Pruned, k)
			} else {
				rep.Skipped = append(rep.Skipped, k)
			}
		}
	}
	for _, s := range []*[]string{&rep.Created, &rep.Updated, &rep.Unchanged, &rep.Pruned, &rep.Skipped} {
		sort.Strings(*s)
	}
	if opts.DryRun {
		return rep, nil
	}
	next := destination.Snapshot{}
	for k, e := range want {
		if cur, ok := f.live[k]; ok && cur.Value == e.Value && cur.Secret == e.Secret {
			e.Updated = cur.Updated
		} else if f.stamps {
			e.Updated = f.tick()
		}
		next[k] = e
	}
	if !opts.Prune {
		for k, e := range f.live {
			if _, ok := want[k]; !ok {
				next[k] = e
			}
		}
	}
	f.live = next
	return rep, nil
}

// stampEpoch is the fake host's clock origin.
var stampEpoch = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// tick advances the fake host's clock and returns the new time.
func (f *fakeDest) tick() time.Time {
	f.clock++
	return stampEpoch.Add(time.Duration(f.clock) * time.Second)
}

// fakeReader wraps a fakeDest to advertise ReadsBackSecrets (dotenv-like).
type fakeReader struct{ *fakeDest }

func (f *fakeReader) ReadsBackSecrets() bool { return true }
