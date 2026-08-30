package destination

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
)

type fake struct{ name string }

func (f fake) Name() string                                                  { return f.name }
func (f fake) Live(context.Context) (Snapshot, error)                        { return Snapshot{}, nil }
func (f fake) Apply(context.Context, Snapshot, ApplyOptions) (Report, error) { return Report{}, nil }

func factory(name string) Factory {
	return func(env Env, raw map[string]any) (Destination, error) {
		if _, bad := raw["bad"]; bad {
			return nil, errors.New("bad config")
		}
		return fake{name: name}, nil
	}
}

func TestRegisterAndNew(t *testing.T) {
	Register("test-alpha", factory("test-alpha"))
	Register("test-beta", factory("test-beta"))

	tests := []struct {
		name    string
		dest    string
		raw     map[string]any
		wantErr string
	}{
		{name: "registered", dest: "test-alpha"},
		{name: "factory error propagates", dest: "test-beta", raw: map[string]any{"bad": true}, wantErr: "bad config"},
		{name: "unknown", dest: "nope", wantErr: `unknown destination "nope" (registered: `},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(tc.dest, Env{}, tc.raw)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New(%q) err = %v, want containing %q", tc.dest, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q) error: %v", tc.dest, err)
			}
			if d.Name() != tc.dest {
				t.Fatalf("Name() = %q, want %q", d.Name(), tc.dest)
			}
		})
	}

	if !Registered("test-alpha") || Registered("nope") {
		t.Fatal("Registered() wrong")
	}
	names := Names()
	if !sort.StringsAreSorted(names) {
		t.Fatalf("Names() not sorted: %v", names)
	}
	for _, want := range []string{"test-alpha", "test-beta"} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Fatalf("Names() = %v, missing %q", names, want)
		}
	}
	// The unknown error lists every registered name.
	_, err := New("nope", Env{}, nil)
	for _, n := range names {
		if !strings.Contains(err.Error(), n) {
			t.Fatalf("error %q does not list %q", err, n)
		}
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	Register("test-dup", factory("test-dup"))
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("duplicate Register did not panic")
		}
	}()
	Register("test-dup", factory("test-dup"))
}

func TestRegisterNilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register with nil factory did not panic")
		}
	}()
	Register("test-nil", nil)
}
