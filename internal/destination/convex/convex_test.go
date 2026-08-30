package convex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/montanaflynn/envc/internal/destination"
)

// fakeConvex is an in-memory stand-in for one deployment's env var API.
type fakeConvex struct {
	t          *testing.T
	mu         sync.Mutex
	vars       map[string]string
	calls      []string // "METHOD path[ changes]"
	key        string
	queryError string // when set, /api/query returns status=error with this message
}

func newFake(t *testing.T) *fakeConvex {
	return &fakeConvex{t: t, vars: map[string]string{}, key: "prod:quiet-lion-123|tok"}
}

func (f *fakeConvex) mutations() []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "POST /api/update_environment_variables") {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeConvex) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Convex "+f.key {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"code":"Unauthorized","message":"bad admin key"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/query":
			var body struct {
				Path   string         `json:"path"`
				Args   map[string]any `json:"args"`
				Format string         `json:"format"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				f.t.Errorf("query: %v", err)
			}
			if body.Path != "_system/cli/queryEnvironmentVariables" {
				f.t.Errorf("query path = %q", body.Path)
			}
			if body.Format != "json" {
				f.t.Errorf("query format = %q", body.Format)
			}
			f.calls = append(f.calls, "POST /api/query")
			if f.queryError != "" {
				json.NewEncoder(w).Encode(map[string]any{"status": "error", "errorMessage": f.queryError})
				return
			}
			names := make([]string, 0, len(f.vars))
			for n := range f.vars {
				names = append(names, n)
			}
			sort.Strings(names)
			value := make([]map[string]string, 0, len(names))
			for _, n := range names {
				value = append(value, map[string]string{"name": n, "value": f.vars[n]})
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "value": value})
		case "/api/update_environment_variables":
			var body struct {
				Changes []struct {
					Name  string  `json:"name"`
					Value *string `json:"value"`
				} `json:"changes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				f.t.Errorf("update: %v", err)
			}
			var parts []string
			for _, ch := range body.Changes {
				if ch.Value == nil {
					delete(f.vars, ch.Name)
					parts = append(parts, ch.Name+"=<remove>")
				} else {
					f.vars[ch.Name] = *ch.Value
					parts = append(parts, ch.Name+"="+*ch.Value)
				}
			}
			f.calls = append(f.calls, "POST /api/update_environment_variables "+strings.Join(parts, " "))
			fmt.Fprint(w, `null`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"code":"NotFound","message":"no such route"}`)
		}
	})
}

func newDest(t *testing.T, srv *httptest.Server, raw map[string]any, getenv func(string) string) destination.Destination {
	t.Helper()
	if getenv == nil {
		getenv = func(k string) string {
			if k == "CONVEX_DEPLOY_KEY" {
				return "prod:quiet-lion-123|tok"
			}
			return ""
		}
	}
	if raw == nil {
		raw = map[string]any{"deployment": "quiet-lion-123"}
	}
	raw["url"] = srv.URL + "/"
	d, err := destination.New(Name, destination.Env{Root: t.TempDir(), Env: "production", Getenv: getenv, Log: &bytes.Buffer{}}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != Name {
		t.Fatalf("Name() = %q", d.Name())
	}
	if sr, ok := d.(destination.SecretReader); !ok || !sr.ReadsBackSecrets() {
		t.Fatal("convex must report ReadsBackSecrets() == true")
	}
	return d
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		raw     map[string]any
		want    Config
		wantErr string
	}{
		{name: "explicit", raw: map[string]any{"deployment": "quiet-lion-123", "url": "http://x/", "key_env": "MY_KEY"},
			want: Config{Deployment: "quiet-lion-123", URL: "http://x", KeyEnv: "MY_KEY"}},
		{name: "url derived from deployment", raw: map[string]any{"deployment": "quiet-lion-123"},
			want: Config{Deployment: "quiet-lion-123", URL: "https://quiet-lion-123.convex.cloud", KeyEnv: "CONVEX_DEPLOY_KEY"}},
		{name: "url without deployment (self-hosted)", raw: map[string]any{"url": "http://127.0.0.1:3210"},
			want: Config{URL: "http://127.0.0.1:3210", KeyEnv: "CONVEX_DEPLOY_KEY"}},
		{name: "missing both", raw: map[string]any{}, wantErr: "deployment"},
		{name: "unknown field", raw: map[string]any{"deployment": "d", "team": "x"}, wantErr: `unknown field "team"`},
		{name: "wrong type", raw: map[string]any{"deployment": 1}, wantErr: `"deployment" must be a string`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseConfig(tc.raw)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestKey(t *testing.T) {
	f := newFake(t)
	f.vars["A"] = "1"
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	// No key set.
	d := newDest(t, srv, nil, func(string) string { return "" })
	_, err := d.Live(context.Background())
	if err == nil || !strings.Contains(err.Error(), "CONVEX_DEPLOY_KEY") {
		t.Fatalf("err = %v", err)
	}

	// key_env override is honored.
	d = newDest(t, srv, map[string]any{"deployment": "quiet-lion-123", "key_env": "MY_KEY"}, func(k string) string {
		if k == "MY_KEY" {
			return "prod:quiet-lion-123|tok"
		}
		return ""
	})
	if _, err := d.Live(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A key naming another deployment is refused before any request.
	d = newDest(t, srv, nil, func(string) string { return "prod:other-name-99|tok" })
	_, err = d.Live(context.Background())
	for _, s := range []string{"other-name-99", "quiet-lion-123"} {
		if err == nil || !strings.Contains(err.Error(), s) {
			t.Fatalf("err = %v, want containing %q", err, s)
		}
	}

	// Bare dashboard admin keys embed the name too.
	f.key = "quiet-lion-123|01c2c09c"
	d = newDest(t, srv, nil, func(string) string { return "quiet-lion-123|01c2c09c" })
	if _, err := d.Live(context.Background()); err != nil {
		t.Fatal(err)
	}
	d = newDest(t, srv, nil, func(string) string { return "other-name-99|01c2c09c" })
	if _, err := d.Live(context.Background()); err == nil {
		t.Fatal("bare admin key for another deployment must be refused")
	}

	// Keys without a deployment name (preview/project scope) pass the check.
	f.key = "preview:acme:app|tok"
	d = newDest(t, srv, nil, func(string) string { return "preview:acme:app|tok" })
	if _, err := d.Live(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A rejected key mentions the env var, never the key itself.
	f.key = "prod:quiet-lion-123|tok"
	d = newDest(t, srv, nil, func(string) string { return "prod:quiet-lion-123|wr0ng" })
	_, err = d.Live(context.Background())
	for _, want := range []string{"401", "CONVEX_DEPLOY_KEY", "deployment token create"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want containing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "wr0ng") {
		t.Fatalf("error leaks key: %v", err)
	}
}

func TestLive(t *testing.T) {
	f := newFake(t)
	f.vars = map[string]string{"A": "1", "B": "two words"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	d := newDest(t, srv, nil, nil)
	got, err := d.Live(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := destination.Snapshot{"A": {Value: "1"}, "B": {Value: "two words"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Live = %v, want %v", got, want)
	}
}

func TestQueryError(t *testing.T) {
	f := newFake(t)
	f.queryError = "boom"
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := newDest(t, srv, nil, nil)
	if _, err := d.Live(context.Background()); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

func TestApply(t *testing.T) {
	tests := []struct {
		name      string
		vars      map[string]string
		want      destination.Snapshot
		opts      destination.ApplyOptions
		report    destination.Report
		wantVars  map[string]string
		wantCalls []string
	}{
		{
			name:     "create, update, unchanged in one batch",
			vars:     map[string]string{"A": "old", "U": "same"},
			want:     destination.Snapshot{"A": {Value: "new"}, "U": {Value: "same"}, "N": {Value: "n", Secret: true}},
			report:   destination.Report{Created: []string{"N"}, Updated: []string{"A"}, Unchanged: []string{"U"}},
			wantVars: map[string]string{"A": "new", "U": "same", "N": "n"},
			wantCalls: []string{
				"POST /api/update_environment_variables A=new N=n",
			},
		},
		{
			name:     "extras kept without prune",
			vars:     map[string]string{"A": "1", "X": "x"},
			want:     destination.Snapshot{"A": {Value: "1"}},
			report:   destination.Report{Unchanged: []string{"A"}},
			wantVars: map[string]string{"A": "1", "X": "x"},
		},
		{
			name:     "prune removes extras",
			vars:     map[string]string{"A": "1", "X": "x", "Y": "y"},
			want:     destination.Snapshot{"A": {Value: "1"}},
			opts:     destination.ApplyOptions{Prune: true},
			report:   destination.Report{Unchanged: []string{"A"}, Pruned: []string{"X", "Y"}},
			wantVars: map[string]string{"A": "1"},
			wantCalls: []string{
				"POST /api/update_environment_variables X=<remove> Y=<remove>",
			},
		},
		{
			name:     "dry run writes nothing",
			vars:     map[string]string{"A": "old", "X": "x"},
			want:     destination.Snapshot{"A": {Value: "new"}, "N": {Value: "n"}},
			opts:     destination.ApplyOptions{Prune: true, DryRun: true},
			report:   destination.Report{Created: []string{"N"}, Updated: []string{"A"}, Pruned: []string{"X"}},
			wantVars: map[string]string{"A": "old", "X": "x"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.vars = tc.vars
			srv := httptest.NewServer(f.handler())
			defer srv.Close()

			d := newDest(t, srv, nil, nil)
			got, err := d.Apply(context.Background(), tc.want, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(norm(got), norm(tc.report)) {
				t.Fatalf("report = %+v, want %+v", got, tc.report)
			}
			if !reflect.DeepEqual(f.vars, tc.wantVars) {
				t.Fatalf("vars = %v, want %v", f.vars, tc.wantVars)
			}
			if got := f.mutations(); !reflect.DeepEqual(got, tc.wantCalls) {
				t.Fatalf("mutations = %v, want %v", got, tc.wantCalls)
			}
		})
	}
}

func norm(r destination.Report) destination.Report {
	fix := func(s []string) []string {
		if len(s) == 0 {
			return nil
		}
		return s
	}
	return destination.Report{Created: fix(r.Created), Updated: fix(r.Updated), Unchanged: fix(r.Unchanged), Pruned: fix(r.Pruned), Skipped: fix(r.Skipped)}
}
