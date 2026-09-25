package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/montanaflynn/envc/internal/destination"
)

// fakeGitHub is an in-memory stand-in for the Environment variables/secrets
// endpoints. It checks headers and records every mutating call.
type fakeGitHub struct {
	t       *testing.T
	mu      sync.Mutex
	vars    map[string]string
	secrets map[string][]byte // sealed values, decrypted in assertions
	stamps  map[string]string // secret name → updated_at, when set
	pub     *[32]byte
	priv    *[32]byte
	keyID   string
	calls   []string // "METHOD path"
	fail    map[string]int
	perPage int
	token   string
	prefix  string // path the variables/secrets endpoints live under
}

func newFake(t *testing.T) *fakeGitHub {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeGitHub{
		t: t, vars: map[string]string{}, secrets: map[string][]byte{},
		pub: pub, priv: priv, keyID: "key-123", fail: map[string]int{}, perPage: 30, token: "tok",
		prefix: "/repos/acme/widgets/environments/production/",
	}
}

func (f *fakeGitHub) open(name string) string {
	f.t.Helper()
	sealed, ok := f.secrets[name]
	if !ok {
		f.t.Fatalf("secret %s not stored", name)
	}
	out, ok := box.OpenAnonymous(nil, sealed, f.pub, f.priv)
	if !ok {
		f.t.Fatalf("secret %s: cannot open sealed box", name)
	}
	return string(out)
}

func (f *fakeGitHub) mutations() []string {
	var out []string
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET ") {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeGitHub) handler() http.Handler {
	prefix := f.prefix
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			f.t.Errorf("missing GitHub headers on %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"message":"Bad credentials"}`)
			return
		}
		if st, ok := f.fail[r.Method+" "+r.URL.Path]; ok {
			w.WriteHeader(st)
			fmt.Fprintf(w, `{"message":"forced %d"}`, st)
			return
		}
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"Not Found"}`)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		var body map[string]string
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case rest == "variables" && r.Method == "GET":
			names := sortedKeys(f.vars)
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 {
				page = 1
			}
			per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
			if per < 1 || per > f.perPage {
				per = f.perPage
			}
			start := (page - 1) * per
			end := min(start+per, len(names))
			if start > len(names) {
				start, end = len(names), len(names)
			}
			items := []map[string]string{}
			for _, n := range names[start:end] {
				items = append(items, map[string]string{"name": n, "value": f.vars[n]})
			}
			json.NewEncoder(w).Encode(map[string]any{"total_count": len(names), "variables": items})
		case rest == "variables" && r.Method == "POST":
			if _, dup := f.vars[body["name"]]; dup {
				w.WriteHeader(409)
				return
			}
			f.vars[body["name"]] = body["value"]
			w.WriteHeader(201)
		case strings.HasPrefix(rest, "variables/") && r.Method == "PATCH":
			name := strings.TrimPrefix(rest, "variables/")
			if _, ok := f.vars[name]; !ok {
				w.WriteHeader(404)
				return
			}
			f.vars[name] = body["value"]
			w.WriteHeader(204)
		case strings.HasPrefix(rest, "variables/") && r.Method == "DELETE":
			name := strings.TrimPrefix(rest, "variables/")
			if _, ok := f.vars[name]; !ok {
				w.WriteHeader(404)
				return
			}
			delete(f.vars, name)
			w.WriteHeader(204)
		case rest == "secrets" && r.Method == "GET":
			items := []map[string]string{}
			for _, n := range sortedKeys(f.secrets) {
				item := map[string]string{"name": n}
				if at, ok := f.stamps[n]; ok {
					item["updated_at"] = at
				}
				items = append(items, item)
			}
			json.NewEncoder(w).Encode(map[string]any{"total_count": len(items), "secrets": items})
		case rest == "secrets/public-key" && r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]string{"key_id": f.keyID, "key": base64.StdEncoding.EncodeToString(f.pub[:])})
		case strings.HasPrefix(rest, "secrets/") && r.Method == "PUT":
			name := strings.TrimPrefix(rest, "secrets/")
			if body["key_id"] != f.keyID {
				w.WriteHeader(422)
				fmt.Fprint(w, `{"message":"bad key_id"}`)
				return
			}
			sealed, err := base64.StdEncoding.DecodeString(body["encrypted_value"])
			if err != nil {
				w.WriteHeader(422)
				return
			}
			_, existed := f.secrets[name]
			f.secrets[name] = sealed
			if existed {
				w.WriteHeader(204)
			} else {
				w.WriteHeader(201)
			}
		case strings.HasPrefix(rest, "secrets/") && r.Method == "DELETE":
			name := strings.TrimPrefix(rest, "secrets/")
			if _, ok := f.secrets[name]; !ok {
				w.WriteHeader(404)
				return
			}
			delete(f.secrets, name)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"Not Found"}`)
		}
	})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func newDest(t *testing.T, srv *httptest.Server, getenv func(string) string) destination.Destination {
	t.Helper()
	return newDestRaw(t, srv, getenv, nil)
}

// newDestRaw is newDest with extra config fields merged over the defaults.
func newDestRaw(t *testing.T, srv *httptest.Server, getenv func(string) string, extra map[string]any) destination.Destination {
	t.Helper()
	if getenv == nil {
		getenv = func(k string) string {
			if k == "GH_TOKEN" {
				return "tok"
			}
			return ""
		}
	}
	raw := map[string]any{"repository": "acme/widgets", "base_url": srv.URL + "/"}
	for k, v := range extra {
		raw[k] = v
	}
	d, err := destination.New(Name, destination.Env{Root: t.TempDir(), Env: "production", Getenv: getenv, Log: &bytes.Buffer{}}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != Name {
		t.Fatalf("Name() = %q", d.Name())
	}
	if sr, ok := d.(destination.SecretReader); !ok || sr.ReadsBackSecrets() {
		t.Fatal("github must report ReadsBackSecrets() == false")
	}
	return d
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		raw     map[string]any
		remote  string // git remote to set up; "" = no repo
		want    Config
		wantErr string
	}{
		{name: "explicit", raw: map[string]any{"environment": "prod", "repository": "o/r", "base_url": "https://ghe.example/api/v3/"},
			want: Config{Scope: ScopeEnvironment, Environment: "prod", Repository: "o/r", BaseURL: "https://ghe.example/api/v3"}},
		{name: "defaults from env name and ssh remote", raw: nil, remote: "git@github.com:acme/widgets.git",
			want: Config{Scope: ScopeEnvironment, Environment: "production", Repository: "acme/widgets", BaseURL: "https://api.github.com"}},
		{name: "ssh:// remote", raw: map[string]any{}, remote: "ssh://git@github.com/acme/widgets",
			want: Config{Scope: ScopeEnvironment, Environment: "production", Repository: "acme/widgets", BaseURL: "https://api.github.com"}},
		{name: "https remote", raw: nil, remote: "https://github.com/acme/widgets.git",
			want: Config{Scope: ScopeEnvironment, Environment: "production", Repository: "acme/widgets", BaseURL: "https://api.github.com"}},
		{name: "repository scope has no environment", raw: map[string]any{"scope": "repository", "repository": "o/r"},
			want: Config{Scope: ScopeRepository, Repository: "o/r", BaseURL: "https://api.github.com"}},
		{name: "explicit environment scope", raw: map[string]any{"scope": "environment", "repository": "o/r"},
			want: Config{Scope: ScopeEnvironment, Environment: "production", Repository: "o/r", BaseURL: "https://api.github.com"}},
		{name: "environment with repository scope", raw: map[string]any{"scope": "repository", "environment": "prod", "repository": "o/r"},
			wantErr: "environment does not apply to scope: repository"},
		{name: "unknown scope", raw: map[string]any{"scope": "org", "repository": "o/r"}, wantErr: `scope "org"`},
		{name: "no git repo", raw: nil, wantErr: "repository"},
		{name: "bad repository", raw: map[string]any{"repository": "widgets"}, wantErr: `"widgets"`},
		{name: "unknown field", raw: map[string]any{"repository": "o/r", "env": "x"}, wantErr: `unknown field "env"`},
		{name: "wrong type", raw: map[string]any{"repository": true}, wantErr: `"repository" must be a string`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.remote != "" {
				for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", tc.remote}} {
					cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("git %v: %v\n%s", args, err, out)
					}
				}
			}
			got, err := ParseConfig(root, "production", tc.raw)
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

func TestParseRemote(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"git@github.com:o/r.git", "o/r"},
		{"git@github.com:o/r", "o/r"},
		{"ssh://git@github.com/o/r", "o/r"},
		{"ssh://git@github.com:22/o/r.git", "o/r"},
		{"https://github.com/o/r.git", "o/r"},
		{"https://github.com/o/r", "o/r"},
		{"https://github.com/o/r/", "o/r"},
		{"https://user:pw@github.com/o/r.git", "o/r"},
		{"https://ghe.example.com/o/r.git", "o/r"},
		{"https://github.com/o", ""},
		{"", ""},
		{"/local/path", ""},
	}
	for _, tc := range tests {
		got, err := parseRemote(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("parseRemote(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseRemote(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestToken(t *testing.T) {
	f := newFake(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	t.Run("missing names both vars", func(t *testing.T) {
		d := newDest(t, srv, func(string) string { return "" })
		_, err := d.Live(context.Background())
		if err == nil || !strings.Contains(err.Error(), "GH_TOKEN") || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("GITHUB_TOKEN fallback", func(t *testing.T) {
		d := newDest(t, srv, func(k string) string {
			if k == "GITHUB_TOKEN" {
				return "tok"
			}
			return ""
		})
		if _, err := d.Live(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("GH_TOKEN wins", func(t *testing.T) {
		d := newDest(t, srv, func(k string) string {
			switch k {
			case "GH_TOKEN":
				return "tok"
			case "GITHUB_TOKEN":
				return "wrong"
			}
			return ""
		})
		if _, err := d.Live(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bad token → 401 message, token not echoed", func(t *testing.T) {
		d := newDest(t, srv, func(string) string { return "s3cret-token" })
		_, err := d.Live(context.Background())
		if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "GH_TOKEN") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("error leaks token: %v", err)
		}
	})
}

func TestLive(t *testing.T) {
	f := newFake(t)
	f.perPage = 2
	for i := 0; i < 5; i++ {
		f.vars[fmt.Sprintf("V%d", i)] = fmt.Sprint(i)
	}
	f.secrets["S1"] = []byte("x")
	f.secrets["S2"] = []byte("y")
	f.stamps = map[string]string{"S1": "2026-09-24T12:00:01Z"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	d := newDest(t, srv, nil)
	got, err := d.Live(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := destination.Snapshot{
		"V0": {Value: "0"}, "V1": {Value: "1"}, "V2": {Value: "2"}, "V3": {Value: "3"}, "V4": {Value: "4"},
		"S1": {Secret: true, Updated: time.Date(2026, 9, 24, 12, 0, 1, 0, time.UTC)}, "S2": {Secret: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Live = %v, want %v", got, want)
	}
	pages := 0
	for _, c := range f.calls {
		if strings.HasSuffix(c, "/variables") {
			pages++
		}
	}
	if pages != 3 {
		t.Fatalf("expected 3 variable pages, got %d (%v)", pages, f.calls)
	}
}

func TestApply(t *testing.T) {
	const base = "/repos/acme/widgets/environments/production/"
	tests := []struct {
		name        string
		vars        map[string]string
		secrets     []string
		want        destination.Snapshot
		opts        destination.ApplyOptions
		report      destination.Report
		wantVars    map[string]string
		wantSecrets map[string]string // name → plaintext
		wantCalls   []string          // mutating calls in order
	}{
		{
			name:        "create both kinds",
			want:        destination.Snapshot{"B": {Value: "sekrit", Secret: true}, "A": {Value: "1"}},
			report:      destination.Report{Created: []string{"A", "B"}},
			wantVars:    map[string]string{"A": "1"},
			wantSecrets: map[string]string{"B": "sekrit"},
			wantCalls:   []string{"POST " + base + "variables", "PUT " + base + "secrets/B"},
		},
		{
			name:        "update / unchanged / secret always re-put",
			vars:        map[string]string{"A": "old", "U": "same"},
			secrets:     []string{"S"},
			want:        destination.Snapshot{"A": {Value: "new"}, "U": {Value: "same"}, "S": {Value: "v2", Secret: true}},
			report:      destination.Report{Updated: []string{"A", "S"}, Unchanged: []string{"U"}},
			wantVars:    map[string]string{"A": "new", "U": "same"},
			wantSecrets: map[string]string{"S": "v2"},
			wantCalls:   []string{"PATCH " + base + "variables/A", "PUT " + base + "secrets/S"},
		},
		{
			name:        "variable becomes secret",
			vars:        map[string]string{"K": "plain"},
			want:        destination.Snapshot{"K": {Value: "hidden", Secret: true}},
			report:      destination.Report{Created: []string{"K"}},
			wantVars:    map[string]string{},
			wantSecrets: map[string]string{"K": "hidden"},
			wantCalls:   []string{"DELETE " + base + "variables/K", "PUT " + base + "secrets/K"},
		},
		{
			name:        "secret becomes variable",
			secrets:     []string{"K"},
			want:        destination.Snapshot{"K": {Value: "plain"}},
			report:      destination.Report{Created: []string{"K"}},
			wantVars:    map[string]string{"K": "plain"},
			wantSecrets: map[string]string{},
			wantCalls:   []string{"DELETE " + base + "secrets/K", "POST " + base + "variables"},
		},
		{
			name:        "extras kept without prune",
			vars:        map[string]string{"X": "1", "A": "1"},
			secrets:     []string{"Y"},
			want:        destination.Snapshot{"A": {Value: "1"}},
			report:      destination.Report{Unchanged: []string{"A"}},
			wantVars:    map[string]string{"X": "1", "A": "1"},
			wantSecrets: map[string]string{"Y": ""},
			wantCalls:   nil,
		},
		{
			name:        "prune deletes both kinds",
			vars:        map[string]string{"X": "1", "A": "1"},
			secrets:     []string{"Y"},
			want:        destination.Snapshot{"A": {Value: "1"}},
			opts:        destination.ApplyOptions{Prune: true},
			report:      destination.Report{Unchanged: []string{"A"}, Pruned: []string{"X", "Y"}},
			wantVars:    map[string]string{"A": "1"},
			wantSecrets: map[string]string{},
			wantCalls:   []string{"DELETE " + base + "variables/X", "DELETE " + base + "secrets/Y"},
		},
		{
			name:        "dry run writes nothing",
			vars:        map[string]string{"A": "old", "X": "1"},
			secrets:     []string{"S"},
			want:        destination.Snapshot{"A": {Value: "new"}, "S": {Value: "v", Secret: true}, "N": {Value: "n", Secret: true}},
			opts:        destination.ApplyOptions{Prune: true, DryRun: true},
			report:      destination.Report{Created: []string{"N"}, Updated: []string{"A", "S"}, Pruned: []string{"X"}},
			wantVars:    map[string]string{"A": "old", "X": "1"},
			wantSecrets: map[string]string{"S": ""},
			wantCalls:   nil,
		},
		{
			name:        "case-insensitive match against GitHub's uppercased names",
			vars:        map[string]string{"LOWER": "1"},
			secrets:     []string{"SEC"},
			want:        destination.Snapshot{"lower": {Value: "1"}, "sec": {Value: "v", Secret: true}},
			report:      destination.Report{Unchanged: []string{"lower"}, Updated: []string{"sec"}},
			wantVars:    map[string]string{"LOWER": "1"},
			wantSecrets: map[string]string{"SEC": "v"},
			wantCalls:   []string{"PUT " + base + "secrets/SEC"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			for k, v := range tc.vars {
				f.vars[k] = v
			}
			for _, s := range tc.secrets {
				f.secrets[s] = []byte("pre-existing")
			}
			srv := httptest.NewServer(f.handler())
			defer srv.Close()

			d := newDest(t, srv, nil)
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
			if len(f.secrets) != len(tc.wantSecrets) {
				t.Fatalf("secrets = %v, want %v", sortedKeys(f.secrets), sortedKeys(tc.wantSecrets))
			}
			for name, plain := range tc.wantSecrets {
				if plain == "" {
					if _, ok := f.secrets[name]; !ok {
						t.Fatalf("secret %s missing", name)
					}
					continue
				}
				if got := f.open(name); got != plain {
					t.Fatalf("secret %s = %q, want %q", name, got, plain)
				}
			}
			if got := f.mutations(); !reflect.DeepEqual(got, tc.wantCalls) {
				t.Fatalf("mutations = %v, want %v", got, tc.wantCalls)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	const base = "/repos/acme/widgets/environments/production/"
	tests := []struct {
		name     string
		fail     map[string]int
		wantSubs []string
	}{
		{name: "403 explains scope", fail: map[string]int{"GET " + base + "secrets": 403}, wantSubs: []string{"403", "GITHUB_TOKEN", "secrets"}},
		{name: "404 names repo and environment", fail: map[string]int{"GET " + base + "variables": 404}, wantSubs: []string{"404", "acme/widgets", "production"}},
		{name: "5xx after retry surfaces", fail: map[string]int{"GET " + base + "variables": 502}, wantSubs: []string{"502", "forced 502"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.fail = tc.fail
			srv := httptest.NewServer(f.handler())
			defer srv.Close()
			d := newDest(t, srv, nil)
			_, err := d.Live(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			for _, s := range tc.wantSubs {
				if !strings.Contains(err.Error(), s) {
					t.Fatalf("err %q missing %q", err, s)
				}
			}
		})
	}
}

func TestRetryOn5xx(t *testing.T) {
	f := newFake(t)
	f.vars["A"] = "1"
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		f.handler().ServeHTTP(w, r)
	}))
	defer srv.Close()
	d := newDest(t, srv, nil).(*GitHub)
	d.http.Backoff = 0
	got, err := d.Live(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got["A"].Value != "1" {
		t.Fatalf("Live = %v", got)
	}
}

func TestApplyFailsMidwayReturnsError(t *testing.T) {
	const base = "/repos/acme/widgets/environments/production/"
	f := newFake(t)
	f.fail = map[string]int{"PUT " + base + "secrets/S": 422}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := newDest(t, srv, nil)
	_, err := d.Apply(context.Background(), destination.Snapshot{"S": {Value: "v", Secret: true}}, destination.ApplyOptions{})
	if err == nil || !strings.Contains(err.Error(), "S") {
		t.Fatalf("err = %v", err)
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

func TestCaseInsensitiveNames(t *testing.T) {
	var d destination.Destination = &GitHub{}
	ci, ok := d.(destination.CaseInsensitiveNames)
	if !ok || !ci.CaseInsensitiveNames() {
		t.Fatal("GitHub must advertise case-insensitive names so diff folds them")
	}
}

// Repository scope uses the same request shapes under /actions/, so the
// Apply behaviour (sealed secrets, kind switches) carries over unchanged.
func TestApplyRepositoryScope(t *testing.T) {
	const base = "/repos/acme/widgets/actions/"
	f := newFake(t)
	f.prefix = base
	f.vars["K"] = "plain"
	f.secrets["NPM_TOKEN"] = []byte("hand-added")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := newDestRaw(t, srv, nil, map[string]any{"scope": "repository"})

	got, err := d.Apply(context.Background(), destination.Snapshot{
		"A": {Value: "1"}, "K": {Value: "hidden", Secret: true},
	}, destination.ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if want := (destination.Report{Created: []string{"A", "K"}}); !reflect.DeepEqual(norm(got), want) {
		t.Fatalf("report = %+v, want %+v", got, want)
	}
	if f.vars["A"] != "1" || f.open("K") != "hidden" {
		t.Fatalf("vars = %v secrets = %v", f.vars, sortedKeys(f.secrets))
	}
	wantCalls := []string{"POST " + base + "variables", "DELETE " + base + "variables/K", "PUT " + base + "secrets/K"}
	if got := f.mutations(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("mutations = %v, want %v", got, wantCalls)
	}
	live, err := d.Live(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := live["NPM_TOKEN"]; !ok {
		t.Fatalf("Live = %v, want the hand-added secret listed", live)
	}
}

// Repository secrets are shared with whatever else sets them (the UI, other
// tools), so prune would delete secrets envc never wrote.
func TestApplyRepositoryScopeRefusesPrune(t *testing.T) {
	f := newFake(t)
	f.prefix = "/repos/acme/widgets/actions/"
	f.secrets["NPM_TOKEN"] = []byte("hand-added")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := newDestRaw(t, srv, nil, map[string]any{"scope": "repository"})
	for _, dry := range []bool{false, true} {
		_, err := d.Apply(context.Background(), destination.Snapshot{"A": {Value: "1"}}, destination.ApplyOptions{Prune: true, DryRun: dry})
		if err == nil || !strings.Contains(err.Error(), "prune") || !strings.Contains(err.Error(), "scope: repository") {
			t.Fatalf("dry=%v err = %v", dry, err)
		}
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutations = %v", m)
	}
}

// GitHub Free answers 403 "Upgrade to GitHub Pro…" for environment endpoints
// on private repositories. That is a plan limit, not a token problem.
func TestErrorPlanLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"message":"Upgrade to GitHub Pro or make this repository public to enable this feature."}`)
	}))
	defer srv.Close()
	_, err := newDest(t, srv, nil).Live(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	for _, s := range []string{"Upgrade to GitHub Pro", "private repositories", "scope: repository"} {
		if !strings.Contains(err.Error(), s) {
			t.Fatalf("err %q missing %q", err, s)
		}
	}
	if strings.Contains(err.Error(), "lacks permission") {
		t.Fatalf("plan limit reported as a token problem: %v", err)
	}
}

func TestError404RepositoryScope(t *testing.T) {
	f := newFake(t)
	f.prefix = "/repos/acme/widgets/actions/"
	f.fail = map[string]int{"GET /repos/acme/widgets/actions/variables": 404}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	_, err := newDestRaw(t, srv, nil, map[string]any{"scope": "repository"}).Live(context.Background())
	if err == nil || !strings.Contains(err.Error(), "acme/widgets") || strings.Contains(err.Error(), "environment") {
		t.Fatalf("err = %v", err)
	}
}
