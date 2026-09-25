package vercel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/montanaflynn/envc/internal/destination"
)

type fakeVar struct {
	ID                   string   `json:"id"`
	Key                  string   `json:"key"`
	Value                string   `json:"value"`
	Type                 string   `json:"type"`
	Target               []string `json:"target"`
	GitBranch            string   `json:"gitBranch,omitempty"`
	CustomEnvironmentIds []string `json:"customEnvironmentIds,omitempty"`
	Decrypted            *bool    `json:"decrypted,omitempty"`
}

// fakeVercel is an in-memory stand-in for the project env endpoints.
type fakeVercel struct {
	t          *testing.T
	mu         sync.Mutex
	envs       []fakeVar
	nextID     int
	calls      []string // "METHOD path[ body]"
	fail       map[string]int
	pageSize   int // 0 = no pagination
	team       string
	token      string
	customEnvs map[string]string // slug -> id
}

func newFake(t *testing.T) *fakeVercel {
	return &fakeVercel{t: t, fail: map[string]int{}, token: "vtok"}
}

func (f *fakeVercel) add(v fakeVar) string {
	f.nextID++
	v.ID = fmt.Sprintf("id%d", f.nextID)
	f.envs = append(f.envs, v)
	return v.ID
}

func (f *fakeVercel) find(id string) int {
	for i, v := range f.envs {
		if v.ID == id {
			return i
		}
	}
	return -1
}

func (f *fakeVercel) mutations() []string {
	var out []string
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET ") {
			out = append(out, c)
		}
	}
	return out
}

// refuse mirrors the two rules the real API enforces on a write: a sensitive
// variable must say visibility "secret", and development cannot hold one.
func (f *fakeVercel) refuse(r *http.Request, body map[string]any) string {
	if r.Method != "POST" && r.Method != "PATCH" {
		return ""
	}
	typ, _ := body["type"].(string)
	if typ != "sensitive" {
		return ""
	}
	if vis, _ := body["visibility"].(string); vis != "secret" {
		return "Environment variables with `type: sensitive` must use `visibility: secret`."
	}
	targets, _ := body["target"].([]any)
	if r.Method == "PATCH" && targets == nil {
		if i := f.find(strings.TrimPrefix(r.URL.Path, "/v9/projects/prj_1/env/")); i >= 0 {
			for _, t := range f.envs[i].Target {
				targets = append(targets, t)
			}
		}
	}
	for _, t := range targets {
		if t == "development" {
			return "Sensitive environment variables cannot be created in the Development environment."
		}
	}
	return ""
}

func (f *fakeVercel) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":{"code":"forbidden","message":"Not authorized"}}`)
			return
		}
		if got := r.URL.Query().Get("teamId"); got != f.team {
			f.t.Errorf("%s %s: teamId = %q, want %q", r.Method, r.URL.Path, got, f.team)
		}
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		call := r.Method + " " + r.URL.Path
		if body != nil {
			// Deterministic body rendering for assertions.
			keys := make([]string, 0, len(body))
			for k := range body {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%v", k, body[k]))
			}
			call += " {" + strings.Join(parts, " ") + "}"
		}
		f.calls = append(f.calls, call)
		if st, ok := f.fail[r.Method+" "+r.URL.Path]; ok {
			w.WriteHeader(st)
			fmt.Fprintf(w, `{"error":{"code":"forced","message":"forced %d"}}`, st)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if msg := f.refuse(r, body); msg != "" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "bad_request", "message": msg}})
			return
		}
		const listPath = "/v10/projects/prj_1/env"
		const itemPrefix = "/v9/projects/prj_1/env/"
		switch {
		case r.URL.Path == "/v9/projects/prj_1/custom-environments" && r.Method == "GET":
			envs := []map[string]string{}
			for slug, id := range f.customEnvs {
				envs = append(envs, map[string]string{"id": id, "slug": slug})
			}
			sort.Slice(envs, func(i, j int) bool { return envs[i]["slug"] < envs[j]["slug"] })
			json.NewEncoder(w).Encode(map[string]any{"environments": envs})
		case r.URL.Path == listPath && r.Method == "GET":
			if r.URL.Query().Get("decrypt") != "true" {
				f.t.Errorf("list without decrypt=true")
			}
			envs := f.envs
			resp := map[string]any{}
			if f.pageSize > 0 {
				start := 0
				if u := r.URL.Query().Get("until"); u != "" {
					fmt.Sscanf(u, "%d", &start)
				}
				end := min(start+f.pageSize, len(envs))
				envs = envs[start:end]
				next := 0
				if end < len(f.envs) {
					next = end
				}
				resp["pagination"] = map[string]any{"count": len(envs), "next": next}
			}
			// Sensitive values never come back.
			out := make([]fakeVar, 0, len(envs))
			for _, v := range envs {
				if v.Type == "sensitive" {
					v.Value = ""
				}
				// Encrypted values come back as ciphertext, decrypt=true or not.
				if v.Type == "encrypted" {
					v.Value = "eyJ2IjoidjIi-ciphertext-" + v.Value
					no := false
					v.Decrypted = &no
				}
				out = append(out, v)
			}
			resp["envs"] = out
			json.NewEncoder(w).Encode(resp)
		case r.URL.Path == listPath && r.Method == "POST":
			if r.URL.Query().Get("upsert") != "true" {
				f.t.Errorf("create without upsert=true")
			}
			v := fakeVar{Key: body["key"].(string), Value: body["value"].(string), Type: body["type"].(string)}
			if ts, ok := body["target"].([]any); ok {
				for _, t := range ts {
					v.Target = append(v.Target, t.(string))
				}
			}
			if cs, ok := body["customEnvironmentIds"].([]any); ok {
				for _, c := range cs {
					v.CustomEnvironmentIds = append(v.CustomEnvironmentIds, c.(string))
				}
			}
			id := f.add(v)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"created": map[string]string{"id": id}, "failed": []any{}})
		case strings.HasPrefix(r.URL.Path, itemPrefix) && r.Method == "PATCH":
			i := f.find(strings.TrimPrefix(r.URL.Path, itemPrefix))
			if i < 0 {
				w.WriteHeader(404)
				return
			}
			if v, ok := body["value"].(string); ok {
				f.envs[i].Value = v
			}
			if t, ok := body["type"].(string); ok {
				f.envs[i].Type = t
			}
			if ts, ok := body["target"].([]any); ok {
				f.envs[i].Target = nil
				for _, t := range ts {
					f.envs[i].Target = append(f.envs[i].Target, t.(string))
				}
			}
			if cs, ok := body["customEnvironmentIds"].([]any); ok {
				f.envs[i].CustomEnvironmentIds = nil
				for _, c := range cs {
					f.envs[i].CustomEnvironmentIds = append(f.envs[i].CustomEnvironmentIds, c.(string))
				}
			}
			json.NewEncoder(w).Encode(f.envs[i])
		case strings.HasPrefix(r.URL.Path, itemPrefix) && r.Method == "DELETE":
			i := f.find(strings.TrimPrefix(r.URL.Path, itemPrefix))
			if i < 0 {
				w.WriteHeader(404)
				return
			}
			f.envs = append(f.envs[:i], f.envs[i+1:]...)
			w.WriteHeader(200)
			fmt.Fprint(w, `[]`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":{"code":"not_found","message":"no such route"}}`)
		}
	})
}

func newDest(t *testing.T, srv *httptest.Server, raw map[string]any, getenv func(string) string) destination.Destination {
	t.Helper()
	if getenv == nil {
		getenv = func(k string) string {
			if k == "VERCEL_TOKEN" {
				return "vtok"
			}
			return ""
		}
	}
	if raw == nil {
		raw = map[string]any{"environment": "production", "project": "prj_1"}
	}
	raw["base_url"] = srv.URL + "/"
	d, err := destination.New(Name, destination.Env{Root: t.TempDir(), Env: "production", Getenv: getenv, Log: &bytes.Buffer{}}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != Name {
		t.Fatalf("Name() = %q", d.Name())
	}
	if sr, ok := d.(destination.SecretReader); !ok || sr.ReadsBackSecrets() {
		t.Fatal("vercel must report ReadsBackSecrets() == false")
	}
	return d
}

func writeProjectJSON(t *testing.T, root, projectID, orgID string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, ".vercel"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf(`{"projectId":%q,"orgId":%q,"settings":{}}`, projectID, orgID)
	if err := os.WriteFile(filepath.Join(root, ".vercel", "project.json"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		raw     map[string]any
		project string // .vercel/project.json projectId; "" = no file
		org     string
		want    Config
		wantErr string
	}{
		{name: "explicit", raw: map[string]any{"environment": "preview", "project": "my-app", "team": "team_x", "base_url": "http://x/"},
			want: Config{Environment: "preview", Project: "my-app", Team: "team_x", BaseURL: "http://x"}},
		{name: "defaults from project.json with team", raw: map[string]any{"environment": "production"}, project: "prj_abc", org: "team_123",
			want: Config{Environment: "production", Project: "prj_abc", Team: "team_123", BaseURL: "https://api.vercel.com"}},
		{name: "personal orgId is not a team", raw: map[string]any{"environment": "production"}, project: "prj_abc", org: "usr_personal",
			want: Config{Environment: "production", Project: "prj_abc", BaseURL: "https://api.vercel.com"}},
		{name: "explicit project keeps file team", raw: map[string]any{"environment": "development", "project": "other"}, project: "prj_abc", org: "team_123",
			want: Config{Environment: "development", Project: "other", Team: "team_123", BaseURL: "https://api.vercel.com"}},
		{name: "missing environment", raw: map[string]any{"project": "p"}, wantErr: "environment"},
		{name: "custom environment slug", raw: map[string]any{"environment": "staging", "project": "p"},
			want: Config{Environment: "staging", Project: "p", BaseURL: "https://api.vercel.com"}},
		{name: "no project anywhere", raw: map[string]any{"environment": "production"}, wantErr: "project"},
		{name: "unknown field", raw: map[string]any{"environment": "production", "project": "p", "org": "x"}, wantErr: `unknown field "org"`},
		{name: "wrong type", raw: map[string]any{"environment": 1}, wantErr: `"environment" must be a string`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.project != "" {
				writeProjectJSON(t, root, tc.project, tc.org)
			}
			got, err := ParseConfig(root, tc.raw)
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

func TestToken(t *testing.T) {
	f := newFake(t)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	d := newDest(t, srv, nil, func(string) string { return "" })
	_, err := d.Live(context.Background())
	if err == nil || !strings.Contains(err.Error(), "VERCEL_TOKEN") {
		t.Fatalf("err = %v", err)
	}

	d = newDest(t, srv, nil, func(string) string { return "wrong-t0ken" })
	_, err = d.Live(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "VERCEL_TOKEN") || !strings.Contains(err.Error(), "Not authorized") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "wrong-t0ken") {
		t.Fatalf("error leaks token: %v", err)
	}
}

func TestLive(t *testing.T) {
	f := newFake(t)
	f.team = "team_9"
	f.pageSize = 2
	f.add(fakeVar{Key: "PLAIN", Value: "1", Type: "plain", Target: []string{"production"}})
	f.add(fakeVar{Key: "ENC", Value: "2", Type: "encrypted", Target: []string{"production", "preview"}})
	f.add(fakeVar{Key: "SENS", Value: "hidden", Type: "sensitive", Target: []string{"production"}})
	f.add(fakeVar{Key: "OTHER", Value: "3", Type: "plain", Target: []string{"preview"}})
	f.add(fakeVar{Key: "BRANCH", Value: "4", Type: "plain", Target: []string{"production"}, GitBranch: "feat"})
	f.add(fakeVar{Key: "LAST", Value: "5", Type: "plain", Target: []string{"development", "production"}})
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	d := newDest(t, srv, map[string]any{"environment": "production", "project": "prj_1", "team": "team_9"}, nil)
	got, err := d.Live(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := destination.Snapshot{
		// Encrypted values come back as ciphertext, so they are as unreadable
		// as sensitive ones.
		"PLAIN": {Value: "1"}, "ENC": {Secret: true}, "SENS": {Secret: true}, "LAST": {Value: "5"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Live = %v, want %v", got, want)
	}
	if len(f.calls) != 3 {
		t.Fatalf("expected 3 paginated GETs, got %v", f.calls)
	}
}

func TestApply(t *testing.T) {
	const list = "/v10/projects/prj_1/env"
	const item = "/v9/projects/prj_1/env/"
	tests := []struct {
		name      string
		envs      []fakeVar
		want      destination.Snapshot
		opts      destination.ApplyOptions
		report    destination.Report
		wantEnvs  []fakeVar // ID ignored
		wantCalls []string
	}{
		{
			name:   "create plain and sensitive",
			want:   destination.Snapshot{"S": {Value: "sek", Secret: true}, "A": {Value: "1"}},
			report: destination.Report{Created: []string{"A", "S"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "1", Type: "plain", Target: []string{"production"}},
				{Key: "S", Value: "sek", Type: "sensitive", Target: []string{"production"}},
			},
			wantCalls: []string{
				"POST " + list + " {key=A target=[production] type=plain value=1 visibility=config}",
				"POST " + list + " {key=S target=[production] type=sensitive value=sek visibility=secret}",
			},
		},
		{
			name: "update / unchanged / secret always re-sent",
			envs: []fakeVar{
				{Key: "A", Value: "old", Type: "plain", Target: []string{"production"}},
				{Key: "U", Value: "same", Type: "plain", Target: []string{"production"}},
				{Key: "S", Value: "x", Type: "sensitive", Target: []string{"production"}},
			},
			want:   destination.Snapshot{"A": {Value: "new"}, "U": {Value: "same"}, "S": {Value: "v2", Secret: true}},
			report: destination.Report{Updated: []string{"A", "S"}, Unchanged: []string{"U"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "new", Type: "plain", Target: []string{"production"}},
				{Key: "U", Value: "same", Type: "plain", Target: []string{"production"}},
				{Key: "S", Value: "v2", Type: "sensitive", Target: []string{"production"}},
			},
			wantCalls: []string{
				"PATCH " + item + "id1 {target=[production] type=plain value=new visibility=config}",
				"PATCH " + item + "id3 {target=[production] type=sensitive value=v2 visibility=secret}",
			},
		},
		{
			// A public value stored as encrypted (the dashboard's default) cannot
			// be compared, so it is re-sent once and becomes plain.
			name:   "a public value stored encrypted becomes plain",
			envs:   []fakeVar{{Key: "E", Value: "1", Type: "encrypted", Target: []string{"production"}}},
			want:   destination.Snapshot{"E": {Value: "1"}},
			report: destination.Report{Updated: []string{"E"}},
			wantEnvs: []fakeVar{
				{Key: "E", Value: "1", Type: "plain", Target: []string{"production"}},
			},
			wantCalls: []string{
				"PATCH " + item + "id1 {target=[production] type=plain value=1 visibility=config}",
			},
		},
		{
			name:   "sensitive becomes plain and plain becomes sensitive",
			envs:   []fakeVar{{Key: "A", Value: "", Type: "sensitive", Target: []string{"production"}}, {Key: "B", Value: "b", Type: "plain", Target: []string{"production"}}},
			want:   destination.Snapshot{"A": {Value: "a"}, "B": {Value: "b", Secret: true}},
			report: destination.Report{Updated: []string{"A", "B"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "a", Type: "plain", Target: []string{"production"}},
				{Key: "B", Value: "b", Type: "sensitive", Target: []string{"production"}},
			},
			wantCalls: []string{
				"PATCH " + item + "id1 {target=[production] type=plain value=a visibility=config}",
				"PATCH " + item + "id2 {target=[production] type=sensitive value=b visibility=secret}",
			},
		},
		{
			name:   "shared target is split, never edited in place",
			envs:   []fakeVar{{Key: "A", Value: "shared", Type: "plain", Target: []string{"preview", "production"}}},
			want:   destination.Snapshot{"A": {Value: "prod-only"}},
			report: destination.Report{Updated: []string{"A"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "shared", Type: "plain", Target: []string{"preview"}},
				{Key: "A", Value: "prod-only", Type: "plain", Target: []string{"production"}},
			},
			wantCalls: []string{
				"PATCH " + item + "id1 {target=[preview]}",
				"POST " + list + " {key=A target=[production] type=plain value=prod-only visibility=config}",
			},
		},
		{
			name:   "shared target with equal value is still unchanged",
			envs:   []fakeVar{{Key: "A", Value: "same", Type: "plain", Target: []string{"preview", "production"}}},
			want:   destination.Snapshot{"A": {Value: "same"}},
			report: destination.Report{Unchanged: []string{"A"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "same", Type: "plain", Target: []string{"preview", "production"}},
			},
		},
		{
			name: "other targets and branch vars are ignored; extras kept without prune",
			envs: []fakeVar{
				{Key: "A", Value: "1", Type: "plain", Target: []string{"production"}},
				{Key: "X", Value: "x", Type: "plain", Target: []string{"production"}},
				{Key: "P", Value: "p", Type: "plain", Target: []string{"preview"}},
				{Key: "A", Value: "br", Type: "plain", Target: []string{"production"}, GitBranch: "feat"},
			},
			want:   destination.Snapshot{"A": {Value: "1"}},
			report: destination.Report{Unchanged: []string{"A"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "1", Type: "plain", Target: []string{"production"}},
				{Key: "X", Value: "x", Type: "plain", Target: []string{"production"}},
				{Key: "P", Value: "p", Type: "plain", Target: []string{"preview"}},
				{Key: "A", Value: "br", Type: "plain", Target: []string{"production"}, GitBranch: "feat"},
			},
		},
		{
			name: "prune deletes single-target and detaches shared",
			envs: []fakeVar{
				{Key: "A", Value: "1", Type: "plain", Target: []string{"production"}},
				{Key: "X", Value: "x", Type: "sensitive", Target: []string{"production"}},
				{Key: "Y", Value: "y", Type: "plain", Target: []string{"production", "preview"}},
				{Key: "P", Value: "p", Type: "plain", Target: []string{"preview"}},
			},
			want:   destination.Snapshot{"A": {Value: "1"}},
			opts:   destination.ApplyOptions{Prune: true},
			report: destination.Report{Unchanged: []string{"A"}, Pruned: []string{"X", "Y"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "1", Type: "plain", Target: []string{"production"}},
				{Key: "Y", Value: "y", Type: "plain", Target: []string{"preview"}},
				{Key: "P", Value: "p", Type: "plain", Target: []string{"preview"}},
			},
			wantCalls: []string{
				"DELETE " + item + "id2",
				"PATCH " + item + "id3 {target=[preview]}",
			},
		},
		{
			name: "dry run writes nothing",
			envs: []fakeVar{
				{Key: "A", Value: "old", Type: "plain", Target: []string{"production"}},
				{Key: "X", Value: "x", Type: "plain", Target: []string{"production"}},
			},
			want:   destination.Snapshot{"A": {Value: "new"}, "N": {Value: "n", Secret: true}},
			opts:   destination.ApplyOptions{Prune: true, DryRun: true},
			report: destination.Report{Created: []string{"N"}, Updated: []string{"A"}, Pruned: []string{"X"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "old", Type: "plain", Target: []string{"production"}},
				{Key: "X", Value: "x", Type: "plain", Target: []string{"production"}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			for _, v := range tc.envs {
				f.add(v)
			}
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
			gotEnvs := make([]fakeVar, 0, len(f.envs))
			for _, v := range f.envs {
				v.ID = ""
				gotEnvs = append(gotEnvs, v)
			}
			if !reflect.DeepEqual(gotEnvs, tc.wantEnvs) {
				t.Fatalf("envs = %+v, want %+v", gotEnvs, tc.wantEnvs)
			}
			if got := f.mutations(); !reflect.DeepEqual(got, tc.wantCalls) {
				t.Fatalf("mutations = %v, want %v", got, tc.wantCalls)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	f := newFake(t)
	f.add(fakeVar{Key: "S", Value: "", Type: "sensitive", Target: []string{"production"}})
	f.fail = map[string]int{"PATCH /v9/projects/prj_1/env/id1": 403}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := newDest(t, srv, nil, nil)
	_, err := d.Apply(context.Background(), destination.Snapshot{"S": {Value: "v", Secret: true}}, destination.ApplyOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, s := range []string{"S", "403", "forced 403"} {
		if !strings.Contains(err.Error(), s) {
			t.Fatalf("err %q missing %q", err, s)
		}
	}
}

func TestRetryOn5xx(t *testing.T) {
	f := newFake(t)
	f.add(fakeVar{Key: "A", Value: "1", Type: "plain", Target: []string{"production"}})
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		f.handler().ServeHTTP(w, r)
	}))
	defer srv.Close()
	d := newDest(t, srv, nil, nil)
	got, err := d.Live(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got["A"].Value != "1" {
		t.Fatalf("Live = %v", got)
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

func TestCustomEnvironmentLive(t *testing.T) {
	f := newFake(t)
	f.customEnvs = map[string]string{"edge": "env_e1", "qa": "env_q1"}
	f.add(fakeVar{Key: "OURS", Value: "1", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}})
	f.add(fakeVar{Key: "SENS", Value: "hidden", Type: "sensitive", CustomEnvironmentIds: []string{"env_e1"}})
	f.add(fakeVar{Key: "OTHER", Value: "2", Type: "plain", CustomEnvironmentIds: []string{"env_q1"}})
	f.add(fakeVar{Key: "PROD", Value: "3", Type: "plain", Target: []string{"production"}})
	f.add(fakeVar{Key: "SHARED", Value: "4", Type: "plain", Target: []string{"production"}, CustomEnvironmentIds: []string{"env_e1"}})
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	d := newDest(t, srv, map[string]any{"environment": "edge", "project": "prj_1"}, nil)
	for i := 0; i < 2; i++ {
		got, err := d.Live(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		want := destination.Snapshot{"OURS": {Value: "1"}, "SENS": {Secret: true}, "SHARED": {Value: "4"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Live = %v, want %v", got, want)
		}
	}
	lookups := 0
	for _, c := range f.calls {
		if c == "GET /v9/projects/prj_1/custom-environments" {
			lookups++
		}
	}
	if lookups != 1 {
		t.Fatalf("custom environment resolved %d times, want once (calls: %v)", lookups, f.calls)
	}
}

func TestCustomEnvironmentUnknownSlug(t *testing.T) {
	f := newFake(t)
	f.customEnvs = map[string]string{"qa": "env_q1", "load": "env_l1"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := newDest(t, srv, map[string]any{"environment": "edge", "project": "prj_1"}, nil)
	_, err := d.Live(context.Background())
	for _, s := range []string{`"edge"`, "load, qa"} {
		if err == nil || !strings.Contains(err.Error(), s) {
			t.Fatalf("err = %v, want containing %q", err, s)
		}
	}
}

func TestCustomEnvironmentPlanGated(t *testing.T) {
	f := newFake(t)
	f.customEnvs = map[string]string{"edge": "env_e1"}
	f.fail = map[string]int{"GET /v9/projects/prj_1/custom-environments": 403}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := newDest(t, srv, map[string]any{"environment": "edge", "project": "prj_1"}, nil)
	_, err := d.Live(context.Background())
	for _, s := range []string{"403", "Pro and Enterprise", `"edge"`} {
		if err == nil || !strings.Contains(err.Error(), s) {
			t.Fatalf("err = %v, want containing %q", err, s)
		}
	}
}

func TestCustomEnvironmentApply(t *testing.T) {
	const list = "/v10/projects/prj_1/env"
	const item = "/v9/projects/prj_1/env/"
	tests := []struct {
		name      string
		envs      []fakeVar
		want      destination.Snapshot
		opts      destination.ApplyOptions
		report    destination.Report
		wantEnvs  []fakeVar // ID ignored
		wantCalls []string
	}{
		{
			name:   "create in the custom environment",
			want:   destination.Snapshot{"A": {Value: "1"}, "S": {Value: "sek", Secret: true}},
			report: destination.Report{Created: []string{"A", "S"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "1", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "S", Value: "sek", Type: "sensitive", CustomEnvironmentIds: []string{"env_e1"}},
			},
			wantCalls: []string{
				"POST " + list + " {customEnvironmentIds=[env_e1] key=A type=plain value=1 visibility=config}",
				"POST " + list + " {customEnvironmentIds=[env_e1] key=S type=sensitive value=sek visibility=secret}",
			},
		},
		{
			name: "update in place / unchanged",
			envs: []fakeVar{
				{Key: "A", Value: "old", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "U", Value: "same", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
			},
			want:   destination.Snapshot{"A": {Value: "new"}, "U": {Value: "same"}},
			report: destination.Report{Updated: []string{"A"}, Unchanged: []string{"U"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "new", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "U", Value: "same", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
			},
			wantCalls: []string{
				"PATCH " + item + "id1 {customEnvironmentIds=[env_e1] type=plain value=new visibility=config}",
			},
		},
		{
			name: "shared with a target or another custom environment is split",
			envs: []fakeVar{
				{Key: "A", Value: "shared", Type: "plain", Target: []string{"production"}, CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "B", Value: "shared", Type: "plain", CustomEnvironmentIds: []string{"env_q1", "env_e1"}},
			},
			want:   destination.Snapshot{"A": {Value: "edge-a"}, "B": {Value: "edge-b"}},
			report: destination.Report{Updated: []string{"A", "B"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "shared", Type: "plain", Target: []string{"production"}},
				{Key: "B", Value: "shared", Type: "plain", CustomEnvironmentIds: []string{"env_q1"}},
				{Key: "A", Value: "edge-a", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "B", Value: "edge-b", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
			},
			wantCalls: []string{
				"PATCH " + item + "id1 {customEnvironmentIds=[]}",
				"POST " + list + " {customEnvironmentIds=[env_e1] key=A type=plain value=edge-a visibility=config}",
				"PATCH " + item + "id2 {customEnvironmentIds=[env_q1]}",
				"POST " + list + " {customEnvironmentIds=[env_e1] key=B type=plain value=edge-b visibility=config}",
			},
		},
		{
			name: "prune deletes ours and detaches shared; other environments ignored",
			envs: []fakeVar{
				{Key: "A", Value: "1", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "X", Value: "x", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "Y", Value: "y", Type: "plain", Target: []string{"preview"}, CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "P", Value: "p", Type: "plain", Target: []string{"production"}},
			},
			want:   destination.Snapshot{"A": {Value: "1"}},
			opts:   destination.ApplyOptions{Prune: true},
			report: destination.Report{Unchanged: []string{"A"}, Pruned: []string{"X", "Y"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "1", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
				{Key: "Y", Value: "y", Type: "plain", Target: []string{"preview"}},
				{Key: "P", Value: "p", Type: "plain", Target: []string{"production"}},
			},
			wantCalls: []string{
				"DELETE " + item + "id2",
				"PATCH " + item + "id3 {customEnvironmentIds=[]}",
			},
		},
		{
			name:   "dry run writes nothing",
			envs:   []fakeVar{{Key: "A", Value: "old", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}}},
			want:   destination.Snapshot{"A": {Value: "new"}, "N": {Value: "n"}},
			opts:   destination.ApplyOptions{DryRun: true},
			report: destination.Report{Created: []string{"N"}, Updated: []string{"A"}},
			wantEnvs: []fakeVar{
				{Key: "A", Value: "old", Type: "plain", CustomEnvironmentIds: []string{"env_e1"}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.customEnvs = map[string]string{"edge": "env_e1", "qa": "env_q1"}
			for _, v := range tc.envs {
				f.add(v)
			}
			srv := httptest.NewServer(f.handler())
			defer srv.Close()

			d := newDest(t, srv, map[string]any{"environment": "edge", "project": "prj_1"}, nil)
			got, err := d.Apply(context.Background(), tc.want, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(norm(got), norm(tc.report)) {
				t.Fatalf("report = %+v, want %+v", got, tc.report)
			}
			gotEnvs := make([]fakeVar, 0, len(f.envs))
			for _, v := range f.envs {
				v.ID = ""
				gotEnvs = append(gotEnvs, v)
			}
			if !reflect.DeepEqual(gotEnvs, tc.wantEnvs) {
				t.Fatalf("envs = %+v, want %+v", gotEnvs, tc.wantEnvs)
			}
			if got := f.mutations(); !reflect.DeepEqual(got, tc.wantCalls) {
				t.Fatalf("mutations = %v, want %v", got, tc.wantCalls)
			}
		})
	}
}

// Development cannot hold a sensitive variable, and a development secret has
// to stay readable for `vercel env pull`, so it goes out as "encrypted". The
// fake refuses a sensitive write to development the way the real API does.
func TestDevelopmentSecretsAreEncrypted(t *testing.T) {
	const list = "/v10/projects/prj_1/env"
	const item = "/v9/projects/prj_1/env/"
	f := newFake(t)
	f.add(fakeVar{Key: "S", Value: "old", Type: "encrypted", Target: []string{"development"}})
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	d := newDest(t, srv, map[string]any{"environment": "development", "project": "prj_1"}, nil)
	want := destination.Snapshot{"S": {Value: "new", Secret: true}, "N": {Value: "n", Secret: true}, "P": {Value: "p"}}
	if _, err := d.Apply(context.Background(), want, destination.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{
		"POST " + list + " {key=N target=[development] type=encrypted value=n visibility=config}",
		"POST " + list + " {key=P target=[development] type=plain value=p visibility=config}",
		"PATCH " + item + "id1 {target=[development] type=encrypted value=new visibility=config}",
	}
	if got := f.mutations(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("mutations = %v, want %v", got, wantCalls)
	}
	for _, v := range f.envs {
		if v.Type == "sensitive" {
			t.Fatalf("%s is sensitive in development", v.Key)
		}
	}
	// The list returns ciphertext for them, which must not be read as a value.
	live, err := d.Live(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e := live["S"]; !e.Secret || e.Value != "" {
		t.Fatalf("live S = %+v, want a hidden secret", e)
	}
	if e := live["P"]; e.Secret || e.Value != "p" {
		t.Fatalf("live P = %+v, want plain p", e)
	}
}
