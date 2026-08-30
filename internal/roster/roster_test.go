package roster

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	ed25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ094754KQrqtdfmXm0p59RL07NAa++w1fXRZ3h20uWY alice@mac"
	rsaKey     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDeohmb7uKE0RdoEHpZAwEecIDeNZSBmbv1tA5MuiLOcw7CG4eNlIVp8arOgTLsOVWdhzr42V6PLqYM3F7KM0hgxE3/f3cYIoKTewTdgUVvf/aGDkPbUfqHUEeV9Q/wnnDlBDwR9m5dJFaazqx/xPgsb7L6E/7bUVtW9PJxFUqj5bnhukRMYOoNXhKlQZ+CZj1e8Miz5ectL5MyLJ2vVehBX5nZ/zu5zfo4lodn1DooAiTjXI8ESZaQjVR64LJmcRpqO9akmP9uIMunPR/vHfCoPyyht929t3OASztXiK8OEgrGfGGyrov0IE2ZMdlnyGLRLC6dHzeT+zbCXyexIGSF alice@old"
	ecdsaKey   = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFjO3jFNhiG6L36ywuen0CAx3LxLbYRon7Pjj/kBVpZU7he1kkYVBiAgymf37QkQ8arStFUdeNBtH9mphAnrW7E= bad@ecdsa"
	ageRcpt    = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
)

func writeRoster(t *testing.T, root, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, FileName), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sample() *Roster {
	r := New()
	r.Principals["alice"] = Principal{GitHub: "alice", Keys: []string{ed25519Key, rsaKey}}
	r.Principals["deploy"] = Principal{Keys: []string{ed25519Key}, Age: ageRcpt}
	r.Principals["carol"] = Principal{Age: ageRcpt}
	r.Groups["engineers"] = []string{"alice"}
	r.Groups["leads"] = []string{"alice", "carol"}
	r.Sync["production"] = map[string]DestConfig{
		"github": {"environment": "production"},
		"vercel": {"environment": "production", "project": "my-app"},
	}
	r.Sync["local"] = map[string]DestConfig{"dotenv": {"path": ".env", "override": ".env.local"}}
	r.Sync["preview"] = map[string]DestConfig{}
	return r
}

func TestNew(t *testing.T) {
	r := New()
	if r.Principals == nil || r.Groups == nil || r.Sync == nil {
		t.Fatal("New must return non-nil maps")
	}
	if len(r.Principals)+len(r.Groups)+len(r.Sync) != 0 {
		t.Fatal("New must return empty maps")
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantErr string
		check   func(t *testing.T, r *Roster)
	}{
		{
			name: "full",
			text: `principals:
  alice:
    github: alice
    keys:
      - ` + ed25519Key + `
  deploy:
    keys:
      - ` + ed25519Key + `
    age: ` + ageRcpt + `
groups:
  engineers: [alice]
sync:
  local:
    dotenv:
      path: .env
      override: .env.local
  production:
    github: { environment: production }
    vercel: { environment: production, project: my-app }
`,
			check: func(t *testing.T, r *Roster) {
				if got := r.Principals["alice"].GitHub; got != "alice" {
					t.Errorf("alice.github = %q", got)
				}
				if got := r.Principals["deploy"].Age; got != ageRcpt {
					t.Errorf("deploy.age = %q", got)
				}
				if got := r.Groups["engineers"]; !reflect.DeepEqual(got, []string{"alice"}) {
					t.Errorf("groups.engineers = %v", got)
				}
				if got := r.Sync["production"]["vercel"]["project"]; got != "my-app" {
					t.Errorf("sync.production.vercel.project = %v", got)
				}
				if got := r.Sync["local"]["dotenv"]["override"]; got != ".env.local" {
					t.Errorf("sync.local.dotenv.override = %v", got)
				}
			},
		},
		{
			name: "minimal has non-nil maps",
			text: "principals: {}\n",
			check: func(t *testing.T, r *Roster) {
				if r.Principals == nil || r.Groups == nil || r.Sync == nil {
					t.Error("Load must leave maps non-nil")
				}
			},
		},
		{
			name: "empty sync env block",
			text: "sync:\n  preview: {}\n",
			check: func(t *testing.T, r *Roster) {
				if _, ok := r.Sync["preview"]; !ok {
					t.Error("sync.preview missing")
				}
			},
		},
		{
			name:    "unknown top-level key",
			text:    "bogus: 1\n",
			wantErr: "bogus",
		},
		{
			name:    "unknown principal field",
			text:    "principals:\n  alice:\n    email: a@b\n",
			wantErr: "email",
		},
		{
			name:    "invalid yaml",
			text:    "principals: [\n",
			wantErr: "yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeRoster(t, root, tt.text)
			r, err := Load(root)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not mention %q", err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), FileName) {
					t.Errorf("error %q does not mention the file path", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, r)
		})
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error should wrap fs.ErrNotExist: %v", err)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	root := t.TempDir()
	r := sample()
	if err := r.Save(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 644", info.Mode().Perm())
	}
	got, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v", got, r)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestSaveCanonical(t *testing.T) {
	root := t.TempDir()
	r := New()
	r.Principals["zed"] = Principal{Keys: []string{ed25519Key}}
	r.Principals["alice"] = Principal{GitHub: "alice", Keys: []string{ed25519Key}, Age: ageRcpt}
	r.Groups["leads"] = []string{"zed"}
	r.Groups["engineers"] = []string{"alice", "zed"}
	r.Sync["production"] = map[string]DestConfig{"vercel": {"project": "p", "environment": "production"}}
	if err := r.Save(root); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, FileName))
	want := `principals:
  alice:
    github: alice
    keys:
      - ` + ed25519Key + `
    age: ` + ageRcpt + `
  zed:
    keys:
      - ` + ed25519Key + `
groups:
  engineers:
    - alice
    - zed
  leads:
    - zed
sync:
  production:
    vercel:
      environment: production
      project: p
`
	if string(b) != want {
		t.Errorf("canonical output mismatch:\n--- got ---\n%s\n--- want ---\n%s", b, want)
	}
}

func TestSaveNilMaps(t *testing.T) {
	root := t.TempDir()
	r := &Roster{}
	if err := r.Save(root); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, FileName))
	want := "principals: {}\n"
	if string(b) != want {
		t.Errorf("got:\n%s\nwant:\n%s", b, want)
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("nil maps must not serialize as null:\n%s", b)
	}
}

func TestSaveOverwrites(t *testing.T) {
	root := t.TempDir()
	writeRoster(t, root, "groups:\n  old: []\n# a comment\n")
	r := New()
	r.Principals["new"] = Principal{Age: ageRcpt}
	if err := r.Save(root); err != nil {
		t.Fatal(err)
	}
	got, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Groups["old"]; ok {
		t.Error("Save must overwrite, not merge")
	}
	if _, ok := got.Principals["new"]; !ok {
		t.Error("saved principal missing")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(r *Roster)
		want   []string // Problem.Path values expected (exact set)
	}{
		{name: "valid", mutate: func(*Roster) {}},
		{
			name:   "bad principal name",
			mutate: func(r *Roster) { r.Principals["Bad Name"] = Principal{Keys: []string{ed25519Key}} },
			want:   []string{"principals.Bad Name"},
		},
		{
			name:   "name starting with dot",
			mutate: func(r *Roster) { r.Principals[".x"] = Principal{Keys: []string{ed25519Key}} },
			want:   []string{"principals..x"},
		},
		{
			name:   "bad group name",
			mutate: func(r *Roster) { r.Groups["Ops"] = []string{"alice"} },
			want:   []string{"groups.Ops"},
		},
		{
			name:   "unparseable key",
			mutate: func(r *Roster) { r.Principals["bob"] = Principal{Keys: []string{"ssh-ed25519 notbase64!!"}} },
			want:   []string{"principals.bob.keys[0]"},
		},
		{
			name:   "unsupported key type",
			mutate: func(r *Roster) { r.Principals["bob"] = Principal{Keys: []string{ed25519Key, ecdsaKey}} },
			want:   []string{"principals.bob.keys[1]"},
		},
		{
			name:   "no keys and no age",
			mutate: func(r *Roster) { r.Principals["bob"] = Principal{GitHub: "bob"} },
			want:   []string{"principals.bob"},
		},
		{
			name:   "bad age recipient",
			mutate: func(r *Roster) { r.Principals["bob"] = Principal{Age: "AGE-SECRET-KEY-1XYZ"} },
			want:   []string{"principals.bob.age"},
		},
		{
			name:   "group member unknown",
			mutate: func(r *Roster) { r.Groups["leads"] = []string{"alice", "nobody"} },
			want:   []string{"groups.leads[1]"},
		},
		{
			name:   "group member is a group",
			mutate: func(r *Roster) { r.Groups["all"] = []string{"engineers"} },
			want:   []string{"groups.all[0]"},
		},
		{
			name: "name is both principal and group",
			mutate: func(r *Roster) {
				r.Groups["alice"] = []string{"carol"}
			},
			want: []string{"groups.alice"},
		},
		{
			name:   "empty sync env block is fine",
			mutate: func(r *Roster) { r.Sync["staging"] = map[string]DestConfig{} },
		},
		{
			name:   "nil maps are fine",
			mutate: func(r *Roster) { r.Principals, r.Groups, r.Sync = nil, nil, nil },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := sample()
			tt.mutate(r)
			probs := r.Validate()
			var paths []string
			for _, p := range probs {
				if p.Msg == "" {
					t.Errorf("problem %q has empty message", p.Path)
				}
				paths = append(paths, p.Path)
			}
			sort.Strings(paths)
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if len(paths) == 0 && len(want) == 0 {
				return
			}
			if !reflect.DeepEqual(paths, want) {
				t.Errorf("problems = %v, want paths %v", probs, want)
			}
		})
	}
}

func TestValidateDeterministic(t *testing.T) {
	r := sample()
	r.Principals["zz"] = Principal{}
	r.Principals["aa"] = Principal{}
	r.Groups["g1"] = []string{"nobody"}
	r.Groups["g0"] = []string{"nobody"}
	first := r.Validate()
	for i := 0; i < 5; i++ {
		if got := r.Validate(); !reflect.DeepEqual(got, first) {
			t.Fatalf("Validate order not stable: %v vs %v", got, first)
		}
	}
}

func TestIsPrincipalIsGroup(t *testing.T) {
	r := sample()
	if !r.IsPrincipal("alice") || r.IsPrincipal("engineers") || r.IsPrincipal("nobody") {
		t.Error("IsPrincipal wrong")
	}
	if !r.IsGroup("engineers") || r.IsGroup("alice") || r.IsGroup("nobody") {
		t.Error("IsGroup wrong")
	}
	var nilMaps Roster
	if nilMaps.IsPrincipal("x") || nilMaps.IsGroup("x") {
		t.Error("nil maps should report false")
	}
}

func TestExpand(t *testing.T) {
	tests := []struct {
		name    string
		access  []string
		want    []string
		wantErr string
	}{
		{name: "empty", access: nil, want: []string{}},
		{name: "principal", access: []string{"deploy"}, want: []string{"deploy"}},
		{name: "group", access: []string{"leads"}, want: []string{"alice", "carol"}},
		{name: "dedupe and sort", access: []string{"leads", "engineers", "deploy", "alice"}, want: []string{"alice", "carol", "deploy"}},
		{name: "unknown", access: []string{"leads", "nobody"}, wantErr: "nobody"},
	}
	r := sample()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.Expand(tt.access)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want mention of %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				got = []string{}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeysFor(t *testing.T) {
	r := sample()
	got, err := r.KeysFor([]string{"deploy", "alice"})
	if err != nil {
		t.Fatal(err)
	}
	want := []KeyRef{
		{Principal: "deploy", SSH: ed25519Key},
		{Principal: "deploy", Age: ageRcpt},
		{Principal: "alice", SSH: ed25519Key},
		{Principal: "alice", SSH: rsaKey},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if _, err := r.KeysFor([]string{"alice", "nobody"}); err == nil || !strings.Contains(err.Error(), "nobody") {
		t.Errorf("expected unknown principal error, got %v", err)
	}
	if _, err := r.KeysFor([]string{"engineers"}); err == nil {
		t.Error("groups are not principals; expected error")
	}
	empty, err := r.KeysFor(nil)
	if err != nil || len(empty) != 0 {
		t.Errorf("KeysFor(nil) = %v, %v", empty, err)
	}
}

func TestEnvironmentsWith(t *testing.T) {
	r := sample()
	tests := []struct {
		dest string
		want []string
	}{
		{"github", []string{"production"}},
		{"vercel", []string{"production"}},
		{"dotenv", []string{"local"}},
		{"convex", []string{}},
		{"", []string{"local", "production"}},
	}
	for _, tt := range tests {
		got := r.EnvironmentsWith(tt.dest)
		if got == nil {
			got = []string{}
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("EnvironmentsWith(%q) = %v, want %v", tt.dest, got, tt.want)
		}
	}
}

func TestRemovePrincipal(t *testing.T) {
	r := sample()
	r.Groups["zeta"] = []string{"alice", "carol", "alice"}
	got := r.RemovePrincipal("alice")
	if want := []string{"engineers", "leads", "zeta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("groups = %v, want %v", got, want)
	}
	if r.IsPrincipal("alice") {
		t.Error("alice still a principal")
	}
	for name, members := range r.Groups {
		for _, m := range members {
			if m == "alice" {
				t.Errorf("alice still in group %s", name)
			}
		}
	}
	if !reflect.DeepEqual(r.Groups["leads"], []string{"carol"}) {
		t.Errorf("leads = %v", r.Groups["leads"])
	}
	if !reflect.DeepEqual(r.Groups["engineers"], []string{}) {
		t.Errorf("engineers = %#v, want empty non-nil", r.Groups["engineers"])
	}
	if got := r.RemovePrincipal("nobody"); len(got) != 0 {
		t.Errorf("removing unknown principal returned %v", got)
	}
}
