package envfile

import (
	"errors"
	"github.com/montanaflynn/envc/internal/state"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const token = "ENC[envc1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=]"

func bp(b bool) *bool { return &b }

func writeEnv(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sample() *File {
	f := New()
	f.Access = []string{"leads", "deploy"}
	f.Config["NEXT_PUBLIC_APP_URL"] = Entry{Description: "Public site URL", Secret: bp(false), Value: "https://my-app.vercel.app"}
	f.Config["LOG_LEVEL"] = Entry{Secret: bp(false), Value: "warn", Enum: []string{"debug", "info", "warn", "error"}}
	f.Config["DATABASE_URL"] = Entry{Description: "Postgres", Secret: bp(true), Value: token, Pattern: "^postgres(ql)?://"}
	f.Config["API_KEY"] = Entry{Secret: bp(true), Value: token}
	f.Crypto = &state.Envelope{Version: 1, Recipients: []string{"SHA256:abc", "age1xyz"}, Key: "QUJD", MAC: "REVG"}
	return f
}

func TestPath(t *testing.T) {
	got := Path("/repo", "production")
	want := filepath.Join("/repo", ".envc", "environments", "production.yaml")
	if got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

func TestList(t *testing.T) {
	root := t.TempDir()
	got, err := List(root)
	if err != nil {
		t.Fatalf("List on missing config dir: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
	for _, name := range []string{"production.yaml", "local.yaml", "preview.yaml", "notes.txt", ".hidden.yaml"} {
		writeEnv(t, filepath.Join(root, Dir, name), "access: []\nconfig: {}\n")
	}
	if err := os.Mkdir(filepath.Join(root, Dir, "sub.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err = List(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".hidden", "local", "preview", "production"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List = %v, want %v", got, want)
	}
}

func TestNew(t *testing.T) {
	f := New()
	if f.Access == nil || len(f.Access) != 0 {
		t.Errorf("Access = %#v, want empty non-nil", f.Access)
	}
	if f.Config == nil || len(f.Config) != 0 {
		t.Errorf("Config = %#v, want empty non-nil", f.Config)
	}
	if f.Crypto != nil {
		t.Error("Crypto should be nil")
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantErr string
		check   func(t *testing.T, f *File)
	}{
		{
			name: "full",
			text: `access: [leads, deploy]
config:
  NEXT_PUBLIC_APP_URL:
    description: Public site URL
    secret: false
    value: https://my-app.vercel.app
  LOG_LEVEL:
    secret: false
    value: warn
    enum: [debug, info, warn, error]
  DATABASE_URL:
    description: Postgres
    secret: true
    value: ` + token + `
    pattern: '^postgres(ql)?://'
    required: false
    kind: env
  CERT:
    secret: false
    value: |
      line1
      line2
`,
			check: func(t *testing.T, f *File) {
				if !reflect.DeepEqual(f.Access, []string{"leads", "deploy"}) {
					t.Errorf("access = %v", f.Access)
				}
				e := f.Config["DATABASE_URL"]
				if !e.IsSecret() || e.IsRequired() || e.Pattern != "^postgres(ql)?://" || e.Kind != "env" || e.Value != token {
					t.Errorf("DATABASE_URL = %+v", e)
				}
				if e := f.Config["LOG_LEVEL"]; e.IsSecret() || !e.IsRequired() || len(e.Enum) != 4 {
					t.Errorf("LOG_LEVEL = %+v", e)
				}
				if got := f.Config["CERT"].Value; got != "line1\nline2\n" {
					t.Errorf("CERT.value = %q", got)
				}
				if f.Crypto != nil {
					t.Errorf("Load must not attach an envelope; got %+v", f.Crypto)
				}
			},
		},
		{
			name: "empty file has non-nil maps",
			text: "access: []\nconfig: {}\n",
			check: func(t *testing.T, f *File) {
				if f.Config == nil {
					t.Error("Config must be non-nil after Load")
				}
				if f.Crypto != nil {
					t.Error("Crypto should be nil when absent")
				}
			},
		},
		{
			name: "missing secret field is detectable",
			text: "access: []\nconfig:\n  A:\n    value: x\n",
			check: func(t *testing.T, f *File) {
				if f.Config["A"].Secret != nil {
					t.Error("Secret should be nil when secret: is absent")
				}
			},
		},
		{
			name: "explicit false is not nil",
			text: "access: []\nconfig:\n  A:\n    secret: false\n    value: x\n",
			check: func(t *testing.T, f *File) {
				if s := f.Config["A"].Secret; s == nil || *s {
					t.Errorf("Secret = %v, want &false", s)
				}
			},
		},
		{
			name:    "unknown top-level key",
			text:    "access: []\nconfig: {}\nextra: 1\n",
			wantErr: "extra",
		},
		{
			name:    "unknown entry field",
			text:    "access: []\nconfig:\n  A:\n    secret: false\n    value: x\n    comment: hi\n",
			wantErr: "comment",
		},
		{
			name:    "crypto block is not part of the manifest",
			text:    "access: []\nconfig: {}\ncrypto:\n  version: 1\n  key: QUJD\n",
			wantErr: "crypto",
		},
		{
			name:    "invalid yaml",
			text:    "access: [\n",
			wantErr: "yaml",
		},
		{
			name:    "wrong type",
			text:    "access: []\nconfig:\n  A:\n    secret: maybe\n    value: x\n",
			wantErr: "line 4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := Path(t.TempDir(), "production")
			writeEnv(t, path, tt.text)
			f, err := Load(path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not mention %q", err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), path) {
					t.Errorf("error %q does not mention the path", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, f)
		})
	}
}

func TestLoadMissing(t *testing.T) {
	path := Path(t.TempDir(), "nope")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("should wrap fs.ErrNotExist: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not mention the path", err)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	root := t.TempDir()
	path := Path(root, "production")
	f := sample()
	f.Config["CERT"] = Entry{Secret: bp(false), Value: "-----BEGIN-----\nabc\n-----END-----\n"}
	f.Config["NO_TRAILING"] = Entry{Secret: bp(false), Value: "a\nb"}
	f.Config["EMPTY"] = Entry{Secret: bp(false), Value: ""}
	f.Config["TRICKY"] = Entry{Secret: bp(false), Value: "yes", Required: bp(false), Kind: "env"}
	f.Config["SPACES"] = Entry{Secret: bp(false), Value: "  padded  "}
	f.Config["COLON"] = Entry{Secret: bp(false), Value: "a: b #c"}
	f.Config["NUMERIC"] = Entry{Secret: bp(false), Value: "0123"}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 644", info.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Crypto = nil // the envelope lives in .envc/state, never in the manifest
	if !reflect.DeepEqual(got, f) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v", got, f)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestSaveCanonical(t *testing.T) {
	path := Path(t.TempDir(), "production")
	f := sample()
	f.Config["CERT"] = Entry{Secret: bp(false), Value: "line1\nline2\n"}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	want := `access:
  - leads
  - deploy
config:
  API_KEY:
    secret: true
    value: ` + token + `
  CERT:
    secret: false
    value: |
      line1
      line2
  DATABASE_URL:
    description: Postgres
    secret: true
    value: ` + token + `
    pattern: ^postgres(ql)?://
  LOG_LEVEL:
    secret: false
    value: warn
    enum:
      - debug
      - info
      - warn
      - error
  NEXT_PUBLIC_APP_URL:
    description: Public site URL
    secret: false
    value: https://my-app.vercel.app
`
	if string(b) != want {
		t.Errorf("canonical output mismatch:\n--- got ---\n%s\n--- want ---\n%s", b, want)
	}
}

func TestSaveEmpty(t *testing.T) {
	tests := []struct {
		name string
		f    *File
	}{
		{"New", New()},
		{"nil maps", &File{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := Path(t.TempDir(), "local")
			if err := tt.f.Save(path); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(path)
			if string(b) != "access: []\nconfig: {}\n" {
				t.Errorf("got %q", b)
			}
		})
	}
}

func TestSaveMissingDir(t *testing.T) {
	path := Path(t.TempDir(), "local")
	if err := New().Save(path); err != nil {
		t.Fatalf("Save should create config dir: %v", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(f *File)
		want   []string // Problem.Path values (exact set)
	}{
		{name: "valid", mutate: func(*File) {}},
		{name: "empty file", mutate: func(f *File) { *f = *New() }},
		{name: "nil maps", mutate: func(f *File) { *f = File{} }},
		{
			name:   "bad key name",
			mutate: func(f *File) { f.Config["1BAD"] = Entry{Secret: bp(false), Value: "x"} },
			want:   []string{"config.1BAD"},
		},
		{
			name:   "key with dash",
			mutate: func(f *File) { f.Config["A-B"] = Entry{Secret: bp(false), Value: "x"} },
			want:   []string{"config.A-B"},
		},
		{
			name:   "secret missing",
			mutate: func(f *File) { f.Config["X"] = Entry{Value: "x"} },
			want:   []string{"config.X.secret"},
		},
		{
			name:   "kind file reserved",
			mutate: func(f *File) { f.Config["X"] = Entry{Secret: bp(false), Value: "x", Kind: "file"} },
			want:   []string{"config.X.kind"},
		},
		{
			name:   "kind unknown",
			mutate: func(f *File) { f.Config["X"] = Entry{Secret: bp(false), Value: "x", Kind: "blob"} },
			want:   []string{"config.X.kind"},
		},
		{
			name:   "kind env ok",
			mutate: func(f *File) { f.Config["X"] = Entry{Secret: bp(false), Value: "x", Kind: "env"} },
		},
		{
			name:   "bad pattern",
			mutate: func(f *File) { f.Config["X"] = Entry{Secret: bp(false), Value: "x", Pattern: "("} },
			want:   []string{"config.X.pattern"},
		},
		{
			name:   "empty enum entry",
			mutate: func(f *File) { f.Config["X"] = Entry{Secret: bp(false), Value: "a", Enum: []string{"a", ""}} },
			want:   []string{"config.X.enum[1]"},
		},
		{
			name:   "duplicate enum entry",
			mutate: func(f *File) { f.Config["X"] = Entry{Secret: bp(false), Value: "a", Enum: []string{"a", "b", "a"}} },
			want:   []string{"config.X.enum[2]"},
		},
		{
			name:   "token on public value",
			mutate: func(f *File) { f.Config["LOG_LEVEL"] = Entry{Secret: bp(false), Value: token} },
			want:   []string{"config.LOG_LEVEL.value"},
		},
		{
			name:   "plaintext secret with crypto",
			mutate: func(f *File) { f.Config["API_KEY"] = Entry{Secret: bp(true), Value: "sk_live_x"} },
			want:   []string{"config.API_KEY.value"},
		},
		{
			name: "plaintext secret without crypto is allowed",
			mutate: func(f *File) {
				f.Crypto = nil
				f.Config["API_KEY"] = Entry{Secret: bp(true), Value: "sk_live_x"}
				f.Config["DATABASE_URL"] = Entry{Secret: bp(true), Value: "postgres://x"}
			},
		},
		{
			name:   "empty access with secrets",
			mutate: func(f *File) { f.Access = nil },
			want:   []string{"access"},
		},
		{
			name: "empty access without secrets",
			mutate: func(f *File) {
				f.Access = nil
				f.Crypto = nil
				delete(f.Config, "API_KEY")
				delete(f.Config, "DATABASE_URL")
			},
		},
		{
			name: "multiple problems on one entry",
			mutate: func(f *File) {
				f.Config["bad-name"] = Entry{Value: "x", Kind: "file", Pattern: "["}
			},
			want: []string{"config.bad-name", "config.bad-name.secret", "config.bad-name.kind", "config.bad-name.pattern"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := sample()
			tt.mutate(f)
			probs := f.Validate()
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

func TestValidateMessages(t *testing.T) {
	f := sample()
	f.Config["X"] = Entry{Value: "x", Kind: "file"}
	msgs := map[string]string{}
	for _, p := range f.Validate() {
		msgs[p.Path] = p.Msg
	}
	if !strings.Contains(msgs["config.X.secret"], "explicitly") {
		t.Errorf("secret msg = %q", msgs["config.X.secret"])
	}
	if !strings.Contains(msgs["config.X.kind"], "reserved") {
		t.Errorf("kind msg = %q", msgs["config.X.kind"])
	}
}

func TestValidateDeterministic(t *testing.T) {
	f := sample()
	for _, k := range []string{"z", "y", "x", "w"} {
		f.Config[k] = Entry{Value: "v"}
	}
	first := f.Validate()
	for i := 0; i < 5; i++ {
		if got := f.Validate(); !reflect.DeepEqual(got, first) {
			t.Fatalf("Validate order not stable: %v vs %v", got, first)
		}
	}
	if first[0].Path != "config.w.secret" {
		t.Errorf("problems should be sorted by key; first = %v", first[0])
	}
}

func TestKeyHelpers(t *testing.T) {
	f := sample()
	f.Config["PLAIN_SECRET"] = Entry{Secret: bp(true), Value: "hunter2"}
	f.Config["NIL_SECRET"] = Entry{Value: "x"}
	if got, want := f.Keys(), []string{"API_KEY", "DATABASE_URL", "LOG_LEVEL", "NEXT_PUBLIC_APP_URL", "NIL_SECRET", "PLAIN_SECRET"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Keys = %v, want %v", got, want)
	}
	if got, want := f.SecretKeys(), []string{"API_KEY", "DATABASE_URL", "PLAIN_SECRET"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SecretKeys = %v, want %v", got, want)
	}
	if got, want := f.PlaintextSecretKeys(), []string{"PLAIN_SECRET"}; !reflect.DeepEqual(got, want) {
		t.Errorf("PlaintextSecretKeys = %v, want %v", got, want)
	}
	var empty File
	if len(empty.Keys()) != 0 || len(empty.SecretKeys()) != 0 || len(empty.PlaintextSecretKeys()) != 0 {
		t.Error("nil map helpers should return empty")
	}
}

func TestEntryDefaults(t *testing.T) {
	var e Entry
	if e.IsSecret() {
		t.Error("nil Secret should be false")
	}
	if !e.IsRequired() {
		t.Error("nil Required should be true")
	}
	e.Secret, e.Required = bp(true), bp(false)
	if !e.IsSecret() || e.IsRequired() {
		t.Error("explicit values ignored")
	}
}
