package state

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPaths(t *testing.T) {
	if got, want := EnvelopePath("/repo", "production"), filepath.Join("/repo", ".envc", "state", "production", "envelope.yaml"); got != want {
		t.Errorf("EnvelopePath = %q, want %q", got, want)
	}
	if got, want := SyncPath("/repo", "production"), filepath.Join("/repo", ".envc", "state", "production", "sync.yaml"); got != want {
		t.Errorf("SyncPath = %q, want %q", got, want)
	}
}

func TestEnvelopeMissing(t *testing.T) {
	e, err := LoadEnvelope(t.TempDir(), "production")
	if err != nil || e != nil {
		t.Fatalf("missing envelope = %v, %v; want nil, nil", e, err)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	root := t.TempDir()
	e := &Envelope{Version: 1, Recipients: []string{"SHA256:abc", "age1xyz"}, Key: "QUJD", MAC: "REVG"}
	if err := e.Save(root, "production"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(EnvelopePath(root, "production"))
	want := `# Written by envc. Commit it. Never edit or delete: it holds the data key that
# unlocks the ENC[…] values in environments/production.yaml.
version: 1
recipients:
  - SHA256:abc
  - age1xyz
key: QUJD
mac: REVG
`
	if string(b) != want {
		t.Errorf("canonical output mismatch:\n--- got ---\n%s\n--- want ---\n%s", b, want)
	}
	got, err := LoadEnvelope(root, "production")
	if err != nil || !reflect.DeepEqual(got, e) {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	if err := RemoveEnvelope(root, "production"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(EnvelopePath(root, "production")); !os.IsNotExist(err) {
		t.Fatal("envelope not removed")
	}
	if err := RemoveEnvelope(root, "production"); err != nil {
		t.Fatalf("removing a missing envelope: %v", err)
	}
}

func TestEnvelopeErrors(t *testing.T) {
	root := t.TempDir()
	path := EnvelopePath(root, "production")
	os.MkdirAll(filepath.Dir(path), 0o755)
	for _, tt := range []struct{ name, text, want string }{
		{"unknown field", "version: 1\nrecipients: []\nkey: x\nmac: y\nnonce: z\n", "nonce"},
		{"invalid yaml", "version: [\n", "yaml"},
	} {
		os.WriteFile(path, []byte(tt.text), 0o644)
		_, err := LoadEnvelope(root, "production")
		if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: err = %v", tt.name, err)
		}
	}
}

func TestEnvelopeValidate(t *testing.T) {
	for _, tt := range []struct {
		name string
		e    Envelope
		want []string
	}{
		{"ok", Envelope{Version: 1, Recipients: []string{"a"}, Key: "k", MAC: "m"}, nil},
		{"version", Envelope{Version: 2, Recipients: []string{"a"}, Key: "k"}, []string{"version"}},
		{"no key", Envelope{Version: 1, Recipients: []string{"a"}}, []string{"key"}},
		{"no recipients", Envelope{Version: 1, Key: "k"}, []string{"recipients"}},
	} {
		var got []string
		for _, p := range tt.e.Validate() {
			got = append(got, p.Path)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: paths = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSyncMissing(t *testing.T) {
	root := t.TempDir()
	s, err := LoadSync(root, "production")
	if err != nil || s == nil || len(s) != 0 {
		t.Fatalf("missing sync = %v, %v", s, err)
	}
	os.MkdirAll(EnvDir(root, "production"), 0o755)
	if s, err = LoadSync(root, "production"); err != nil || s == nil || len(s) != 0 {
		t.Fatalf("missing sync in existing dir = %v, %v", s, err)
	}
}

func TestSyncRoundTrip(t *testing.T) {
	root := t.TempDir()
	s := Sync{
		"vercel": {At: time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC), KeyID: "9b1f2e07", Keys: map[string]string{}},
		"github": {
			At:    time.Date(2026, 8, 29, 15, 0, 0, 123456789, time.FixedZone("PST", -8*3600)),
			KeyID: "9b1f2e07",
			Keys:  map[string]string{"LOG_LEVEL": "0d4a9e21c7b3f815", "DATABASE_URL": "7c11a0b3e9f04d21"},
		},
	}
	if err := s.Save(root, "production"); err != nil {
		t.Fatal(err)
	}
	path := SyncPath(root, "production")
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 644", info.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	want := `# Written by envc sync. Commit it. Safe to delete; the next sync recreates it.
github:
  at: 2026-08-29T23:00:00Z
  key_id: 9b1f2e07
  keys:
    DATABASE_URL: 7c11a0b3e9f04d21
    LOG_LEVEL: 0d4a9e21c7b3f815
vercel:
  at: 2026-08-30T01:02:03Z
  key_id: 9b1f2e07
  keys: {}
`
	if string(b) != want {
		t.Errorf("canonical output mismatch:\n--- got ---\n%s\n--- want ---\n%s", b, want)
	}
	got, err := LoadSync(root, "production")
	if err != nil {
		t.Fatal(err)
	}
	if !got["github"].At.Equal(s["github"].At.Truncate(time.Second)) || !reflect.DeepEqual(got["github"].Keys, s["github"].Keys) || got["vercel"].KeyID != "9b1f2e07" || len(got["vercel"].Keys) != 0 {
		t.Errorf("round trip mismatch: %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestSyncUpdatedRoundTrip(t *testing.T) {
	root := t.TempDir()
	s := Sync{"vercel": {
		At:      time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC),
		KeyID:   "9b1f2e07",
		Keys:    map[string]string{"API_KEY": "7c11a0b3e9f04d21"},
		Updated: map[string]time.Time{"API_KEY": time.Date(2026, 9, 24, 5, 0, 1, 123000000, time.FixedZone("PDT", -7*3600))},
	}}
	if err := s.Save(root, "production"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(SyncPath(root, "production"))
	want := `# Written by envc sync. Commit it. Safe to delete; the next sync recreates it.
vercel:
  at: 2026-09-24T12:00:00Z
  key_id: 9b1f2e07
  keys:
    API_KEY: 7c11a0b3e9f04d21
  updated:
    API_KEY: 2026-09-24T12:00:01.123Z
`
	if string(b) != want {
		t.Errorf("canonical output mismatch:\n--- got ---\n%s\n--- want ---\n%s", b, want)
	}
	got, err := LoadSync(root, "production")
	if err != nil {
		t.Fatal(err)
	}
	if !got["vercel"].Updated["API_KEY"].Equal(s["vercel"].Updated["API_KEY"]) {
		t.Errorf("updated round trip = %v", got["vercel"].Updated)
	}

	// Records written before timestamps existed still load, with none.
	os.WriteFile(SyncPath(root, "production"), []byte("github:\n  at: 2026-08-29T23:00:00Z\n  key_id: x\n  keys: {}\n"), 0o644)
	if got, err = LoadSync(root, "production"); err != nil || len(got["github"].Updated) != 0 {
		t.Fatalf("old record = %+v, %v", got, err)
	}
}

func TestSyncErrors(t *testing.T) {
	root := t.TempDir()
	path := SyncPath(root, "production")
	os.MkdirAll(filepath.Dir(path), 0o755)
	for _, tt := range []struct{ name, text, want string }{
		{"unknown field", "github:\n  at: 2026-08-29T23:00:00Z\n  key_id: x\n  keys: {}\n  commit: abc\n", "commit"},
		{"invalid yaml", "github: [\n", "yaml"},
		{"bad time", "github:\n  at: yesterday\n  key_id: x\n  keys: {}\n", "yesterday"},
	} {
		os.WriteFile(path, []byte(tt.text), 0o644)
		_, err := LoadSync(root, "production")
		if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: err = %v", tt.name, err)
		}
	}
}

func TestRemove(t *testing.T) {
	root := t.TempDir()
	if err := (&Envelope{Version: 1, Key: "k", Recipients: []string{"a"}}).Save(root, "production"); err != nil {
		t.Fatal(err)
	}
	if err := (Sync{}).Save(root, "production"); err != nil {
		t.Fatal(err)
	}
	if err := Remove(root, "production"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(EnvDir(root, "production")); !os.IsNotExist(err) {
		t.Fatal("state dir still exists")
	}
	if err := Remove(root, "production"); err != nil {
		t.Fatalf("removing a missing dir: %v", err)
	}
}
