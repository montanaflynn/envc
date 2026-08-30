package sshkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// genLine returns an authorized_keys line for a fresh key of the given type.
func genLine(t *testing.T, typ, comment string) (string, ssh.PublicKey) {
	t.Helper()
	var pub any
	switch typ {
	case "ssh-ed25519":
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = p
	case "ssh-rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	case "ecdsa-sha2-nistp256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	default:
		t.Fatalf("genLine: unsupported %s", typ)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk)))
	if comment != "" {
		line += " " + comment
	}
	return line, spk
}

// skLine builds an sk-ssh-ed25519@openssh.com (FIDO) public key line, which
// age cannot encrypt to. Wire format: type, ed25519 point, application.
func skLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Type, Pub, App string
	}{"sk-ssh-ed25519@openssh.com", string(pub), "ssh:"})
	spk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spk))) + " alice@yubikey"
}

func TestParse(t *testing.T) {
	edLine, edKey := genLine(t, "ssh-ed25519", "alice@mac")
	rsaLine, rsaKey := genLine(t, "ssh-rsa", "")
	ecLine, _ := genLine(t, "ecdsa-sha2-nistp256", "alice@ec")
	skLine := skLine(t)

	tests := []struct {
		name     string
		in       string
		wantType string
		wantKey  ssh.PublicKey
		wantCmt  string
		wantLine string
		wantErr  string
	}{
		{name: "ed25519 with comment", in: edLine, wantType: "ssh-ed25519", wantKey: edKey, wantCmt: "alice@mac", wantLine: edLine},
		{name: "ed25519 trailing newline", in: edLine + "\n", wantType: "ssh-ed25519", wantKey: edKey, wantCmt: "alice@mac", wantLine: edLine},
		{name: "ed25519 surrounding whitespace", in: "  " + edLine + "  ", wantType: "ssh-ed25519", wantKey: edKey, wantCmt: "alice@mac", wantLine: edLine},
		{name: "rsa no comment", in: rsaLine, wantType: "ssh-rsa", wantKey: rsaKey, wantCmt: "", wantLine: rsaLine},
		{name: "options prefix dropped", in: `no-pty,command="x" ` + edLine, wantType: "ssh-ed25519", wantKey: edKey, wantCmt: "alice@mac", wantLine: edLine},
		{name: "ecdsa rejected", in: ecLine, wantErr: "age cannot encrypt"},
		{name: "sk rejected", in: skLine, wantErr: "age cannot encrypt"},
		{name: "empty", in: "", wantErr: "parse"},
		{name: "garbage", in: "ssh-ed25519 notbase64!!", wantErr: "parse"},
		{name: "comment line", in: "# just a comment", wantErr: "parse"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pk, err := Parse(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Parse(%q) = %+v, want error containing %q", tc.in, pk, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Parse(%q) error = %q, want containing %q", tc.in, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if pk.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", pk.Type, tc.wantType)
			}
			if pk.Comment != tc.wantCmt {
				t.Errorf("Comment = %q, want %q", pk.Comment, tc.wantCmt)
			}
			if pk.Line != tc.wantLine {
				t.Errorf("Line = %q, want %q", pk.Line, tc.wantLine)
			}
			if pk.Key == nil || string(pk.Key.Marshal()) != string(tc.wantKey.Marshal()) {
				t.Errorf("Key mismatch")
			}
		})
	}
}

func TestParseRejectMentionsType(t *testing.T) {
	_, err := Parse(skLine(t))
	if err == nil || !strings.Contains(err.Error(), "sk-ssh-ed25519@openssh.com") {
		t.Fatalf("error should name the rejected type, got %v", err)
	}
}

func TestParseAll(t *testing.T) {
	edLine, _ := genLine(t, "ssh-ed25519", "a")
	rsaLine, _ := genLine(t, "ssh-rsa", "b")
	ecLine, _ := genLine(t, "ecdsa-sha2-nistp256", "c")

	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "empty", in: "", want: nil},
		{name: "blank and comments only", in: "\n\n# hi\n   \n", want: nil},
		{name: "two keys", in: edLine + "\n" + rsaLine + "\n", want: []string{edLine, rsaLine}},
		{name: "crlf and comments", in: "# header\r\n" + edLine + "\r\n\r\n" + rsaLine, want: []string{edLine, rsaLine}},
		{name: "unsupported in the middle", in: edLine + "\n" + ecLine + "\n" + rsaLine, wantErr: true},
		{name: "garbage line", in: edLine + "\nnope\n", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAll(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseAll: want error, got %d keys", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAll: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d keys, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i].Line != tc.want[i] {
					t.Errorf("[%d] Line = %q, want %q", i, got[i].Line, tc.want[i])
				}
			}
		})
	}
}

func TestParseAllErrorHasLineNumber(t *testing.T) {
	edLine, _ := genLine(t, "ssh-ed25519", "a")
	_, err := ParseAll(edLine + "\n\nbad line here\n")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("want error naming line 3, got %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	for _, typ := range []string{"ssh-ed25519", "ssh-rsa"} {
		t.Run(typ, func(t *testing.T) {
			line, key := genLine(t, typ, "x")
			pk, err := Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			fp := Fingerprint(pk)
			if !strings.HasPrefix(fp, "SHA256:") {
				t.Fatalf("fingerprint %q lacks SHA256: prefix", fp)
			}
			if strings.HasSuffix(fp, "=") {
				t.Fatalf("fingerprint %q has base64 padding", fp)
			}
			if len(fp) != len("SHA256:")+43 {
				t.Fatalf("fingerprint %q has unexpected length %d", fp, len(fp))
			}
			if want := ssh.FingerprintSHA256(key); fp != want {
				t.Fatalf("fingerprint = %q, want %q", fp, want)
			}
			// Deterministic and independent of the comment.
			pk2, _ := Parse(strings.TrimSuffix(line, " x") + " other")
			if Fingerprint(pk2) != fp {
				t.Fatalf("fingerprint depends on comment")
			}
		})
	}
}

func TestFetchGitHub(t *testing.T) {
	edLine, _ := genLine(t, "ssh-ed25519", "")
	rsaLine, _ := genLine(t, "ssh-rsa", "")
	ecLine, _ := genLine(t, "ecdsa-sha2-nistp256", "")
	skLine := skLine(t)

	var gotUA, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotPath = r.URL.Path
		switch r.URL.Path {
		case "/alice.keys":
			_, _ = w.Write([]byte(edLine + "\n" + rsaLine + "\n"))
		case "/yubi.keys":
			_, _ = w.Write([]byte(skLine + "\n" + edLine + "\n" + ecLine + "\n"))
		case "/nokeys.keys":
			_, _ = w.Write([]byte("\n"))
		case "/broken.keys":
			_, _ = w.Write([]byte("this is not a key\n"))
		case "/boom.keys":
			http.Error(w, "nope", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	old := githubBaseURL
	githubBaseURL = srv.URL
	defer func() { githubBaseURL = old }()

	tests := []struct {
		name        string
		user        string
		wantLines   []string
		wantSkipped []string
		wantErr     string
	}{
		{name: "two supported keys", user: "alice", wantLines: []string{edLine, rsaLine}},
		{name: "unsupported skipped", user: "yubi", wantLines: []string{edLine},
			wantSkipped: []string{"sk-ssh-ed25519@openssh.com alice@yubikey", "ecdsa-sha2-nistp256"}},
		{name: "no keys", user: "nokeys"},
		{name: "unknown user", user: "ghost", wantErr: `github user "ghost" not found`},
		{name: "server error", user: "boom", wantErr: "500"},
		{name: "garbage body", user: "broken", wantErr: "parse"},
		{name: "bad user name", user: "../etc", wantErr: "invalid github user"},
		{name: "empty user name", user: "", wantErr: "invalid github user"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotUA, gotPath = "", ""
			keys, skipped, err := FetchGitHub(context.Background(), tc.user)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotUA != "envc" {
				t.Errorf("User-Agent = %q, want envc", gotUA)
			}
			if gotPath != "/"+tc.user+".keys" {
				t.Errorf("path = %q", gotPath)
			}
			if len(keys) != len(tc.wantLines) {
				t.Fatalf("got %d keys, want %d", len(keys), len(tc.wantLines))
			}
			for i := range keys {
				if keys[i].Line != tc.wantLines[i] {
					t.Errorf("[%d] = %q, want %q", i, keys[i].Line, tc.wantLines[i])
				}
			}
			if len(skipped) != len(tc.wantSkipped) {
				t.Fatalf("skipped = %q, want %q", skipped, tc.wantSkipped)
			}
			for i := range skipped {
				if skipped[i] != tc.wantSkipped[i] {
					t.Errorf("skipped[%d] = %q, want %q", i, skipped[i], tc.wantSkipped[i])
				}
			}
		})
	}
}

func TestFetchGitHubContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	old := githubBaseURL
	githubBaseURL = srv.URL
	defer func() { githubBaseURL = old }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := FetchGitHub(ctx, "alice")
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
