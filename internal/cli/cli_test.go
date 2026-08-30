package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/montanaflynn/envc/internal/app"
	"github.com/montanaflynn/envc/internal/destination"
)

func run(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Main(args, strings.NewReader(stdin), &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

// runInDir runs Main with the test chdir'd into dir (walk-up starts there).
func runInDir(t *testing.T, dir string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Chdir(dir)
	return run(t, "", args...)
}

func TestVersion(t *testing.T) {
	code, out, errs := run(t, "", "version")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	if want := "envc " + Version + "\n"; out != want {
		t.Errorf("stdout %q, want %q", out, want)
	}
	if errs != "" {
		t.Errorf("stderr %q, want empty", errs)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, out, errs := run(t, "", "nope")
	if code != app.ExitUsage {
		t.Fatalf("exit %d, want %d", code, app.ExitUsage)
	}
	if out != "" {
		t.Errorf("stdout %q, want empty", out)
	}
	if !strings.HasPrefix(errs, "envc: unknown command \"nope\"") {
		t.Errorf("stderr %q", errs)
	}
	if !strings.Contains(errs, "Run 'envc --help'") {
		t.Errorf("stderr missing help hint: %q", errs)
	}
}

func TestUnknownSubcommand(t *testing.T) {
	code, _, errs := run(t, "", "env", "nope")
	if code != app.ExitUsage {
		t.Fatalf("exit %d, want %d: %s", code, app.ExitUsage, errs)
	}
	if !strings.Contains(errs, "Run 'envc env --help'") {
		t.Errorf("stderr %q", errs)
	}
}

func TestBareGroupIsUsage(t *testing.T) {
	code, _, errs := run(t, "", "principal")
	if code != app.ExitUsage {
		t.Fatalf("exit %d, want %d: %s", code, app.ExitUsage, errs)
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"set", "--help"}, {"env", "-h"}} {
		code, out, errs := run(t, "", args...)
		if code != 0 {
			t.Errorf("%v: exit %d, stderr %q", args, code, errs)
		}
		if !strings.Contains(out, "Usage:") {
			t.Errorf("%v: stdout %q lacks Usage", args, out)
		}
	}
	// README COMMANDS block wording shows up in root help.
	_, out, _ := run(t, "", "--help")
	for _, short := range []string{
		"create .envc.yaml and gitignore entries",
		"add, list, remove environments",
		"grant decrypt access",
		"make the generated state match the files; --dry-run only reports",
		"print the environment file (secrets redacted)",
		"exec a process with the resolved values",
	} {
		if !strings.Contains(out, short) {
			t.Errorf("root help missing %q", short)
		}
	}
}

// initRepo creates a repo with environments local and production and returns
// its path. Commands run against it with -C.
// initRepo creates a repo with environments local and production, chdirs the
// test into it (walk-up discovery finds it from there), and returns its path.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	for _, args := range [][]string{{"init"}, {"env", "add", "local"}, {"env", "add", "production"}} {
		if code, _, errs := run(t, "", args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errs)
		}
	}
	return dir
}

func TestFlagErrorsAreUsage(t *testing.T) {
	initRepo(t)
	cases := [][]string{
		{"--bogus"},
		{"-C", ".", "env", "ls"},   // -C is gone: walk-up discovery replaced it
		{"-e", "production", "ls"}, // -e is gone
		{"set", "--nope", "K=V"},
		{"get"},                 // missing ENV and KEY
		{"get", "A", "B", "C"},  // too many
		{"get", "A", "B"},       // A is not an environment
		{"get", "production"},   // environment but no KEY
		{"get", "KEY"},          // KEY is not an environment; no default
		{"unset", "production"}, // environment but no KEY
		{"unset", "nope", "K"},  // nope is not an environment
		{"ls"},                  // missing ENV
		{"ls", "nope"},          // not an environment
		{"who"},                 // missing ENV
		{"who", "nope"},         // not an environment
		{"show"},                // missing ENV
		{"export"},              // missing ENV
		{"sync"},                // missing ENV
		{"diff"},                // missing ENV
		{"ensure", "nope"},      // not an environment
		{"ensure", "a", "b"},    // too many
		{"check"},               // folded into ensure
		{"rewrap", "local"},     // folded into ensure
		{"reencrypt", "local"},  // folded into ensure
		{"status"},              // folded into ensure
		{"deny", "production", "x", "--no-reencrypt"}, // flag is gone
		{"allow", "production"},                       // environment but no NAME
		{"allow", "engineers"},                        // NAME but no ENV
		{"deny", "production"},                        // environment but no NAME
		{"env", "add"},                                // missing NAME
		{"run"},                                       // no --
		{"run", "bun", "dev"},                         // no --
		{"run", "--"},                                 // no ENV, nothing after --
		{"run", "--", "bun", "dev"},                   // no ENV
		{"run", "x", "--", "y"},                       // x is not an environment
		{"run", "x", "y", "--", "z"},                  // two args before --
		{"run", "production", "--"},                   // nothing after --
		{"principal", "sync"},                         // neither NAME nor --all
		{"principal", "sync", "a", "--all"},
		{"principal", "add", "bob"}, // no source
		{"set", "local", "K=V", "--secret", "--public"},
		{"set", "local", "K", "--stdin", "--file", "x"},
		{"set", "local", "K=V", "--stdin"},
		{"set", "local", "K"}, // no value, no metadata
		{"set", "local", "bad-key=V", "--public"},
		{"set"},
		{"set", "K=V", "--public"}, // no ENV
		{"set", "A=1", "B=2"},      // A=1 is not an environment
		{"set", "nosuchenv", "K=v", "--public"},
		{"set", "production"},               // environment but no KEY
		{"set", "production", "A=1", "B=2"}, // too many
	}
	for _, args := range cases {
		code, out, errs := run(t, "", args...)
		if code != app.ExitUsage {
			t.Errorf("%v: exit %d, want %d (stderr %q)", args, code, app.ExitUsage, errs)
		}
		if out != "" {
			t.Errorf("%v: stdout %q, want empty", args, out)
		}
		if !strings.HasPrefix(errs, "envc: ") || !strings.Contains(errs, "--help") {
			t.Errorf("%v: stderr %q", args, errs)
		}
	}
}

func TestExitStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
		msg  string
	}{
		{"nil", nil, 0, ""},
		{"plain", errors.New("boom"), 1, "boom"},
		{"usage", usagef("bad %s", "x"), 3, "bad x"},
		{"exit decrypt", &app.ExitError{Code: app.ExitDecrypt, Err: errors.New("no key")}, 2, "no key"},
		{"exit usage", &app.ExitError{Code: app.ExitUsage, Err: errors.New("schema")}, 3, "schema"},
		{"wrapped exit", errWrap(&app.ExitError{Code: app.ExitDrift, Err: errors.New("drift")}), 1, "ctx: drift"},
		{"wrapped usage", errWrap(usagef("u")), 3, "ctx: u"},
	}
	for _, tc := range cases {
		code, msg := exitStatus(tc.err)
		if code != tc.code || msg != tc.msg {
			t.Errorf("%s: got (%d, %q), want (%d, %q)", tc.name, code, msg, tc.code, tc.msg)
		}
	}
}

func errWrap(err error) error { return &wrapped{err} }

type wrapped struct{ err error }

func (w *wrapped) Error() string { return "ctx: " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }

func ptr[T any](v T) *T { return &v }

func TestParseSetArgs(t *testing.T) {
	files := map[string]string{"key.pem": "-----BEGIN-----\nabc\n-----END-----\n"}
	readFile := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("no such file")
	}
	cases := []struct {
		name  string
		args  []string
		flags setFlags
		stdin string
		key   string
		want  app.SetOptions
		usage bool // expect usage error
		err   bool // expect any error
	}{
		{
			name: "key=value secret",
			args: []string{"DATABASE_URL=postgres://x"}, flags: setFlags{secret: true},
			key:  "DATABASE_URL",
			want: app.SetOptions{Secret: ptr(true), HasValue: true, Value: "postgres://x"},
		},
		{
			name: "value with equals",
			args: []string{"A=b=c"}, flags: setFlags{public: true},
			key:  "A",
			want: app.SetOptions{Secret: ptr(false), HasValue: true, Value: "b=c"},
		},
		{
			name: "empty value",
			args: []string{"A="}, flags: setFlags{public: true},
			key:  "A",
			want: app.SetOptions{Secret: ptr(false), HasValue: true, Value: ""},
		},
		{
			name: "no secret flag keeps existing",
			args: []string{"A=1"},
			key:  "A",
			want: app.SetOptions{HasValue: true, Value: "1"},
		},
		{
			name: "stdin strips one newline",
			args: []string{"TOKEN"}, flags: setFlags{stdin: true, secret: true}, stdin: "abc\n",
			key:  "TOKEN",
			want: app.SetOptions{Secret: ptr(true), HasValue: true, Value: "abc"},
		},
		{
			name: "stdin strips crlf",
			args: []string{"TOKEN"}, flags: setFlags{stdin: true}, stdin: "abc\r\n",
			key:  "TOKEN",
			want: app.SetOptions{HasValue: true, Value: "abc"},
		},
		{
			name: "stdin strips only one newline",
			args: []string{"TOKEN"}, flags: setFlags{stdin: true}, stdin: "abc\n\n",
			key:  "TOKEN",
			want: app.SetOptions{HasValue: true, Value: "abc\n"},
		},
		{
			name: "file verbatim",
			args: []string{"CERT"}, flags: setFlags{file: "key.pem", secret: true},
			key:  "CERT",
			want: app.SetOptions{Secret: ptr(true), HasValue: true, Value: files["key.pem"]},
		},
		{
			name: "file missing",
			args: []string{"CERT"}, flags: setFlags{file: "nope.pem"},
			err: true,
		},
		{
			name: "metadata only",
			args: []string{"LOG_LEVEL"},
			flags: setFlags{
				description: "verbosity", hasDescription: true,
				enum: "debug, info,warn", hasEnum: true,
				pattern: "^[a-z]+$", hasPattern: true,
			},
			key: "LOG_LEVEL",
			want: app.SetOptions{
				Description: ptr("verbosity"),
				Enum:        []string{"debug", "info", "warn"},
				Pattern:     ptr("^[a-z]+$"),
			},
		},
		{
			name: "enum empty clears",
			args: []string{"LOG_LEVEL"}, flags: setFlags{enum: "", hasEnum: true},
			key:  "LOG_LEVEL",
			want: app.SetOptions{Enum: []string{}},
		},
		{
			name: "description empty clears",
			args: []string{"A"}, flags: setFlags{description: "", hasDescription: true},
			key:  "A",
			want: app.SetOptions{Description: ptr("")},
		},
		{
			name: "value plus metadata",
			args: []string{"A=1"}, flags: setFlags{public: true, description: "d", hasDescription: true},
			key:  "A",
			want: app.SetOptions{Secret: ptr(false), HasValue: true, Value: "1", Description: ptr("d")},
		},
		{name: "no args", args: nil, usage: true},
		{name: "two args", args: []string{"A=1", "B=2"}, usage: true},
		{name: "key only", args: []string{"A"}, usage: true},
		{name: "secret and public", args: []string{"A=1"}, flags: setFlags{secret: true, public: true}, usage: true},
		{name: "stdin and file", args: []string{"A"}, flags: setFlags{stdin: true, file: "x"}, usage: true},
		{name: "value and stdin", args: []string{"A=1"}, flags: setFlags{stdin: true}, usage: true},
		{name: "value and file", args: []string{"A=1"}, flags: setFlags{file: "key.pem"}, usage: true},
		{name: "bad key", args: []string{"bad-key=1"}, flags: setFlags{public: true}, usage: true},
		{name: "empty key", args: []string{"=1"}, flags: setFlags{public: true}, usage: true},
		{name: "leading digit", args: []string{"1A=1"}, flags: setFlags{public: true}, usage: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, got, err := parseSetArgs(tc.args, tc.flags, strings.NewReader(tc.stdin), readFile)
			if tc.usage || tc.err {
				if err == nil {
					t.Fatalf("want error, got key=%q opts=%+v", key, got)
				}
				if tc.usage != isUsage(err) {
					t.Fatalf("usage=%v, want %v: %v", isUsage(err), tc.usage, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key != tc.key {
				t.Errorf("key %q, want %q", key, tc.key)
			}
			if !eqPtr(got.Secret, tc.want.Secret) {
				t.Errorf("Secret %v, want %v", fmtPtr(got.Secret), fmtPtr(tc.want.Secret))
			}
			if got.HasValue != tc.want.HasValue || got.Value != tc.want.Value {
				t.Errorf("value (%v,%q), want (%v,%q)", got.HasValue, got.Value, tc.want.HasValue, tc.want.Value)
			}
			if !eqPtr(got.Description, tc.want.Description) {
				t.Errorf("Description %v, want %v", fmtPtr(got.Description), fmtPtr(tc.want.Description))
			}
			if !eqPtr(got.Pattern, tc.want.Pattern) {
				t.Errorf("Pattern %v, want %v", fmtPtr(got.Pattern), fmtPtr(tc.want.Pattern))
			}
			if (got.Enum == nil) != (tc.want.Enum == nil) || strings.Join(got.Enum, ",") != strings.Join(tc.want.Enum, ",") {
				t.Errorf("Enum %#v, want %#v", got.Enum, tc.want.Enum)
			}
		})
	}
}

func eqPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func fmtPtr[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestParseRunArgs(t *testing.T) {
	cases := []struct {
		args   []string
		dash   int
		before []string
		want   []string
		usage  bool
	}{
		{[]string{"production", "bun", "dev"}, 1, []string{"production"}, []string{"bun", "dev"}, false},
		{[]string{"local", "sh", "-c", "echo $X"}, 1, []string{"local"}, []string{"sh", "-c", "echo $X"}, false},
		{[]string{"bun", "dev"}, 0, nil, nil, true},  // no environment before --
		{[]string{"bun", "dev"}, -1, nil, nil, true}, // no --
		{[]string{}, 0, nil, nil, true},
		{[]string{"production"}, 1, nil, nil, true},
		{[]string{"x", "y", "bun"}, 2, nil, nil, true},
	}
	for _, tc := range cases {
		before, got, err := parseRunArgs(tc.args, tc.dash)
		if tc.usage {
			if err == nil || !isUsage(err) {
				t.Errorf("%v dash=%d: want usage error, got %v", tc.args, tc.dash, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v: %v", tc.args, err)
			continue
		}
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%v: got %v, want %v", tc.args, got, tc.want)
		}
		if strings.Join(before, " ") != strings.Join(tc.before, " ") {
			t.Errorf("%v: before %v, want %v", tc.args, before, tc.before)
		}
	}
}

func TestEnvArg(t *testing.T) {
	dir := initRepo(t)
	a, err := app.Open(app.Options{Root: dir, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		args  []string
		env   string
		rest  string
		usage string // expected substring of the usage error; "" = success
	}{
		{name: "env only", args: []string{"production"}, env: "production"},
		{name: "env then rest", args: []string{"production", "alice", "bob"}, env: "production", rest: "alice bob"},
		{name: "no args", args: nil, usage: "missing environment"},
		{name: "not an env", args: []string{"KEY"}, usage: `unknown environment "KEY" (environments: local, production)`},
		{name: "group name is not an env", args: []string{"engineers", "alice"}, usage: `unknown environment "engineers"`},
		{name: "base for a manifest command", args: []string{"base", "KEY"}, env: "base", rest: "KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, rest, err := envArg(a, "get", tc.args)
			if tc.usage != "" {
				if err == nil || !isUsage(err) || !strings.Contains(err.Error(), tc.usage) {
					t.Fatalf("want usage error containing %q, got %v", tc.usage, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if env != tc.env || strings.Join(rest, " ") != tc.rest {
				t.Errorf("got (%q, %q), want (%q, %q)", env, strings.Join(rest, " "), tc.env, tc.rest)
			}
		})
	}
	// base is refused where an environment is meant, accepted where a manifest is.
	for _, cmd := range []string{"run", "export", "sync", "diff", "allow", "deny"} {
		if _, _, err := envArg(a, cmd, []string{"base", "x"}); err == nil || !isUsage(err) || !strings.Contains(err.Error(), app.BaseNotEnvMsg) {
			t.Errorf("%s base: want usage error %q, got %v", cmd, app.BaseNotEnvMsg, err)
		}
	}
	for _, cmd := range []string{"set", "unset", "get", "ls", "show", "ensure", "who"} {
		if env, _, err := envArg(a, cmd, []string{"base"}); err != nil || env != "base" {
			t.Errorf("%s base: got (%q, %v)", cmd, env, err)
		}
	}

	// No environments at all: the error points at env add.
	empty := t.TempDir()
	if code, _, errs := runInDir(t, empty, "init"); code != 0 {
		t.Fatal(errs)
	}
	if code, _, errs := runInDir(t, empty, "get", "local", "K"); code != app.ExitUsage || !strings.Contains(errs, "run `envc env add local`") {
		t.Errorf("no envs: exit %d: %s", code, errs)
	}
}

// TestPositionalEnvEndToEnd runs the public-value path through Main so the
// rule is exercised as users see it, without any crypto.
func TestPositionalEnvEndToEnd(t *testing.T) {
	dir := initRepo(t)
	must := func(args ...string) (string, string) {
		t.Helper()
		code, out, errs := run(t, "", args...)
		if code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errs)
		}
		return out, errs
	}
	must("set", "local", "LOG_LEVEL=debug", "--public")
	must("set", "production", "LOG_LEVEL=warn", "--public")
	if out, _ := must("get", "local", "LOG_LEVEL"); out != "debug\n" {
		t.Errorf("local: %q", out)
	}
	if out, _ := must("get", "production", "LOG_LEVEL"); out != "warn\n" {
		t.Errorf("production: %q", out)
	}
	// Omitting the environment is a usage error, never a default.
	if code, _, errs := run(t, "", "get", "LOG_LEVEL"); code != app.ExitUsage {
		t.Errorf("no env: exit %d: %s", code, errs)
	}
	if code, _, errs := run(t, "", "ls", "LOG_LEVEL"); code != app.ExitUsage || !strings.Contains(errs, `unknown environment "LOG_LEVEL"`) {
		t.Errorf("no env: exit %d: %s", code, errs)
	}
	// A key may share its name with an environment; the first argument is
	// always the environment.
	must("set", "local", "production=1", "--public")
	if out, _ := must("get", "local", "production"); out != "1\n" {
		t.Errorf("key named like an env: %q", out)
	}
	if _, errs := must("ensure", "--dry-run"); strings.Contains(errs, "warning:") || !strings.Contains(errs, "ok") {
		t.Errorf("ensure --dry-run should be clean: %q", errs)
	}
	must("unset", "local", "production")
	if code, _, errs := run(t, "", "run", "production", "--", "nonexistent-binary-xyz"); code != app.ExitUsage {
		t.Errorf("run production: exit %d (%s)", code, errs)
	}
	if code, _, errs := run(t, "", "set", "nosuchenv", "K=v", "--public"); code != app.ExitUsage ||
		!strings.Contains(errs, `unknown environment "nosuchenv" (environments: local, production)`) {
		t.Errorf("unknown env: exit %d: %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, ".envc", "environments", "production.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestPickKeys(t *testing.T) {
	keys := []string{"k1", "k2", "k3"}
	cases := []struct {
		sel   string
		want  string
		usage bool
	}{
		{"", "k1 k2 k3", false},
		{"  \n", "k1 k2 k3", false},
		{"2", "k2", false},
		{"1,3", "k1 k3", false},
		{"3, 1, 3", "k3 k1", false},
		{"0", "", true},
		{"4", "", true},
		{"a", "", true},
		{",", "", true},
	}
	for _, tc := range cases {
		got, err := pickKeys(keys, tc.sel)
		if tc.usage {
			if err == nil || !isUsage(err) {
				t.Errorf("%q: want usage error, got %v", tc.sel, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.sel, err)
			continue
		}
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("%q: got %q, want %q", tc.sel, s, tc.want)
		}
	}
}

func TestSummarizeReport(t *testing.T) {
	r := destination.Report{Created: []string{"A", "B"}, Updated: []string{"C"}, Unchanged: []string{"D", "E", "F", "G", "H"}}
	if got, want := summarizeReport(r, false, false), "2 created, 1 updated, 5 unchanged"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := summarizeReport(r, true, false), "would create 2, update 1, 5 unchanged"; got != want {
		t.Errorf("dry-run: got %q, want %q", got, want)
	}
	r.Pruned = []string{"Z"}
	r.Skipped = []string{"Y"}
	if got, want := summarizeReport(r, false, true), "2 created, 1 updated, 1 pruned, 5 unchanged, 1 skipped"; got != want {
		t.Errorf("pruned: got %q, want %q", got, want)
	}
	// Without --prune a destination that regenerates its file (dotenv) still
	// drops keys; say so without implying --prune semantics.
	if got, want := summarizeReport(r, false, false), "2 created, 1 updated, 1 removed (file regenerated), 5 unchanged, 1 skipped"; got != want {
		t.Errorf("removed: got %q, want %q", got, want)
	}
	if got, want := summarizeReport(r, true, false), "would create 2, update 1, remove 1 (file regenerated), 5 unchanged, 1 skipped"; got != want {
		t.Errorf("dry-run removed: got %q, want %q", got, want)
	}
}

func TestFormatProblem(t *testing.T) {
	cases := []struct {
		p    app.Problem
		want string
	}{
		{app.Problem{File: ".envc.yaml", Path: "groups.x[1]", Msg: "not a principal"}, ".envc.yaml: groups.x[1]: not a principal"},
		{app.Problem{File: ".envc/environments/production.yaml", Msg: "missing access"}, ".envc/environments/production.yaml: missing access"},
		{app.Problem{File: ".envc.yaml", Path: "sync.local.dotenv", Msg: "stale", Warn: true}, "warning: .envc.yaml: sync.local.dotenv: stale"},
	}
	for _, tc := range cases {
		if got := formatProblem(tc.p); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

func TestPrintDiff(t *testing.T) {
	var errb bytes.Buffer
	c := &cli{stderr: &errb}
	c.printDiff(app.DiffResult{Destination: "vercel", Keys: map[string]app.DiffState{
		"DATABASE_URL":   app.DiffUnverifiable,
		"LOG_LEVEL":      app.DiffChangedRemote,
		"A":              app.DiffOK,
		"ZZ_INTEGRATION": app.DiffExtra,
	}})
	want := strings.Join([]string{
		"vercel: drift",
		"  KEY           STATE",
		"  A             ok",
		"  DATABASE_URL  ok (unverifiable)",
		"  LOG_LEVEL     changed at destination",
		"  extra (not in file):",
		"    ZZ_INTEGRATION",
		"",
	}, "\n")
	if errb.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", errb.String(), want)
	}
}

// Walk-up root discovery: every command works from a subdirectory, files land
// at the root, and init refuses inside an existing repo.
func TestWalkUpRootDiscovery(t *testing.T) {
	dir := initRepo(t)
	if code, _, errs := run(t, "", "set", "local", "K=v", "--public"); code != 0 {
		t.Fatalf("set at root: %d %s", code, errs)
	}
	sub := filepath.Join(dir, "apps", "web")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)

	if code, out, errs := run(t, "", "get", "local", "K"); code != 0 || out != "v\n" {
		t.Fatalf("get from subdir: %d %q %s", code, out, errs)
	}
	if code, _, errs := run(t, "", "set", "local", "SUB=1", "--public"); code != 0 {
		t.Fatalf("set from subdir: %d %s", code, errs)
	}
	// Files land at the root, not the cwd.
	if _, err := os.Stat(filepath.Join(dir, ".env.local.example")); err != nil {
		t.Errorf("template not at root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sub, ".env.local.example")); err == nil {
		t.Errorf("template written in the subdirectory")
	}
	if _, err := os.Stat(filepath.Join(sub, ".envc")); err == nil {
		t.Errorf(".envc created in the subdirectory")
	}
	// Stored dotenv paths are root-relative: the flag value is stored verbatim
	// and resolved against the root at use, regardless of the cwd.
	if code, _, errs := run(t, "", "env", "add", "local", "--dotenv", ".env"); code != 0 {
		t.Fatalf("env add from subdir: %d %s", code, errs)
	}
	roster, err := os.ReadFile(filepath.Join(dir, ".envc.yaml"))
	if err != nil || !strings.Contains(string(roster), "path: .env") {
		t.Errorf("dotenv path not stored verbatim: %v %s", err, roster)
	}
	if code, _, errs := run(t, "", "sync", "local"); code != 0 {
		t.Fatalf("sync from subdir: %d %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err != nil {
		t.Errorf(".env not at root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sub, ".env")); err == nil {
		t.Errorf(".env written in the subdirectory")
	}
	// init refuses inside an existing repo, naming its root.
	if code, _, errs := run(t, "", "init"); code != app.ExitUsage ||
		!strings.Contains(errs, "refusing to init inside an existing envc repo") ||
		!strings.Contains(errs, dir) {
		t.Errorf("init in subdir: %d %s", code, errs)
	}
}

func TestNoRootFound(t *testing.T) {
	code, _, errs := runInDir(t, t.TempDir(), "env", "ls")
	if code != app.ExitUsage || !strings.Contains(errs, "no .envc.yaml in this directory or any parent; run `envc init` at the repo root") {
		t.Fatalf("no root: %d %s", code, errs)
	}
}
