// Package app is the orchestration layer: everything the CLI can do, expressed
// as methods that take and return plain values. The CLI prints; app decides.
//
// Conventions:
//   - Every error a user can cause is an *ExitError with the right exit code
//     and a message that names the environment, key, or file involved.
//   - app never writes to Stdout or Stderr itself; cli prints confirmations.
//     Options.Stderr is only handed to crypto (passphrase prompt, non-TTY
//     skip notice) and to destinations as their Log.
//   - Options.DryRun disables every filesystem write (.envc.yaml, .envc/environments/*,
//     .envc/state/*, .env is a destination's business). Computation still runs so
//     errors surface.
//   - The identity search home directory is Options.Getenv("HOME"); when that
//     is empty crypto falls back to os.UserHomeDir.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/montanaflynn/envc/internal/crypto"
	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/envfile"
	"github.com/montanaflynn/envc/internal/resolve"
	"github.com/montanaflynn/envc/internal/roster"
	"github.com/montanaflynn/envc/internal/state"
)

// Exit codes (README → CLI reference).
const (
	ExitOK      = 0
	ExitDrift   = 1 // also check failure
	ExitDecrypt = 2
	ExitUsage   = 3 // also schema
)

// ExitError carries an exit code. cli prints Err to stderr and exits with Code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// Options configures an App. Everything that touches the outside world is here.
type Options struct {
	Root   string // repo root (directory containing .envc.yaml); "" → cwd
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	IsTTY  bool // stdin/stderr are a terminal: passphrase prompts allowed
	DryRun bool
	Now    func() time.Time
	// Prompt overrides the passphrase prompt (tests). nil → /dev/tty.
	Prompt func(prompt string) (string, error)
	// Confirm asks a yes/no question on the TTY; nil → always false when !IsTTY.
	Confirm func(question string) (bool, error)
}

// App holds a loaded roster and caches unwrapped data keys per environment.
type App struct {
	Opts   Options
	Roster *roster.Roster
	// unexported caches
	keys map[string]crypto.DataKey // env → unwrapped data key
	// passphrases memoizes the passphrase prompt by prompt text so one
	// invocation touching several environments asks once (README →
	// Encryption: "prompts once per invocation").
	passphrases map[string]string
	// effects collects what a mutation did beyond its headline, in base
	// form ("update production readers: carol now reads production secrets",
	// "re-key base: bob no longer reads base secrets"); the CLI prints them
	// under the action line. lostHint names readers that are leaving in this
	// call (a removed principal, a replaced key) so re-key effects can still
	// name them after their key is gone.
	effects  []string
	lostHint []string
	// macBroken marks environments whose MAC mismatched while every token
	// still decrypted (a hand edit): inspectEnv sets it, ensure repairs it.
	macBroken map[string]bool

	// overlay holds manifests this call has changed but may not have
	// written (--dry-run), keyed by environment; nil means "removed". The
	// derived base access reads it in preference to disk so a dry run
	// reports the same base effect a real run would.
	overlay map[string]*envfile.File
}

// stage records env's manifest as this call now sees it (nil: removed).
func (a *App) stage(env string, f *envfile.File) {
	if a.overlay == nil {
		a.overlay = map[string]*envfile.File{}
	}
	a.overlay[env] = f
}

// Effects returns what the last mutation did, one entry per effect, in the
// order they happened. Each starts with a verb in base form.
func (a *App) Effects() []string { return append([]string(nil), a.effects...) }

func (a *App) effect(s string) { a.effects = append(a.effects, s) }

// usagef builds an ExitUsage error.
func usagef(format string, args ...any) error {
	return &ExitError{Code: ExitUsage, Err: fmt.Errorf(format, args...)}
}

// decryptf builds an ExitDecrypt error.
func decryptf(format string, args ...any) error {
	return &ExitError{Code: ExitDecrypt, Err: fmt.Errorf(format, args...)}
}

// exitErr wraps err with code unless it already is an *ExitError.
func exitErr(code int, err error) error {
	if err == nil {
		return nil
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return err
	}
	return &ExitError{Code: code, Err: err}
}

// root returns the resolved repo root.
func (a *App) root() string { return a.Opts.Root }

func (a *App) getenv(key string) string {
	if a.Opts.Getenv == nil {
		return os.Getenv(key)
	}
	return a.Opts.Getenv(key)
}

func (a *App) stderr() io.Writer {
	if a.Opts.Stderr == nil {
		return io.Discard
	}
	return a.Opts.Stderr
}

func (a *App) now() time.Time {
	if a.Opts.Now == nil {
		return time.Now()
	}
	return a.Opts.Now()
}

// Init creates .envc.yaml and .gitignore entries at root. Errors if .envc.yaml
// already exists.
func Init(root string, opts Options) error {
	root, err := resolveRoot(root)
	if err != nil {
		return err
	}
	rosterPath := filepath.Join(root, roster.FileName)
	if _, err := os.Stat(rosterPath); err == nil {
		return usagef("%s already exists", rosterPath)
	}
	if above := findRoot(filepath.Dir(root)); above != "" {
		return usagef("refusing to init inside an existing envc repo (%s at %s)", roster.FileName, above)
	}
	if opts.DryRun {
		return nil
	}
	if err := roster.New().Save(root); err != nil {
		return exitErr(ExitDrift, err)
	}
	if err := ensureGitignore(root, []string{".env", ".env.local", "*.agekey"}); err != nil {
		return exitErr(ExitDrift, err)
	}
	return nil
}

// ensureGitignore appends each missing entry to root/.gitignore (creating it).
func ensureGitignore(root string, entries []string) error {
	path := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	have := map[string]bool{}
	for _, line := range splitLines(string(data)) {
		have[line] = true
	}
	var add []string
	for _, e := range entries {
		if !have[e] {
			add = append(add, e)
		}
	}
	if len(add) == 0 {
		return nil
	}
	out := string(data)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out += "\n"
	}
	for _, e := range add {
		out += e + "\n"
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// splitLines returns trimmed lines.
func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return lines
}

// resolveRoot turns "" into the cwd and makes the path absolute.
func resolveRoot(root string) (string, error) {
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", exitErr(ExitDrift, fmt.Errorf("getwd: %w", err))
		}
		return wd, nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", exitErr(ExitDrift, fmt.Errorf("resolve %s: %w", root, err))
	}
	return abs, nil
}

// findRoot walks from dir toward the filesystem root and returns the first
// directory containing .envc.yaml, or "" if there is none. A stat error other
// than not-exist is treated as a boundary: the walk stops there.
func findRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, roster.FileName)); err == nil {
			return dir
		} else if !errors.Is(err, os.ErrNotExist) {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// discoverRoot resolves the repo root. An explicit root (tests, Options.Root)
// is used as given; otherwise the root is the nearest ancestor of the cwd —
// including the cwd — that contains .envc.yaml, like git.
func discoverRoot(root string) (string, error) {
	if root != "" {
		return resolveRoot(root)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", exitErr(ExitDrift, fmt.Errorf("getwd: %w", err))
	}
	found := findRoot(wd)
	if found == "" {
		return "", usagef("no %s in this directory or any parent; run `envc init` at the repo root", roster.FileName)
	}
	return found, nil
}

// Open loads .envc.yaml at opts.Root, or — when Root is "" — at the nearest
// ancestor of the cwd that contains one (walk-up discovery, like git).
func Open(opts Options) (*App, error) {
	root, err := discoverRoot(opts.Root)
	if err != nil {
		return nil, err
	}
	opts.Root = root
	rosterPath := filepath.Join(root, roster.FileName)
	if _, err := os.Stat(rosterPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, usagef("no %s in %s; run `envc init`", roster.FileName, root)
		}
		return nil, exitErr(ExitDrift, fmt.Errorf("stat %s: %w", rosterPath, err))
	}
	r, err := roster.Load(root)
	if err != nil {
		return nil, exitErr(ExitUsage, err)
	}
	return &App{Opts: opts, Roster: r, keys: map[string]crypto.DataKey{}}, nil
}

// Env checks that name is a non-empty environment whose file exists. The
// base layer is not an environment.
func (a *App) Env(name string) (string, error) {
	if name == "" {
		return "", usagef("environment is required")
	}
	if err := baseGuard(name); err != nil {
		return "", err
	}
	if err := checkEnvName(name); err != nil {
		return "", err
	}
	if _, err := os.Stat(envfile.Path(a.root(), name)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", a.unknownEnv(name)
		}
		return "", exitErr(ExitDrift, fmt.Errorf("stat %s: %w", envfile.Path(a.root(), name), err))
	}
	return name, nil
}

// unknownEnv builds the "unknown environment" usage error, listing known envs.
func (a *App) unknownEnv(name string) error {
	envs, _ := envfile.List(a.root())
	if len(envs) == 0 {
		return usagef("unknown environment %q (no environments yet; run `envc env add %s`)", name, name)
	}
	return usagef("unknown environment %q (known: %s)", name, joinComma(envs))
}

// Load reads .envc/environments/<env>.yaml and attaches its envelope from
// .envc/state/<env>/envelope.yaml. A manifest with encrypted values whose
// envelope is missing cannot be read: that is ExitDecrypt with a restore hint,
// never a silently regenerated envelope. check and env rm use loadLenient.
func (a *App) Load(env string) (*envfile.File, error) {
	f, err := a.loadLenient(env)
	if err != nil {
		return nil, err
	}
	if f.Crypto == nil && len(f.EncryptedKeys()) > 0 {
		return nil, decryptf("%s", missingEnvelope(env))
	}
	return f, nil
}

// loadLenient is Load without the missing-envelope check. For the base
// layer a missing file is an empty layer, not an error.
func (a *App) loadLenient(env string) (*envfile.File, error) {
	var f *envfile.File
	if isBase(env) {
		var err error
		f, err = envfile.LoadBase(envfile.BasePath(a.root()))
		if errors.Is(err, os.ErrNotExist) {
			f, err = envfile.NewBase(), nil
		}
		if err != nil {
			return nil, exitErr(ExitUsage, err)
		}
	} else {
		if err := checkEnvName(env); err != nil {
			return nil, err
		}
		path := envfile.Path(a.root(), env)
		var err error
		f, err = envfile.Load(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, a.unknownEnv(env)
			}
			return nil, exitErr(ExitUsage, err)
		}
	}
	var err error
	f.Crypto, err = state.LoadEnvelope(a.root(), env)
	if err != nil {
		return nil, exitErr(ExitUsage, err)
	}
	return f, nil
}

// missingEnvelope is the message for a manifest with ENC[…] values and no envelope.
func missingEnvelope(env string) string {
	p := envelopePath(env)
	return fmt.Sprintf("%s is missing; it holds the data key — restore it: git checkout -- %s", p, p)
}

// saveFile writes the envelope (or removes it when f.Crypto is nil) and then
// .envc/environments/<env>.yaml, unless DryRun. The manifest is validated
// first; schema problems are refused with ExitUsage. The envelope goes first
// so an interrupted write never leaves encrypted values without their key.
func (a *App) saveFile(env string, f *envfile.File) error {
	if probs := f.Validate(); len(probs) > 0 {
		return usagef("%s: %s", relPath(envfile.Path("", env)), joinProblems(probs))
	}
	if f.Crypto != nil {
		if probs := f.Crypto.Validate(); len(probs) > 0 {
			return usagef("%s: %s", envelopePath(env), joinStateProblems(probs))
		}
	}
	if a.Opts.DryRun {
		return nil
	}
	if f.Crypto != nil {
		if err := f.Crypto.Save(a.root(), env); err != nil {
			return exitErr(ExitDrift, err)
		}
	} else if err := state.RemoveEnvelope(a.root(), env); err != nil {
		return exitErr(ExitDrift, err)
	}
	if err := f.Save(a.manifestPath(env)); err != nil {
		return exitErr(ExitDrift, err)
	}
	if isBase(env) {
		// Every inheriting environment's template shows base entries.
		return a.refreshAllExamples()
	}
	return a.refreshExample(env, f)
}

// manifestPath is the on-disk path of env's manifest (or the base layer).
func (a *App) manifestPath(env string) string {
	if isBase(env) {
		return envfile.BasePath(a.root())
	}
	return envfile.Path(a.root(), env)
}

// saveRoster writes .envc.yaml unless DryRun.
func (a *App) saveRoster() error {
	if probs := a.Roster.Validate(); len(probs) > 0 {
		return usagef("%s: %s", roster.FileName, joinRosterProblems(probs))
	}
	if a.Opts.DryRun {
		return nil
	}
	if err := a.Roster.Save(a.root()); err != nil {
		return exitErr(ExitDrift, err)
	}
	return nil
}

func joinProblems(probs []envfile.Problem) string {
	s := make([]string, len(probs))
	for i, p := range probs {
		s[i] = p.String()
	}
	return joinSemi(s)
}

func joinStateProblems(probs []state.Problem) string {
	s := make([]string, len(probs))
	for i, p := range probs {
		s[i] = p.String()
	}
	return joinSemi(s)
}

func joinRosterProblems(probs []roster.Problem) string {
	s := make([]string, len(probs))
	for i, p := range probs {
		s[i] = p.String()
	}
	return joinSemi(s)
}

func joinComma(s []string) string { return strings.Join(s, ", ") }
func joinSemi(s []string) string  { return strings.Join(s, "; ") }

// relPath is the display form of a path relative to root (".envc/environments/x.yaml").
func relPath(p string) string { return filepath.ToSlash(p) }

// sortedStrings returns a sorted copy.
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func remove(list []string, s string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// --- environments -----------------------------------------------------------

// EnvAddOptions are the destination flags for `env add`.
type EnvAddOptions struct {
	Dotenv, Override      string
	GitHub, GitHubScope   string
	Vercel, VercelProject string
	Convex                string
}

// --- principals & groups ----------------------------------------------------

// PrincipalSync refetches GitHub keys for name (or all with github: set) and
// applies pins. Added keys → rewrap; removed keys → reencrypt.
type KeyChange struct {
	Principal      string
	Added, Removed []string // OpenSSH lines
}

// --- access -----------------------------------------------------------------

// Who describes who can decrypt env.
type Who struct {
	Access  []string // as listed; empty for base
	Derived bool     // base: Principals is the union of every inheriting environment's access
	// InheritsBase: an environment that inherits base while base has secrets,
	// so its principals decrypt those too.
	InheritsBase bool
	Principals   []string            // expanded, sorted
	Keys         map[string][]string // principal → fingerprints / age1…
}

// --- values -----------------------------------------------------------------

// SetOptions are the flags for `set`.
type SetOptions struct {
	Secret      *bool // nil = keep existing; required on create
	HasValue    bool  // false = metadata-only patch
	Value       string
	Description *string
	Enum        []string // nil = keep; empty slice = clear
	Pattern     *string
}

// Resolve returns the values export, run, and sync use: the environment's
// own decrypted values layered over the base entries it inherits (all keys
// are kind env in v1).
func (a *App) Resolve(env string) (resolve.Vars, error) {
	if err := baseGuard(env); err != nil {
		return nil, err
	}
	f, err := a.Load(env)
	if err != nil {
		return nil, err
	}
	v, err := a.view(env, f)
	if err != nil {
		return nil, err
	}
	return a.viewVars(env, f, v)
}

// --- sync / diff ------------------------------------------------------------

// SyncResult is one destination's outcome.
type SyncResult struct {
	Destination string
	Report      destination.Report
	Err         error
}

// DiffState is one key's status at one destination.
type DiffState string

const (
	DiffOK            DiffState = "ok"
	DiffUnverifiable  DiffState = "ok (unverifiable)"
	DiffNeverSynced   DiffState = "never synced"
	DiffStaleSync     DiffState = "stale sync record (re-keyed elsewhere)"
	DiffChangedFile   DiffState = "changed in file"
	DiffChangedRemote DiffState = "changed at destination"
	DiffMissing       DiffState = "missing at destination"
	DiffExtra         DiffState = "extra"
)

// IsDrift reports whether the state should fail diff.
func (s DiffState) IsDrift() bool {
	switch s {
	case DiffOK, DiffUnverifiable, DiffExtra:
		return false
	}
	return true
}

// DiffResult is one destination's comparison.
type DiffResult struct {
	Destination string
	Keys        map[string]DiffState // includes extras
	Err         error
}

// Drifted reports whether any key drifted.
func (d DiffResult) Drifted() bool {
	for _, s := range d.Keys {
		if s.IsDrift() {
			return true
		}
	}
	return false
}

// --- check ------------------------------------------------------------------

// Problem is a check finding.
type Problem struct {
	File string // ".envc.yaml", ".envc/environments/production.yaml", or ".envc/state/production/envelope.yaml"
	Path string
	Msg  string
	Warn bool // warning, does not fail check
}

// ctxOrBackground returns ctx or context.Background when nil.
func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
