// Package cli wires cobra commands to internal/app. It contains no business
// logic: parse flags, call app, print results, map errors to exit codes.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/montanaflynn/envc/internal/app"
	_ "github.com/montanaflynn/envc/internal/destination/all" // register built-in destinations
)

// Version is printed by `envc version`. Set at build time with
// -ldflags "-X github.com/montanaflynn/envc/internal/cli.Version=v1.2.3".
var Version = "dev"

// Main runs the CLI and returns the process exit code.
// args excludes the program name. getenv is injected for tests.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	c := &cli{stdin: stdin, stdout: stdout, stderr: stderr, getenv: getenv}
	root := c.root()
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)

	cmd, err := root.ExecuteC()
	if err == nil {
		return app.ExitOK
	}
	var se *silentExit
	if errors.As(err, &se) {
		return se.code // child process already reported itself
	}
	code, msg := exitStatus(err)
	fmt.Fprintf(stderr, "envc: %s\n", msg)
	if isUsage(err) {
		path := "envc"
		if cmd != nil {
			path = cmd.CommandPath()
		}
		fmt.Fprintf(stderr, "Run '%s --help' for usage.\n", path)
	}
	return code
}

// cli is the per-invocation state: injected I/O plus the global flags.
// It is built fresh by Main; there are no package-level globals besides Version.
type cli struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string

	// global flags
	dryRun bool
	json   bool
}

// usageError marks an error as a usage problem (exit 3).
type usageError struct{ err error }

func (u *usageError) Error() string { return u.err.Error() }
func (u *usageError) Unwrap() error { return u.err }

// silentExit ends Main with code and no message: the exit code of a child
// process run by `envc run` when execve is unavailable.
type silentExit struct{ code int }

func (s *silentExit) Error() string { return fmt.Sprintf("exit status %d", s.code) }

func usagef(format string, a ...any) error {
	return &usageError{fmt.Errorf(format, a...)}
}

func isUsage(err error) bool {
	var u *usageError
	return errors.As(err, &u)
}

// exitStatus maps an error to (exit code, message). *app.ExitError carries its
// own code; usage errors are 3; anything else is 1.
func exitStatus(err error) (int, string) {
	if err == nil {
		return app.ExitOK, ""
	}
	var ee *app.ExitError
	if errors.As(err, &ee) {
		return ee.Code, err.Error() // outer message keeps any wrapping context
	}
	if isUsage(err) {
		return app.ExitUsage, err.Error()
	}
	return app.ExitDrift, err.Error()
}

// options builds app.Options from the injected I/O and global flags.
func (c *cli) options() app.Options {
	return app.Options{
		Root:   "",
		Stdin:  c.stdin,
		Stdout: c.stdout,
		Stderr: c.stderr,
		Getenv: c.getenv,
		// The passphrase prompt reads /dev/tty, so piped stdin (set --stdin,
		// principal add --ssh-key -) or redirected stderr must not disable it.
		IsTTY:  isTerminal(c.stdin) || isTerminal(c.stderr),
		DryRun: c.dryRun,
		Now:    time.Now,
	}
}

// isTerminal reports whether r is an *os.File attached to a terminal.
func isTerminal(r any) bool {
	f, ok := r.(*os.File)
	if !ok || f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// open loads the roster.
func (c *cli) open() (*app.App, error) {
	return app.Open(c.options())
}

// openEnv loads the roster and takes the environment from args[0] (see
// envArg). It is the entry point for every command that reads an environment.
func (c *cli) openEnv(cmd *cobra.Command, args []string) (*app.App, string, []string, error) {
	a, err := c.open()
	if err != nil {
		return nil, "", nil, err
	}
	env, rest, err := envArg(a, cmd.Name(), args)
	if err != nil {
		return nil, "", nil, err
	}
	return a, env, rest, nil
}

// baseAccepted lists the commands whose first argument may be `base`: the
// ones that read or write one manifest. Everything else means an
// environment (run, export, sync, diff, allow, deny) and refuses it with
// app.BaseNotEnvMsg. This table is the only place that rule lives.
var baseAccepted = map[string]bool{
	"set": true, "unset": true, "get": true, "ls": true, "show": true,
	"ensure": true, "who": true,
}

// envArg applies the rule from the README's CLI reference: commands that read
// an environment take it as the required first argument. args[0] must name an
// existing environment (or `base`, for the commands in baseAccepted); the rest
// are the command's own positionals.
func envArg(a *app.App, cmd string, args []string) (env string, rest []string, err error) {
	if len(args) == 0 {
		return "", nil, usagef("missing environment argument")
	}
	if args[0] == app.BaseName {
		if !baseAccepted[cmd] {
			return "", nil, usagef("%s", app.BaseNotEnvMsg)
		}
		return app.BaseName, args[1:], nil
	}
	envs, err := a.EnvList()
	if err != nil {
		return "", nil, err
	}
	if !slices.Contains(envs, args[0]) {
		return "", nil, unknownEnv(args[0], envs)
	}
	return args[0], args[1:], nil
}

// unknownEnv is the usage error for a leading argument that had to be an
// environment but is not one.
func unknownEnv(name string, envs []string) error {
	if len(envs) == 0 {
		return usagef("unknown environment %q (no environments yet; run `envc env add %s`)", name, name)
	}
	return usagef("unknown environment %q (environments: %s)", name, strings.Join(envs, ", "))
}

// errf writes a progress/warning line to stderr.
func (c *cli) errf(format string, a ...any) {
	fmt.Fprintf(c.stderr, format+"\n", a...)
}

// outf writes a value line to stdout.
func (c *cli) outf(format string, a ...any) {
	fmt.Fprintf(c.stdout, format+"\n", a...)
}

// done reports a completed mutation on stderr: the action on the first
// line, then one line per effect, indented. Phrase both in base form ("set
// KEY", "rewrap production"); effects whose first word is a known verb are
// printed in the past tense ("rewrapped production"), and everything gets a
// "would " prefix under --dry-run:
//
//	allow carol on production
//	  rewrapped production
//	  rewrapped base: carol now reads base secrets
func (c *cli) done(action string, effects ...string) {
	if c.dryRun {
		action = "would " + action
	}
	c.errf("%s", action)
	c.effectLines(effects)
}

// effectLines prints effects indented under an action line, in the past
// tense, or prefixed "would" under --dry-run.
func (c *cli) effectLines(effects []string) {
	for _, e := range c.reportLines(effects) {
		c.errf("  %s", e)
	}
}

// reportLines renders effects as they are shown: past tense, or "would …"
// under --dry-run. Empty effects are dropped.
func (c *cli) reportLines(effects []string) []string {
	out := make([]string, 0, len(effects))
	for _, e := range effects {
		if e == "" {
			continue
		}
		if c.dryRun {
			e = "would " + e
		} else {
			e = pastTense(e)
		}
		out = append(out, e)
	}
	return out
}

// pastTense turns a base-form effect into a report: "update production
// readers: …" → "updated production readers: …". Unknown first words are
// left as they are.
func pastTense(s string) string {
	verb, rest, _ := strings.Cut(s, " ")
	past, ok := map[string]string{
		"encrypt":    "encrypted",
		"update":     "updated",
		"re-key":     "re-keyed",
		"regenerate": "regenerated",
		"repair":     "repaired",
		"remove":     "removed",
		"write":      "wrote",
		"refresh":    "refreshed",
	}[verb]
	if !ok {
		return s
	}
	if rest == "" {
		return past
	}
	return past + " " + rest
}

// effects returns a's effects minus any listed in except.
func effects(a *app.App, except ...string) []string {
	var out []string
	for _, e := range a.Effects() {
		skip := false
		for _, x := range except {
			if e == x {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, e)
		}
	}
	return out
}

// usageArgs wraps a cobra positional-args validator so its errors exit 3.
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := v(cmd, args); err != nil {
			return &usageError{err}
		}
		return nil
	}
}

// group marks cmd as a container of subcommands: leftover args and a bare
// invocation are usage errors rather than silent help.
func group(cmd *cobra.Command) *cobra.Command {
	cmd.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return usagef("unknown command %q for %q", args[0], cmd.CommandPath())
		}
		return nil
	}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return usagef("%s: missing subcommand", cmd.CommandPath())
	}
	return cmd
}
