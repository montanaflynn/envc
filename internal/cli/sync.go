package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/montanaflynn/envc/internal/app"
	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/resolve"
)

func (c *cli) exportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export ENV",
		Short: "KEY=value on stdout",
		Long:  "export prints KEY=value on stdout, .env encoding, secrets in the clear.",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, _, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			vars, err := a.Resolve(env)
			if err != nil {
				return err
			}
			_, err = io.WriteString(c.stdout, resolve.Encode(vars))
			return err
		},
	}
}

// parseRunArgs splits `run ENV [--pure] -- COMMAND [ARGS…]` into the
// arguments before -- (exactly one: the environment, resolved by the caller
// with envArg) and the command after it. dash is cobra's ArgsLenAtDash: -1
// when no "--" was given.
func parseRunArgs(args []string, dash int) (before, argv []string, err error) {
	if dash < 0 {
		return nil, nil, usagef("run: put the command after --, e.g. envc run local -- bun dev")
	}
	if dash == 0 {
		return nil, nil, usagef("run: missing environment before --, e.g. envc run local -- bun dev")
	}
	if dash > 1 {
		return nil, nil, usagef("run: unexpected argument %q before --", args[1])
	}
	if len(args) == dash {
		return nil, nil, usagef("run: missing command after --")
	}
	return args[:dash], args[dash:], nil
}

func (c *cli) runCmd() *cobra.Command {
	var pure bool
	cmd := &cobra.Command{
		Use:   "run ENV [--pure] -- COMMAND [ARGS…]",
		Short: "exec a process with the resolved values",
		Long: `run builds the child's environment as process env > .env.local > resolved values,
then execs COMMAND. --pure skips .env.local.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			before, argv, err := parseRunArgs(args, cmd.ArgsLenAtDash())
			if err != nil {
				return err
			}
			a, env, _, err := c.openEnv(cmd, before)
			if err != nil {
				return err
			}
			childEnv, err := a.RunEnv(env, pure, os.Environ())
			if err != nil {
				return err
			}
			if c.dryRun {
				c.errf("would exec %s with %d variables", strings.Join(argv, " "), len(childEnv))
				return nil
			}
			path, err := exec.LookPath(argv[0])
			if err != nil {
				return &app.ExitError{Code: app.ExitUsage, Err: fmt.Errorf("run: %w", err)}
			}
			return execProcess(path, argv, childEnv, c.stdin, c.stdout, c.stderr)
		},
	}
	cmd.Flags().BoolVar(&pure, "pure", false, "skip .env.local")
	return cmd
}

func (c *cli) syncCmd() *cobra.Command {
	var only string
	var prune bool
	cmd := &cobra.Command{
		Use:   "sync ENV [--only NAME] [--prune] [--dry-run]",
		Short: "push the resolved values to destinations",
		Long: `sync decrypts, resolves, applies each destination for this env, and records
what was pushed in .envc/state/<env>/sync.yaml (non-dotenv destinations).
--only NAME limits to one registered destination.
--prune deletes destination keys not in the resolved values (off by default).`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, _, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			results, err := a.Sync(cmd.Context(), env, only, prune)
			if err != nil {
				return err
			}
			failed := 0
			for _, r := range results {
				if r.Err != nil {
					failed++
					c.errf("%s: error: %s", r.Destination, destErr(r.Destination, r.Err))
					continue
				}
				c.errf("%s: %s", r.Destination, summarizeReport(r.Report, c.dryRun, prune))
			}
			if failed > 0 {
				return &app.ExitError{Code: app.ExitDrift, Err: fmt.Errorf("sync: %d destination(s) failed", failed)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&only, "only", "", "limit to one destination `NAME`")
	cmd.Flags().BoolVar(&prune, "prune", false, "delete destination keys not in the resolved values")
	return cmd
}

// summarizeReport renders "2 created, 1 updated, 5 unchanged" (or
// "would create 2, update 1, 5 unchanged" under dry-run). Zero counts for
// pruned/skipped are omitted. Keys a destination dropped without --prune
// (dotenv regenerates the whole file) are reported as removed rather than
// pruned, so the summary never implies --prune semantics the user did not ask for.
func summarizeReport(r destination.Report, dryRun, prune bool) string {
	type part struct {
		n          int
		past, verb string
		suffix     string // appended after the count, e.g. "(file regenerated)"
		always     bool
	}
	pruned := part{n: len(r.Pruned), past: "pruned", verb: "prune"}
	if !prune {
		pruned = part{n: len(r.Pruned), past: "removed", verb: "remove", suffix: " (file regenerated)"}
	}
	parts := []part{
		{n: len(r.Created), past: "created", verb: "create", always: true},
		{n: len(r.Updated), past: "updated", verb: "update", always: true},
		pruned,
	}
	var out []string
	for _, p := range parts {
		if p.n == 0 && !p.always {
			continue
		}
		if dryRun {
			out = append(out, fmt.Sprintf("%s %d%s", p.verb, p.n, p.suffix))
		} else {
			out = append(out, fmt.Sprintf("%d %s%s", p.n, p.past, p.suffix))
		}
	}
	if dryRun {
		out[0] = "would " + out[0]
	}
	out = append(out, fmt.Sprintf("%d unchanged", len(r.Unchanged)))
	if len(r.Skipped) > 0 {
		out = append(out, fmt.Sprintf("%d skipped", len(r.Skipped)))
	}
	return strings.Join(out, ", ")
}

func (c *cli) diffCmd() *cobra.Command {
	var only string
	cmd := &cobra.Command{
		Use:   "diff ENV [--only NAME]",
		Short: "compare file to destinations",
		Long: `diff compares the file to its destinations, never env vs env.
Exit 1 if a key is changed or missing; extras are listed only.`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, _, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			results, err := a.Diff(cmd.Context(), env, only)
			if err != nil {
				for _, r := range results {
					if r.Err != nil {
						c.errf("%s: error: %s", r.Destination, destErr(r.Destination, r.Err))
					}
				}
				return err
			}
			drifted, failed := 0, 0
			if c.json {
				out := map[string]map[string]app.DiffState{}
				for _, r := range results {
					if r.Err != nil {
						failed++
						c.errf("%s: error: %s", r.Destination, destErr(r.Destination, r.Err))
						continue
					}
					if r.Drifted() {
						drifted++
					}
					keys := r.Keys
					if keys == nil {
						keys = map[string]app.DiffState{}
					}
					out[r.Destination] = keys
				}
				if err := writeJSON(c.stdout, out); err != nil {
					return err
				}
			} else {
				for _, r := range results {
					if r.Err != nil {
						failed++
						c.errf("%s: error: %s", r.Destination, destErr(r.Destination, r.Err))
						continue
					}
					if r.Drifted() {
						drifted++
					}
					c.printDiff(r)
				}
			}
			if failed > 0 {
				return &app.ExitError{Code: app.ExitDrift, Err: fmt.Errorf("diff: %d destination(s) failed", failed)}
			}
			if drifted > 0 {
				return &app.ExitError{Code: app.ExitDrift, Err: errors.New("drift detected")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&only, "only", "", "limit to one destination `NAME`")
	return cmd
}

// printDiff writes one destination's table to stderr: keys in the file
// first, then extras under their own heading.
func (c *cli) printDiff(r app.DiffResult) {
	status := "ok"
	if r.Drifted() {
		status = "drift"
	}
	c.errf("%s: %s", r.Destination, status)

	var keys, extras []string
	width := len("KEY")
	for k, s := range r.Keys {
		if s == app.DiffExtra {
			extras = append(extras, k)
		} else {
			keys = append(keys, k)
			width = max(width, len(k))
		}
	}
	sort.Strings(keys)
	sort.Strings(extras)
	if len(keys) > 0 {
		c.errf("  %-*s  %s", width, "KEY", "STATE")
		for _, k := range keys {
			c.errf("  %-*s  %s", width, k, r.Keys[k])
		}
	}
	if len(extras) > 0 {
		c.errf("  extra (not in file):")
		for _, k := range extras {
			c.errf("    %s", k)
		}
	}
}

// destErr strips repeated "<dest>: " / "live: " prefixes that app and the
// destination each add, so the line reads "github: error: no token: …".
func destErr(dest string, err error) string {
	msg := err.Error()
	for {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(msg, dest+": "), "live: ")
		trimmed = strings.TrimPrefix(trimmed, "apply: ")
		if trimmed == msg {
			return msg
		}
		msg = trimmed
	}
}
