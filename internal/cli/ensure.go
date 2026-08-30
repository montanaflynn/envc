package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/montanaflynn/envc/internal/app"
)

func (c *cli) ensureCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ensure [ENV]",
		Short: "make the generated state match the files; --dry-run only reports",
		Long: `ensure validates the files, fixes what it can, and reports the rest.
Run it after editing YAML by hand. Without ENV every environment and base
are ensured; ENV may be base.

Validated (reported, never changed):
  - schema of .envc.yaml, .envc/environments/*.yaml, .envc/base.yaml,
    .envc/state/*/envelope.yaml; key names, unknown fields
  - every access name exists; groups contain only principals
  - an environment with ENC[envc1,…] values has its envelope
  - sync.<env> names only registered destinations
  - with a key: MAC, enum, and pattern of secret values; values changed
    since the last recorded sync; a configured .env that is missing or
    stale (warnings; run envc sync)

Fixed (each reported as an effect line):
  - hand-written plaintext secrets are encrypted
  - the envelope's readers are brought in line with access; a reader that
    was removed by hand gets a new data key (re-key)
  - base's envelope is brought in line with the union of every inheriting
    environment's access
  - a missing or stale .env.<env>.example is regenerated

A target with an unfixable error is left untouched and says what it is
waiting on: "not fixed: resolve the problem(s) above, then run envc ensure
ENV again to …". --dry-run writes
nothing: fixes are printed as "would …" and count as pending.
Exit 0 consistent · 1 problems remain or pending · 2 a fix needs a key
that cannot open the file · 3 usage.`,
		Args: usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			env := ""
			if len(args) == 1 {
				if env, _, err = envArg(a, cmd.Name(), args); err != nil {
					return err
				}
			}
			res, err := a.Ensure(env)
			if err != nil {
				return err
			}
			failures := res.Failures()
			if c.json {
				type row struct {
					File string `json:"file"`
					Path string `json:"path"`
					Msg  string `json:"msg"`
					Warn bool   `json:"warn"`
				}
				type target struct {
					Name    string   `json:"name"`
					Effects []string `json:"effects"`
				}
				rows := make([]row, 0, len(res.Problems))
				for _, p := range res.Problems {
					rows = append(rows, row{p.File, p.Path, p.Msg, p.Warn})
				}
				targets := make([]target, 0, len(res.Targets))
				for _, t := range res.Targets {
					targets = append(targets, target{t.Name, c.reportLines(t.Effects)})
				}
				if err := writeJSON(c.stdout, map[string]any{"targets": targets, "problems": rows, "pending": res.Pending}); err != nil {
					return err
				}
			} else {
				for _, t := range res.Targets {
					c.errf("ensure %s", t.Name)
					c.effectLines(t.Effects)
				}
				for _, p := range res.Problems {
					c.errf("%s", formatProblem(p))
				}
				if len(res.Targets) == 0 && len(res.Problems) == 0 {
					c.errf("ok")
				}
			}
			if failures == 0 && res.Pending == 0 {
				return nil
			}
			var parts []string
			if res.Pending > 0 {
				parts = append(parts, fmt.Sprintf("%d pending", res.Pending))
			}
			if failures > 0 {
				parts = append(parts, fmt.Sprintf("%d problem(s)", failures))
			}
			return &app.ExitError{Code: app.ExitDrift, Err: fmt.Errorf("ensure: %s", strings.Join(parts, ", "))}
		},
	}
}

// formatProblem renders "file: path: msg", prefixed "warning: " for warnings.
func formatProblem(p app.Problem) string {
	parts := []string{}
	if p.File != "" {
		parts = append(parts, p.File)
	}
	if p.Path != "" {
		parts = append(parts, p.Path)
	}
	parts = append(parts, p.Msg)
	s := strings.Join(parts, ": ")
	if p.Warn {
		s = "warning: " + s
	}
	return s
}
