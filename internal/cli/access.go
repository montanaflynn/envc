package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

func (c *cli) allowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "allow ENV NAME [NAME…]",
		Short: "grant decrypt access",
		Long:  "NAME is a principal or group. allow edits access: and updates the envelope's readers; base follows.",
		Args:  usageArgs(cobra.MinimumNArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, names, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			if err := a.Allow(env, names); err != nil {
				return err
			}
			c.done(fmt.Sprintf("allow %s on %s", strings.Join(names, ", "), env), effects(a)...)
			return nil
		},
	}
}

func (c *cli) denyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deny ENV NAME [NAME…]",
		Short: "revoke decrypt access; re-keys",
		Long:  "NAME is a principal or group. deny edits access: and re-keys the environment (new data key, every secret re-encrypted) so a removed reader is locked out; base follows.",
		Args:  usageArgs(cobra.MinimumNArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, names, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			if err := a.Deny(env, names); err != nil {
				return err
			}
			c.done(fmt.Sprintf("deny %s on %s", strings.Join(names, ", "), env), effects(a)...)
			return nil
		},
	}
	return cmd
}

func (c *cli) whoCmd() *cobra.Command {
	var keys bool
	cmd := &cobra.Command{
		Use:   "who ENV [--keys]",
		Short: "show who can decrypt",
		Long: `who prints groups as listed, then expanded principals. --keys adds fingerprints.
who base prints the derived list: every principal of every environment that
inherits base.`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, _, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			w, err := a.Who(env)
			if err != nil {
				return err
			}
			if c.json {
				out := map[string]any{
					"environment":   env,
					"access":        nonNil(w.Access),
					"derived":       w.Derived,
					"inherits_base": w.InheritsBase,
					"principals":    nonNil(w.Principals),
				}
				if keys {
					out["keys"] = w.Keys
				}
				return writeJSON(c.stdout, out)
			}
			if w.Derived {
				c.outf("access: (derived: the union of every inheriting environment's access)")
			} else {
				c.outf("access: %s", strings.Join(w.Access, ", "))
			}
			c.outf("principals:")
			for _, p := range w.Principals {
				c.outf("  %s", p)
				if keys {
					for _, k := range w.Keys[p] {
						c.outf("    %s", k)
					}
				}
			}
			if w.InheritsBase {
				c.outf("inherits base: these principals also decrypt base secrets")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&keys, "keys", false, "add key fingerprints")
	return cmd
}

// nonNil turns a nil slice into an empty one so JSON prints [] not null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// writeJSON prints v as indented JSON followed by a newline.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
