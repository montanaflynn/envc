package cli

import (
	"github.com/spf13/cobra"

	"github.com/montanaflynn/envc/internal/app"
)

func (c *cli) envCmd() *cobra.Command {
	cmd := group(&cobra.Command{
		Use:   "env",
		Short: "add, list, remove environments",
	})
	cmd.AddCommand(c.envAddCmd(), c.envLsCmd(), c.envRmCmd())
	return cmd
}

func (c *cli) envAddCmd() *cobra.Command {
	var o app.EnvAddOptions
	cmd := &cobra.Command{
		Use:   "add NAME [destination flags]",
		Short: "create .envc/environments/NAME.yaml and merge destination flags into sync.NAME",
		Long: `add writes .envc/environments/NAME.yaml (access: [], config: {}) if missing and
merges destination flags into sync.NAME. Running add on an existing
environment only adds destinations. --vercel pins the project (and team)
from --vercel-project or .vercel/project.json; --github pins the repository
from git remote origin, so ensure and CI never depend on local state.`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Flag combinations are app's call: --override alone is fine on
			// an environment that already has a dotenv destination, and
			// --vercel-project alone on one that already has vercel.
			a, err := c.open()
			if err != nil {
				return err
			}
			if err := a.EnvAdd(args[0], o); err != nil {
				return err
			}
			c.done("add environment "+args[0], effects(a)...)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.Dotenv, "dotenv", "", "write a .env file at `PATH`")
	f.StringVar(&o.Override, "override", "", "hand-edited override file at `PATH` (default .env.local)")
	f.StringVar(&o.GitHub, "github", "", "GitHub Environment `NAME`")
	f.StringVar(&o.Vercel, "vercel", "", "Vercel environment: production|preview|development, or a custom environment slug")
	f.StringVar(&o.VercelProject, "vercel-project", "", "Vercel project `NAME`")
	f.StringVar(&o.Convex, "convex", "", "Convex deployment `NAME`")
	return cmd
}

func (c *cli) envLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "list environments",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			envs, err := a.EnvList()
			if err != nil {
				return err
			}
			if c.json {
				return writeJSON(c.stdout, envs)
			}
			for _, e := range envs {
				c.outf("%s", e)
			}
			return nil
		},
	}
}

func (c *cli) envRmCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rm NAME [--force]",
		Short: "remove an environment and its state (refuses if it has secrets unless --force)",
		Long: `rm deletes .envc/environments/NAME.yaml, .envc/state/NAME/, .env.NAME.example,
and sync.NAME in .envc.yaml.`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			if err := a.EnvRemove(args[0], force); err != nil {
				return err
			}
			c.done("remove environment "+args[0], effects(a)...)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "remove even if the file has secrets")
	return cmd
}
