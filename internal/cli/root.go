package cli

import (
	"github.com/spf13/cobra"

	"github.com/montanaflynn/envc/internal/app"
)

// root builds the command tree. Called once per Main.
func (c *cli) root() *cobra.Command {
	cobra.EnableCommandSorting = false // keep README order

	root := &cobra.Command{
		Use:   "envc [global flags] <command> [flags] [args]",
		Short: "env config: git is the source of truth for environment config and secrets",
		Long: `envc keeps every environment's config and secrets in one reviewable file in
git, synced to .env, GitHub Actions, Vercel, and anywhere else you deploy.
Public values stay plaintext; secret values are encrypted in place to SSH keys
you already have. Git is the source of truth; every host is a destination.

Commands that read an environment take it as the first argument:
envc set production KEY=… --secret, envc get production STRIPE_SECRET_KEY.
Values every environment shares live in the base layer (.envc/base.yaml):
envc set base KEY=… --public. set, unset, get, ls, show, ensure, and who
accept base; run, export, sync, diff, allow, and deny do not.

After editing files by hand, run envc ensure: it validates, encrypts
plaintext secrets, brings envelopes in line with access, and regenerates
.env.<env>.example; ensure --dry-run only reports.

Values go to stdout. Everything else (progress, warnings, prompts) goes to stderr.
Exit codes: 0 ok · 1 drift or problems remain · 2 cannot decrypt · 3 usage / schema.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown command %q for %q", args[0], cmd.CommandPath())
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &usageError{err}
	})

	pf := root.PersistentFlags()
	pf.BoolVar(&c.dryRun, "dry-run", false, "print what would happen")
	pf.BoolVar(&c.json, "json", false, "machine-readable output where noted")

	root.AddCommand(
		c.initCmd(),
		c.versionCmd(),

		c.envCmd(),
		c.principalCmd(),
		c.groupCmd(),

		c.allowCmd(),
		c.denyCmd(),
		c.whoCmd(),

		c.setCmd(),
		c.unsetCmd(),
		c.getCmd(),
		c.lsCmd(),
		c.showCmd(),

		c.exportCmd(),
		c.runCmd(),
		c.syncCmd(),
		c.diffCmd(),

		c.ensureCmd(),
	)
	return root
}

func (c *cli) initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "create .envc.yaml and gitignore entries",
		Long: `Creates .envc.yaml (principals: {}) and .gitignore entries for .env,
.env.local, *.agekey. No environments yet; run envc env add NAME.`,
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := app.Init("", c.options()); err != nil {
				return err
			}
			c.done("create .envc.yaml")
			return nil
		},
	}
}

func (c *cli) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print version",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c.outf("envc %s", Version)
			return nil
		},
	}
}
