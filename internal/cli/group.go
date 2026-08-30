package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/montanaflynn/envc/internal/app"
)

func (c *cli) groupCmd() *cobra.Command {
	cmd := group(&cobra.Command{
		Use:   "group",
		Short: "create and edit groups",
		Long: `Members must be principals. add-member updates the readers of, and
rm-member re-keys, the environments that list this group on access.`,
	})
	cmd.AddCommand(
		c.groupAddCmd(),
		c.groupLsCmd(),
		c.groupShowCmd(),
		c.groupRmCmd(),
		c.groupAddMemberCmd(),
		c.groupRmMemberCmd(),
	)
	return cmd
}

func (c *cli) groupAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add NAME PRINCIPAL [PRINCIPAL…]",
		Short: "create a group (or replace its members)",
		Args:  usageArgs(cobra.MinimumNArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			if err := a.GroupSet(args[0], args[1:]); err != nil {
				return err
			}
			c.done(fmt.Sprintf("set group %s: %s", args[0], strings.Join(args[1:], ", ")), effects(a)...)
			return nil
		},
	}
}

func (c *cli) groupLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "list groups",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			names := sortedKeys(a.Roster.Groups)
			if c.json {
				return writeJSON(c.stdout, names)
			}
			for _, n := range names {
				c.outf("%s", n)
			}
			return nil
		},
	}
}

func (c *cli) groupShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "list a group's members",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			members, ok := a.Roster.Groups[args[0]]
			if !ok {
				return &app.ExitError{Code: app.ExitUsage, Err: fmt.Errorf("group %q not found", args[0])}
			}
			if c.json {
				return writeJSON(c.stdout, map[string]any{"name": args[0], "members": members})
			}
			for _, m := range members {
				c.outf("%s", m)
			}
			return nil
		},
	}
}

func (c *cli) groupRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm NAME",
		Short: "delete a group (errors if any environment lists it on access)",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			if err := a.GroupRemove(args[0]); err != nil {
				return err
			}
			c.done("remove group "+args[0], effects(a)...)
			return nil
		},
	}
}

func (c *cli) groupAddMemberCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-member NAME PRINCIPAL",
		Short: "add a principal to a group",
		Args:  usageArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			if _, err := a.GroupAddMember(args[0], args[1]); err != nil {
				return err
			}
			c.done(fmt.Sprintf("add %s to group %s", args[1], args[0]), effects(a)...)
			return nil
		},
	}
}

func (c *cli) groupRmMemberCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm-member NAME PRINCIPAL",
		Short: "remove a principal from a group; re-keys",
		Args:  usageArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			if _, err := a.GroupRemoveMember(args[0], args[1]); err != nil {
				return err
			}
			c.done(fmt.Sprintf("remove %s from group %s", args[1], args[0]), effects(a)...)
			return nil
		},
	}
	return cmd
}
