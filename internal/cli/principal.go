package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/montanaflynn/envc/internal/app"
	"github.com/montanaflynn/envc/internal/sshkey"
)

func (c *cli) principalCmd() *cobra.Command {
	cmd := group(&cobra.Command{
		Use:   "principal",
		Short: "add, list, remove, sync keys",
	})
	cmd.AddCommand(
		c.principalAddCmd(),
		c.principalLsCmd(),
		c.principalShowCmd(),
		c.principalRmCmd(),
		c.principalSyncCmd(),
	)
	return cmd
}

func (c *cli) principalAddCmd() *cobra.Command {
	var (
		github, sshKey, ageRecipient string
		allKeys, ed25519Only         bool
	)
	cmd := &cobra.Command{
		Use:   "add NAME (--github USER | --ssh-key FILE|- | --age age1…)",
		Short: "add a principal and pin its public keys",
		Long: `add --github lists keys and pins the selection into .envc.yaml.
--ssh-key reads OpenSSH public key lines from FILE (or stdin with -).
--age adds an age1… recipient.`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if github == "" && sshKey == "" && ageRecipient == "" {
				return usagef("principal add: one of --github, --ssh-key, or --age is required")
			}
			if github != "" && sshKey != "" {
				return usagef("principal add: --github and --ssh-key are mutually exclusive")
			}
			a, err := c.open()
			if err != nil {
				return err
			}

			var keys []string
			switch {
			case github != "":
				fetched, skipped, err := a.PrincipalFetchGitHub(cmd.Context(), github, ed25519Only)
				if err != nil {
					return err
				}
				for _, s := range skipped {
					c.errf("skipped unsupported key: %s", s)
				}
				if len(fetched) == 0 {
					return fmt.Errorf("principal add: no supported keys found for github user %q", github)
				}
				keys, err = c.selectKeys(fetched, allKeys)
				if err != nil {
					return err
				}
			case sshKey != "":
				keys, err = readKeyLines(sshKey, c.stdin)
				if err != nil {
					return err
				}
				if len(keys) == 0 {
					return fmt.Errorf("principal add: no public keys in %s", sshKey)
				}
			}

			if err := a.PrincipalAddKeys(name, github, keys, ageRecipient); err != nil {
				return err
			}
			n := len(keys)
			if ageRecipient != "" {
				n++
			}
			c.done(fmt.Sprintf("add principal %s with %d key(s)", name, n), effects(a)...)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&github, "github", "", "fetch https://github.com/`USER`.keys")
	f.StringVar(&sshKey, "ssh-key", "", "public key `FILE`, or - for stdin")
	f.StringVar(&ageRecipient, "age", "", "age `RECIPIENT` (age1…)")
	f.BoolVar(&allKeys, "all-keys", false, "pin every fetched key (default: interactive / TTY)")
	f.BoolVar(&ed25519Only, "ed25519-only", false, "skip ssh-rsa when fetching")
	return cmd
}

// selectKeys picks which fetched keys to pin: all with --all-keys, an
// interactive numbered selection on a TTY, otherwise a usage error.
func (c *cli) selectKeys(fetched []string, allKeys bool) ([]string, error) {
	if allKeys {
		return fetched, nil
	}
	if !isTerminal(c.stdin) || !isTerminal(c.stderr) {
		return nil, usagef("principal add: not a terminal; pass --all-keys to pin every fetched key")
	}
	c.errf("Fetched %d key(s):", len(fetched))
	for i, line := range fetched {
		c.errf("  %d) %s", i+1, describeKey(line))
	}
	fmt.Fprint(c.stderr, "Pin which keys? (comma-separated numbers, empty = all): ")
	sel, err := readLine(c.stdin)
	if err != nil {
		return nil, err
	}
	return pickKeys(fetched, sel)
}

// pickKeys resolves a selection like "1,3" against fetched. Empty = all.
func pickKeys(fetched []string, selection string) ([]string, error) {
	selection = strings.TrimSpace(selection)
	if selection == "" {
		return fetched, nil
	}
	seen := map[int]bool{}
	var out []string
	for _, part := range strings.Split(selection, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > len(fetched) {
			return nil, usagef("principal add: invalid selection %q (choose 1..%d)", part, len(fetched))
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, fetched[n-1])
		}
	}
	if len(out) == 0 {
		return nil, usagef("principal add: nothing selected")
	}
	return out, nil
}

// describeKey renders one OpenSSH line as "type fingerprint comment" for a
// menu; falls back to the raw line when it cannot be parsed.
func describeKey(line string) string {
	pk, err := sshkey.Parse(line)
	if err != nil {
		return line
	}
	s := pk.Type + " " + sshkey.Fingerprint(pk)
	if pk.Comment != "" {
		s += " " + pk.Comment
	}
	return s
}

// readKeyLines reads non-empty, non-comment lines from path (or stdin for "-").
func readKeyLines(path string, stdin io.Reader) ([]string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		lines = append(lines, l)
	}
	return lines, nil
}

// readLine reads one line from r (without the trailing newline).
func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *cli) principalLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "list principals",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			names := sortedKeys(a.Roster.Principals)
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

func (c *cli) principalShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "show a principal's GitHub user and pinned keys",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			p, ok := a.Roster.Principals[args[0]]
			if !ok {
				return &app.ExitError{Code: app.ExitUsage, Err: fmt.Errorf("principal %q not found", args[0])}
			}
			if c.json {
				return writeJSON(c.stdout, map[string]any{
					"name": args[0], "github": p.GitHub, "keys": p.Keys, "age": p.Age,
				})
			}
			c.outf("%s", args[0])
			if p.GitHub != "" {
				c.outf("  github: %s", p.GitHub)
			}
			for _, k := range p.Keys {
				c.outf("  key: %s", describeKey(k))
			}
			if p.Age != "" {
				c.outf("  age: %s", p.Age)
			}
			return nil
		},
	}
}

func (c *cli) principalRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm NAME",
		Short: "remove a principal from roster, groups, and access; re-keys",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.open()
			if err != nil {
				return err
			}
			if _, err := a.PrincipalRemove(args[0]); err != nil {
				return err
			}
			c.done("remove principal "+args[0], effects(a)...)
			return nil
		},
	}
	return cmd
}

func (c *cli) principalSyncCmd() *cobra.Command {
	var all, ed25519Only bool
	cmd := &cobra.Command{
		Use:   "sync NAME | --all",
		Short: "refetch GitHub keys, show +/-, apply pins",
		Long: `sync refetches GitHub keys, shows +/-, applies pins. Added keys update
the readers; removed keys re-key the environments that include this
principal, so the old key is locked out.`,
		Args: usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) == 1) {
				return usagef("principal sync: pass exactly one of NAME or --all")
			}
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			a, err := c.open()
			if err != nil {
				return err
			}
			changes, err := a.PrincipalSync(cmd.Context(), name, all, ed25519Only)
			if err != nil {
				return err
			}
			if c.json {
				return writeJSON(c.stdout, changes)
			}
			n := 0
			for _, ch := range changes {
				if len(ch.Added) == 0 && len(ch.Removed) == 0 {
					continue
				}
				n++
				c.errf("%s:", ch.Principal)
				for _, k := range ch.Added {
					c.errf("  + %s", describeKey(k))
				}
				for _, k := range ch.Removed {
					c.errf("  - %s", describeKey(k))
				}
			}
			if n == 0 {
				c.errf("up to date")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "sync every principal with github: set")
	cmd.Flags().BoolVar(&ed25519Only, "ed25519-only", false, "skip ssh-rsa when fetching")
	return cmd
}

// sortedKeys returns the keys of m sorted.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
