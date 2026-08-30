package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/montanaflynn/envc/internal/app"
	"github.com/montanaflynn/envc/internal/envfile"
)

// setFlags are the raw `set` flags. has* report whether the flag was passed,
// since an empty --enum "" means "clear" and --description "" means "clear".
type setFlags struct {
	secret, public bool
	stdin          bool
	file           string
	description    string
	hasDescription bool
	enum           string
	hasEnum        bool
	pattern        string
	hasPattern     bool
}

// parseSetArgs turns `set` positionals and flags into (key, app.SetOptions).
// readFile is injected so tests need no filesystem.
func parseSetArgs(args []string, f setFlags, stdin io.Reader, readFile func(string) ([]byte, error)) (string, app.SetOptions, error) {
	var o app.SetOptions
	if len(args) != 1 {
		return "", o, usagef("set: expected KEY=VALUE or KEY, got %d argument(s)", len(args))
	}
	if f.secret && f.public {
		return "", o, usagef("set: --secret and --public are mutually exclusive")
	}
	if f.stdin && f.file != "" {
		return "", o, usagef("set: --stdin and --file are mutually exclusive")
	}

	key := args[0]
	if i := strings.IndexByte(key, '='); i >= 0 {
		if f.stdin || f.file != "" {
			return "", o, usagef("set: KEY=VALUE cannot be combined with --stdin or --file")
		}
		key, o.Value, o.HasValue = key[:i], key[i+1:], true
	}
	if !envfile.KeyPattern.MatchString(key) {
		return "", o, usagef("set: invalid key %q (must match %s)", key, envfile.KeyPattern)
	}

	hasMeta := f.hasDescription || f.hasEnum || f.hasPattern
	switch {
	case f.stdin:
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", o, fmt.Errorf("set: read stdin: %w", err)
		}
		v := string(b)
		v = strings.TrimSuffix(v, "\n")
		v = strings.TrimSuffix(v, "\r")
		o.Value, o.HasValue = v, true
	case f.file != "":
		b, err := readFile(f.file)
		if err != nil {
			return "", o, fmt.Errorf("set: read %s: %w", f.file, err)
		}
		o.Value, o.HasValue = string(b), true
	case !o.HasValue && !hasMeta:
		return "", o, usagef("set: %s has no value; pass KEY=VALUE, --stdin, --file, or a metadata flag", key)
	}

	if f.secret || f.public {
		s := f.secret
		o.Secret = &s
	}
	if f.hasDescription {
		d := f.description
		o.Description = &d
	}
	if f.hasEnum {
		o.Enum = splitEnum(f.enum)
	}
	if f.hasPattern {
		p := f.pattern
		o.Pattern = &p
	}
	return key, o, nil
}

// splitEnum parses "a,b,c" into a non-nil slice; "" → empty slice (clear).
func splitEnum(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *cli) setCmd() *cobra.Command {
	var f setFlags
	cmd := &cobra.Command{
		Use:   "set ENV KEY=VALUE | KEY --stdin | KEY --file PATH  (--secret | --public) [flags]",
		Short: "create or update a config entry",
		Long: `--secret / --public are required when creating a key; an update keeps the
existing setting unless one is given.

set KEY with no value and only metadata flags patches metadata.
Flipping --public on a secret, or --secret on a public value, prints a
warning to stderr (treat the old value as compromised either way).`,
		Args: usageArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.hasDescription = cmd.Flags().Changed("description")
			f.hasEnum = cmd.Flags().Changed("enum")
			f.hasPattern = cmd.Flags().Changed("pattern")
			a, env, rest, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			key, o, err := parseSetArgs(rest, f, c.stdin, os.ReadFile)
			if err != nil {
				return err
			}
			c.warnSecretFlip(a, env, key, o.Secret)
			if err := a.Set(env, key, o); err != nil {
				return err
			}
			if env != app.BaseName && a.BaseHas(key) && inheritsBase(a, env) {
				c.done(fmt.Sprintf("set %s in %s", key, env), "overrides base")
			} else {
				c.done(fmt.Sprintf("set %s in %s", key, env))
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&f.secret, "secret", false, "encrypt the value")
	fl.BoolVar(&f.public, "public", false, "store the value in plaintext")
	fl.BoolVar(&f.stdin, "stdin", false, "value from stdin, trailing newline stripped")
	fl.StringVar(&f.file, "file", "", "value from `PATH` (PEM etc.), verbatim")
	fl.StringVar(&f.description, "description", "", "`TEXT` shown by envc ls")
	fl.StringVar(&f.enum, "enum", "", "allowed values `a,b,c` (\"\" clears)")
	fl.StringVar(&f.pattern, "pattern", "", "Go `REGEXP` the whole value must match")
	return cmd
}

// inheritsBase reports whether env layers base (base: false opts out).
// Load failures are ignored; the command itself reports them.
func inheritsBase(a *app.App, env string) bool {
	f, err := a.Load(env)
	return err == nil && f.InheritsBase()
}

// warnSecretFlip prints a warning when set would change an existing entry's
// secret flag. Load failures are ignored here; Set reports them.
func (c *cli) warnSecretFlip(a *app.App, env, key string, secret *bool) {
	if secret == nil {
		return
	}
	file, err := a.Load(env)
	if err != nil || file == nil {
		return
	}
	entry, ok := file.Config[key]
	if !ok || entry.IsSecret() == *secret {
		return
	}
	if *secret {
		c.errf("warning: %s was public and is now secret; the old value was committed in plaintext, treat it as compromised", key)
	} else {
		c.errf("warning: %s was secret and is now public; the value will be committed in plaintext, treat it as compromised", key)
	}
}

func (c *cli) unsetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unset ENV KEY",
		Short: "delete a config entry (a key only inherited from base is unset there)",
		Args:  usageArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, rest, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			if err := a.Unset(env, rest[0]); err != nil {
				return err
			}
			if env != app.BaseName && a.BaseHas(rest[0]) && inheritsBase(a, env) {
				c.done(fmt.Sprintf("unset %s in %s", rest[0], env), fmt.Sprintf("%s now inherits %s from base", env, rest[0]))
			} else {
				c.done(fmt.Sprintf("unset %s in %s", rest[0], env))
			}
			return nil
		},
	}
}

func (c *cli) getCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ENV KEY",
		Short: "print one value",
		Long: `get prints the value and a newline to stdout, TTY or not.
   psql "$(envc get production DATABASE_URL)" is the point.`,
		Args: usageArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, rest, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			v, err := a.Get(env, rest[0])
			if err != nil {
				return err
			}
			_, err = io.WriteString(c.stdout, v+"\n")
			return err
		},
	}
}

func (c *cli) lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls ENV",
		Short: "list keys with their origin (base or the environment)",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, _, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			entries, origin, err := a.Entries(env)
			if err != nil {
				return err
			}
			keys := sortedKeys(entries)
			if c.json {
				type row struct {
					Key         string `json:"key"`
					Secret      bool   `json:"secret"`
					Origin      string `json:"origin"`
					Description string `json:"description"`
				}
				rows := make([]row, 0, len(keys))
				for _, k := range keys {
					e := entries[k]
					rows = append(rows, row{k, e.IsSecret(), origin[k], e.Description})
				}
				return writeJSON(c.stdout, rows)
			}
			width, owidth := 0, 0
			for _, k := range keys {
				width = max(width, len(k))
				owidth = max(owidth, len(origin[k]))
			}
			for _, k := range keys {
				e := entries[k]
				kind := "public"
				if e.IsSecret() {
					kind = "secret"
				}
				line := fmt.Sprintf("%-*s  %-6s  %-*s", width, k, kind, owidth, origin[k])
				if e.Description != "" {
					line += "  " + e.Description
				}
				c.outf("%s", strings.TrimRight(line, " "))
			}
			return nil
		},
	}
}

func (c *cli) showCmd() *cobra.Command {
	var secrets bool
	cmd := &cobra.Command{
		Use:   "show ENV [--secrets]",
		Short: "print the environment file (secrets redacted)",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, env, _, err := c.openEnv(cmd, args)
			if err != nil {
				return err
			}
			file, err := a.Load(env)
			if err != nil {
				return err
			}
			out := envfile.File{Access: file.Access, Crypto: file.Crypto, Config: map[string]envfile.Entry{}}
			var clear map[string]string
			if secrets {
				vars, err := a.Decrypt(env)
				if err != nil {
					return err
				}
				clear = vars
			}
			for k, e := range file.Config {
				if e.IsSecret() {
					if secrets {
						e.Value = clear[k]
					} else {
						e.Value = "<redacted>"
					}
				}
				out.Config[k] = e
			}
			enc := yaml.NewEncoder(c.stdout)
			enc.SetIndent(2)
			if err := enc.Encode(&out); err != nil {
				return err
			}
			return enc.Close()
		},
	}
	cmd.Flags().BoolVar(&secrets, "secrets", false, "print decrypted secret values")
	return cmd
}
