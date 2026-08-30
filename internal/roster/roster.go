// Package roster reads and writes .envc.yaml: principals, groups, and
// per-environment destination config.
package roster

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// FileName is the roster file name at the repo root.
const FileName = ".envc.yaml"

// namePattern is the allowed shape of a principal or group name.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Principal is a named key holder. envc does not distinguish humans from bots.
type Principal struct {
	GitHub string   `yaml:"github,omitempty"`
	Keys   []string `yaml:"keys,omitempty"` // OpenSSH public key lines, pinned
	Age    string   `yaml:"age,omitempty"`  // optional age1… recipient
}

// DestConfig is the raw, destination-specific block under sync.<env>.<name>.
// Destinations decode it themselves.
type DestConfig map[string]any

// Roster is .envc.yaml.
type Roster struct {
	Principals map[string]Principal             `yaml:"principals"`
	Groups     map[string][]string              `yaml:"groups,omitempty"`
	Sync       map[string]map[string]DestConfig `yaml:"sync,omitempty"` // env → dest name → config
}

// Load reads and parses .envc.yaml at root. Unknown top-level keys are an error.
func Load(root string) (*Roster, error) {
	path := filepath.Join(root, FileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	r := &Roster{}
	if err := dec.Decode(r); err != nil {
		if errors.Is(err, io.EOF) {
			// Empty file: treat as an empty roster.
			r = &Roster{}
		} else {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	r.ensureMaps()
	return r, nil
}

// Save writes canonical YAML atomically.
func (r *Roster) Save(root string) error {
	path := filepath.Join(root, FileName)
	data, err := marshal(r)
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := writeAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// New returns an empty roster.
func New() *Roster {
	r := &Roster{}
	r.ensureMaps()
	return r
}

func (r *Roster) ensureMaps() {
	if r.Principals == nil {
		r.Principals = map[string]Principal{}
	}
	if r.Groups == nil {
		r.Groups = map[string][]string{}
	}
	if r.Sync == nil {
		r.Sync = map[string]map[string]DestConfig{}
	}
}

// Problem is one validation finding.
type Problem struct {
	Path string // e.g. "groups.engineers[1]"
	Msg  string
}

func (p Problem) String() string { return p.Path + ": " + p.Msg }

// Validate checks structure: principal names, key parseability, groups contain
// only principals, no name is both a principal and a group, default env set.
// It does not check that sync destination names are registered (app does that).
func (r *Roster) Validate() []Problem {
	var probs []Problem
	add := func(path, format string, args ...any) {
		probs = append(probs, Problem{Path: path, Msg: fmt.Sprintf(format, args...)})
	}

	for _, name := range sortedKeys(r.Principals) {
		p := r.Principals[name]
		path := "principals." + name
		if !namePattern.MatchString(name) {
			add(path, "invalid principal name %q (must match %s)", name, namePattern)
		}
		for i, key := range p.Keys {
			if msg := checkSSHKey(key); msg != "" {
				add(fmt.Sprintf("%s.keys[%d]", path, i), "%s", msg)
			}
		}
		if p.Age != "" && !strings.HasPrefix(p.Age, "age1") {
			add(path+".age", "not an age recipient (expected age1…)")
		}
		if len(p.Keys) == 0 && p.Age == "" {
			add(path, "principal has no keys and no age recipient")
		}
	}

	for _, name := range sortedKeys(r.Groups) {
		path := "groups." + name
		if !namePattern.MatchString(name) {
			add(path, "invalid group name %q (must match %s)", name, namePattern)
		}
		if r.IsPrincipal(name) {
			add(path, "name is both a principal and a group")
		}
		for i, member := range r.Groups[name] {
			switch {
			case r.IsPrincipal(member):
			case r.IsGroup(member):
				add(fmt.Sprintf("%s[%d]", path, i), "%q is a group; groups may contain only principals", member)
			default:
				add(fmt.Sprintf("%s[%d]", path, i), "unknown principal %q", member)
			}
		}
	}

	return probs
}

// checkSSHKey returns a problem message for an authorized_keys line, or "".
func checkSSHKey(line string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return fmt.Sprintf("cannot parse OpenSSH public key: %v", err)
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA:
		return ""
	}
	return fmt.Sprintf("unsupported key type %s (want ssh-ed25519 or ssh-rsa)", pub.Type())
}

// IsPrincipal / IsGroup report whether name exists in that table.
func (r *Roster) IsPrincipal(name string) bool { _, ok := r.Principals[name]; return ok }
func (r *Roster) IsGroup(name string) bool     { _, ok := r.Groups[name]; return ok }

// Expand resolves an access list (principal and group names) to a sorted,
// de-duplicated list of principal names. Unknown names are an error.
func (r *Roster) Expand(access []string) ([]string, error) {
	set := map[string]bool{}
	for _, name := range access {
		switch {
		case r.IsPrincipal(name):
			set[name] = true
		case r.IsGroup(name):
			for _, m := range r.Groups[name] {
				set[m] = true
			}
		default:
			return nil, fmt.Errorf("access: unknown principal or group %q", name)
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// KeyRef is one public key attached to a principal.
type KeyRef struct {
	Principal string
	SSH       string // OpenSSH public key line; "" if this ref is an age recipient
	Age       string // age1… ; "" if SSH
}

// KeysFor returns every key of every named principal, in principal order.
// SSH keys come first (in pinned order), then the age recipient if any.
func (r *Roster) KeysFor(principals []string) ([]KeyRef, error) {
	refs := []KeyRef{}
	for _, name := range principals {
		p, ok := r.Principals[name]
		if !ok {
			return nil, fmt.Errorf("unknown principal %q", name)
		}
		for _, key := range p.Keys {
			refs = append(refs, KeyRef{Principal: name, SSH: key})
		}
		if p.Age != "" {
			refs = append(refs, KeyRef{Principal: name, Age: p.Age})
		}
	}
	return refs, nil
}

// EnvironmentsWith returns sorted env names whose sync block configures the
// destination dest. With dest == "" it returns every env whose sync block is
// non-empty.
func (r *Roster) EnvironmentsWith(dest string) []string {
	var envs []string
	for env, dests := range r.Sync {
		if dest == "" {
			if len(dests) > 0 {
				envs = append(envs, env)
			}
			continue
		}
		if _, ok := dests[dest]; ok {
			envs = append(envs, env)
		}
	}
	sort.Strings(envs)
	return envs
}

// RemovePrincipal deletes the principal and drops it from every group.
// Returns the sorted names of the groups it was removed from.
func (r *Roster) RemovePrincipal(name string) []string {
	delete(r.Principals, name)
	var removed []string
	for group, members := range r.Groups {
		kept := make([]string, 0, len(members))
		for _, m := range members {
			if m != name {
				kept = append(kept, m)
			}
		}
		if len(kept) != len(members) {
			removed = append(removed, group)
			r.Groups[group] = kept
		}
	}
	sort.Strings(removed)
	return removed
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// marshal produces canonical YAML: 2-space indent, sorted map keys, struct
// fields in declared order.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeAtomic writes data to a temp file in path's directory, then renames it
// over path.
func writeAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
