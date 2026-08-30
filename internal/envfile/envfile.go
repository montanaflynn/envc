// Package envfile reads and writes .envc/environments/<env>.yaml.
package envfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/montanaflynn/envc/internal/state"
)

// Dir is the directory under root holding environment files.
const Dir = ".envc/environments"

// BaseFile is the repo-relative path of the base layer: entries every
// environment inherits. It has the manifest schema minus access (base access
// is derived by app from every environment's access).
const BaseFile = ".envc/base.yaml"

// KeyPattern is the allowed export name.
var KeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Token delimiters. Duplicated from internal/crypto on purpose: this package
// must not import crypto (see README → Architecture, dependency direction).
const (
	tokenPrefix = "ENC[envc1,"
	tokenSuffix = "]"
)

// isToken reports whether s looks like an ENC[envc1,…] token.
func isToken(s string) bool {
	return strings.HasPrefix(s, tokenPrefix) && strings.HasSuffix(s, tokenSuffix)
}

// Entry is one config value.
type Entry struct {
	Description string   `yaml:"description,omitempty"`
	Secret      *bool    `yaml:"secret"` // required; pointer so a missing field is detectable
	Value       string   `yaml:"value"`
	Enum        []string `yaml:"enum,omitempty"`
	Pattern     string   `yaml:"pattern,omitempty"`
	Required    *bool    `yaml:"required,omitempty"` // default true
	Kind        string   `yaml:"kind,omitempty"`     // "" or "env"; "file" rejected in v1
}

// IsSecret reports Secret with a nil-safe default of false.
func (e Entry) IsSecret() bool { return e.Secret != nil && *e.Secret }

// IsRequired reports Required with a nil-safe default of true.
func (e Entry) IsRequired() bool { return e.Required == nil || *e.Required }

// File is .envc/environments/<env>.yaml: the hand-edited manifest. Only
// access and config are on disk here. Crypto is the envelope from
// .envc/state/<env>/envelope.yaml, attached in memory by app.Load so callers
// can reason about the file and its envelope together; it is never written
// to the manifest.
type File struct {
	Access []string         `yaml:"access"`
	Config map[string]Entry `yaml:"config"`
	// Inherit is the manifest's optional `base:` field: absent or true means
	// the environment inherits the base layer; false opts out (see
	// InheritsBase). Any value that is not a bool is a parse error.
	Inherit *bool           `yaml:"base,omitempty"`
	Crypto  *state.Envelope `yaml:"-"`
	// IsBase marks the base layer (.envc/base.yaml): no access or base key
	// on disk, and the access rule in Validate does not apply.
	IsBase bool `yaml:"-"`
}

// InheritsBase reports whether the environment layers base under its own
// entries: true unless the manifest says `base: false`.
func (f *File) InheritsBase() bool { return !f.IsBase && (f.Inherit == nil || *f.Inherit) }

// manifest and baseManifest are the on-disk shapes; File marshals through
// them so the base layer never carries an access or base key.
type manifest struct {
	Access []string         `yaml:"access"`
	Base   *bool            `yaml:"base,omitempty"`
	Config map[string]Entry `yaml:"config"`
}

type baseManifest struct {
	Config map[string]Entry `yaml:"config"`
}

// MarshalYAML renders the manifest shape for f (without access when Base).
func (f *File) MarshalYAML() (any, error) {
	cfg := f.Config
	if cfg == nil {
		cfg = map[string]Entry{}
	}
	if f.IsBase {
		return baseManifest{Config: cfg}, nil
	}
	access := f.Access
	if access == nil {
		access = []string{}
	}
	return manifest{Access: access, Base: f.Inherit, Config: cfg}, nil
}

// Path returns root/.envc/environments/<env>.yaml.
func Path(root, env string) string { return filepath.Join(root, Dir, env+".yaml") }

// BasePath returns root/.envc/base.yaml.
func BasePath(root string) string { return filepath.Join(root, filepath.FromSlash(BaseFile)) }

// List returns environment names present under root/.envc/environments
// (sorted). A missing directory yields an empty list.
func List(root string) ([]string, error) {
	dir := filepath.Join(root, Dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	envs := []string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		envs = append(envs, strings.TrimSuffix(name, ".yaml"))
	}
	sort.Strings(envs)
	return envs, nil
}

// Load reads and parses one environment file. Unknown top-level keys and
// unknown entry fields are errors.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	f := &File{}
	if err := dec.Decode(f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.Access == nil {
		f.Access = []string{}
	}
	if f.Config == nil {
		f.Config = map[string]Entry{}
	}
	return f, nil
}

// LoadBase reads and parses the base layer. access and base are unknown
// fields there: base access is derived from every inheriting environment's
// access, and the layer cannot inherit itself.
func LoadBase(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var m baseManifest
	if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	f := &File{Access: []string{}, Config: m.Config, IsBase: true}
	if f.Config == nil {
		f.Config = map[string]Entry{}
	}
	return f, nil
}

// NewBase returns an empty base layer (config: {}).
func NewBase() *File {
	return &File{Access: []string{}, Config: map[string]Entry{}, IsBase: true}
}

// Save writes canonical YAML atomically. Entry keys are sorted; multiline
// values use literal block style. The parent directory is created if needed.
func (f *File) Save(path string) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := writeAtomic(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// New returns an empty file (access: [], config: {}).
func New() *File {
	return &File{Access: []string{}, Config: map[string]Entry{}}
}

// Problem is one validation finding.
type Problem struct {
	Path string // e.g. "config.DATABASE_URL.value"
	Msg  string
}

func (p Problem) String() string { return p.Path + ": " + p.Msg }

// Validate checks schema rules that need no key: key names, secret set
// explicitly, kind, enum/pattern well-formed, tokens only on secrets, secrets
// are tokens once an envelope is attached, empty access only when no secrets.
// Does not verify MAC, enum membership, or pattern match on secret values.
// The envelope itself is validated by state.Envelope.Validate.
func (f *File) Validate() []Problem {
	var probs []Problem
	add := func(path, format string, args ...any) {
		probs = append(probs, Problem{Path: path, Msg: fmt.Sprintf(format, args...)})
	}

	hasSecret := false
	for _, key := range f.Keys() {
		e := f.Config[key]
		path := "config." + key
		if !KeyPattern.MatchString(key) {
			add(path, "invalid key name %q (must match %s)", key, KeyPattern)
		}
		if e.Secret == nil {
			add(path+".secret", "secret must be set explicitly (true or false)")
		}
		switch e.Kind {
		case "", "env":
		case "file":
			add(path+".kind", "kind: file is reserved in v1")
		default:
			add(path+".kind", "unknown kind %q (want env)", e.Kind)
		}
		seen := map[string]bool{}
		for i, v := range e.Enum {
			ep := fmt.Sprintf("%s.enum[%d]", path, i)
			if v == "" {
				add(ep, "enum entry is empty")
			} else if seen[v] {
				add(ep, "duplicate enum entry %q", v)
			}
			seen[v] = true
		}
		if e.Pattern != "" {
			if _, err := regexp.Compile(e.Pattern); err != nil {
				add(path+".pattern", "invalid regexp: %v", err)
			}
		}
		if e.IsSecret() {
			hasSecret = true
			if f.Crypto != nil && !isToken(e.Value) {
				add(path+".value", "secret value is plaintext; run envc ensure")
			}
		} else if isToken(e.Value) {
			add(path+".value", "public value is an encrypted token; set secret: true or replace the value")
		}
	}

	if hasSecret && len(f.Access) == 0 && !f.IsBase {
		add("access", "access is empty but the file has secret entries")
	}
	return probs
}

// SecretKeys returns sorted keys with secret: true.
func (f *File) SecretKeys() []string {
	keys := []string{}
	for _, k := range f.Keys() {
		if f.Config[k].IsSecret() {
			keys = append(keys, k)
		}
	}
	return keys
}

// EncryptedKeys returns sorted secret keys whose value is a token; a file with
// any needs its envelope to be read.
func (f *File) EncryptedKeys() []string {
	keys := []string{}
	for _, k := range f.SecretKeys() {
		if isToken(f.Config[k].Value) {
			keys = append(keys, k)
		}
	}
	return keys
}

// PlaintextSecretKeys returns sorted secret keys whose value is not a token
// (hand-edited, waiting for ensure).
func (f *File) PlaintextSecretKeys() []string {
	keys := []string{}
	for _, k := range f.SecretKeys() {
		if !isToken(f.Config[k].Value) {
			keys = append(keys, k)
		}
	}
	return keys
}

// Keys returns all config keys, sorted.
func (f *File) Keys() []string {
	keys := make([]string, 0, len(f.Config))
	for k := range f.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
