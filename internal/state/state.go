// Package state reads and writes the generated, committed files under
// .envc/state/<env>/: the encryption envelope and the sync record. Nothing in
// this package is hand-edited; the manifest (.envc/environments/<env>.yaml)
// is the human side.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Dir is the directory under root holding one subdirectory per environment.
const Dir = ".envc/state"

// File names inside .envc/state/<env>/.
const (
	EnvelopeFile = "envelope.yaml"
	SyncFile     = "sync.yaml"
)

// Headers written above each file. They are the only comments envc writes.
const (
	envelopeHeader = "# Written by envc. Commit it. Never edit or delete: it holds the data key that\n# unlocks the ENC[…] values in environments/%s.yaml.\n"
	syncHeader     = "# Written by envc sync. Commit it. Safe to delete; the next sync recreates it.\n"
)

// EnvDir returns root/.envc/state/<env>.
func EnvDir(root, env string) string { return filepath.Join(root, Dir, env) }

// EnvelopePath returns root/.envc/state/<env>/envelope.yaml.
func EnvelopePath(root, env string) string { return filepath.Join(EnvDir(root, env), EnvelopeFile) }

// SyncPath returns root/.envc/state/<env>/sync.yaml.
func SyncPath(root, env string) string { return filepath.Join(EnvDir(root, env), SyncFile) }

// Envelope is envelope.yaml: the data key wrapped to every recipient, and the
// MAC over the decrypted secrets.
type Envelope struct {
	Version    int      `yaml:"version"`
	Recipients []string `yaml:"recipients"` // SHA256:… or age1…
	Key        string   `yaml:"key"`        // base64std age ciphertext of data_key
	MAC        string   `yaml:"mac"`
}

// Problem is one validation finding in a state file.
type Problem struct {
	Path string // e.g. "recipients"
	Msg  string
}

func (p Problem) String() string { return p.Path + ": " + p.Msg }

// Validate checks the envelope's own schema (no key needed).
func (e *Envelope) Validate() []Problem {
	var probs []Problem
	if e.Version != 1 {
		probs = append(probs, Problem{"version", fmt.Sprintf("unsupported envelope version %d (want 1)", e.Version)})
	}
	if e.Key == "" {
		probs = append(probs, Problem{"key", "missing wrapped data key"})
	}
	if len(e.Recipients) == 0 {
		probs = append(probs, Problem{"recipients", "no recipients"})
	}
	return probs
}

// LoadEnvelope reads envelope.yaml. A missing file is (nil, nil).
func LoadEnvelope(root, env string) (*Envelope, error) {
	path := EnvelopePath(root, env)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	e := &Envelope{}
	if err := dec.Decode(e); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return e, nil
}

// Save writes envelope.yaml atomically, creating the directory.
func (e *Envelope) Save(root, env string) error {
	out := *e
	if out.Recipients == nil {
		out.Recipients = []string{}
	}
	return write(EnvelopePath(root, env), fmt.Sprintf(envelopeHeader, env), &out)
}

// RemoveEnvelope deletes envelope.yaml (used when the last secret goes away).
// A missing file is not an error.
func RemoveEnvelope(root, env string) error {
	return removeFile(EnvelopePath(root, env))
}

// Destination is the sync record for one destination.
type Destination struct {
	At    time.Time         `yaml:"at"`
	KeyID string            `yaml:"key_id"`
	Keys  map[string]string `yaml:"keys"` // KEY → sync HMAC (16 hex chars)
}

// Sync is sync.yaml: destination name → record.
type Sync map[string]Destination

// LoadSync reads sync.yaml. A missing file is an empty Sync, not an error.
func LoadSync(root, env string) (Sync, error) {
	path := SyncPath(root, env)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Sync{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	s := Sync{}
	if err := dec.Decode(&s); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s == nil {
		s = Sync{}
	}
	for name, d := range s {
		if d.Keys == nil {
			d.Keys = map[string]string{}
			s[name] = d
		}
	}
	return s, nil
}

// Save writes sync.yaml atomically, creating the directory. Times are
// written as RFC3339 in UTC at second precision.
func (s Sync) Save(root, env string) error {
	out := make(Sync, len(s))
	for name, d := range s {
		d.At = d.At.UTC().Truncate(time.Second)
		if d.Keys == nil {
			d.Keys = map[string]string{}
		}
		out[name] = d
	}
	return write(SyncPath(root, env), syncHeader, out)
}

// RemoveSync deletes sync.yaml. A missing file is not an error.
func RemoveSync(root, env string) error {
	return removeFile(SyncPath(root, env))
}

// Remove deletes .envc/state/<env>/ and everything in it.
func Remove(root, env string) error {
	if err := os.RemoveAll(EnvDir(root, env)); err != nil {
		return fmt.Errorf("remove %s: %w", EnvDir(root, env), err)
	}
	return nil
}

func write(path, header string, v any) error {
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
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

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
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
