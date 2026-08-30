// Package sshkey parses OpenSSH public keys, computes fingerprints, and
// fetches a user's keys from GitHub. Only ssh-ed25519 and ssh-rsa are
// accepted; everything else (sk-*, ecdsa, dsa) is rejected with a clear error
// because age cannot encrypt to them.
package sshkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// PublicKey is one parsed authorized_keys line.
type PublicKey struct {
	Type    string // "ssh-ed25519" or "ssh-rsa"
	Key     ssh.PublicKey
	Comment string
	Line    string // canonical "type base64 comment" (comment omitted if empty)
}

// githubBaseURL is the origin that FetchGitHub reads <user>.keys from.
// Tests point it at an httptest server.
var githubBaseURL = "https://github.com"

// githubUserRE is the shape of a GitHub login: alphanumerics and hyphens.
var githubUserRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)

// unsupportedTypeError is returned by Parse for key types age cannot encrypt
// to. FetchGitHub uses it to sort those keys into skipped instead of failing.
type unsupportedTypeError struct {
	Type    string
	Comment string
}

func (e *unsupportedTypeError) Error() string {
	return fmt.Sprintf("unsupported key type %s: age cannot encrypt to %s keys (only ssh-ed25519 and ssh-rsa)", e.Type, e.Type)
}

// Parse parses one authorized_keys-format line.
func Parse(line string) (PublicKey, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return PublicKey{}, errors.New("parse ssh public key: empty line")
	}
	key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return PublicKey{}, fmt.Errorf("parse ssh public key: %w", err)
	}
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA:
	default:
		return PublicKey{}, &unsupportedTypeError{Type: key.Type(), Comment: comment}
	}
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if comment != "" {
		canonical += " " + comment
	}
	return PublicKey{
		Type:    key.Type(),
		Key:     key,
		Comment: comment,
		Line:    canonical,
	}, nil
}

// ParseAll parses every non-empty, non-comment line in text.
func ParseAll(text string) ([]PublicKey, error) {
	var keys []PublicKey
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pk, err := Parse(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		keys = append(keys, pk)
	}
	return keys, nil
}

// Fingerprint returns the OpenSSH SHA256 fingerprint, e.g. "SHA256:abc…" (no padding).
func Fingerprint(pk PublicKey) string {
	return ssh.FingerprintSHA256(pk.Key)
}

// FetchGitHub downloads https://github.com/<user>.keys and parses it.
// Unsupported key types are skipped, not errors; they are returned in skipped.
func FetchGitHub(ctx context.Context, user string) (keys []PublicKey, skipped []string, err error) {
	if !githubUserRE.MatchString(user) {
		return nil, nil, fmt.Errorf("invalid github user name %q", user)
	}
	url := githubBaseURL + "/" + user + ".keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "envc")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, fmt.Errorf("github user %q not found", user)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %s: read body: %w", url, err)
	}

	for i, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pk, err := Parse(line)
		if err != nil {
			var unsupported *unsupportedTypeError
			if errors.As(err, &unsupported) {
				entry := unsupported.Type
				if unsupported.Comment != "" {
					entry += " " + unsupported.Comment
				}
				skipped = append(skipped, entry)
				continue
			}
			return nil, nil, fmt.Errorf("%s line %d: %w", url, i+1, err)
		}
		keys = append(keys, pk)
	}
	return keys, skipped, nil
}
