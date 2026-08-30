// Package github syncs to GitHub Actions Environment variables (public) and
// Environment secrets (secret) over the REST API. Secrets are sealed with the
// environment's libsodium public key. Live returns secret names with empty
// values because GitHub never returns secret values.
//
// Auth: GH_TOKEN, then GITHUB_TOKEN. Needs a PAT/App token with Environment
// write; the GitHub Actions-provided GITHUB_TOKEN cannot manage secrets.
//
// GitHub stores variable and secret names case-insensitively (and reports
// them uppercased), so Apply matches live names to wanted keys with
// strings.EqualFold. Live returns names exactly as GitHub reports them.
package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/crypto/nacl/box"

	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/destination/internal/httpx"
)

const Name = "github"

const defaultBaseURL = "https://api.github.com"

// Config is sync.<env>.github.
type Config struct {
	Environment string `yaml:"environment"`          // default: env name
	Repository  string `yaml:"repository,omitempty"` // owner/repo; default: git remote origin
	BaseURL     string `yaml:"base_url,omitempty"`   // default https://api.github.com (tests / GHES)
}

// ParseConfig decodes the raw block with defaults applied; resolves the
// repository from `git remote get-url origin` at root when unset.
func ParseConfig(root, envName string, raw map[string]any) (Config, error) {
	var cfg Config
	for k, v := range raw {
		s, ok := v.(string)
		if !ok && v != nil {
			return Config{}, fmt.Errorf("github: %q must be a string", k)
		}
		switch k {
		case "environment":
			cfg.Environment = s
		case "repository":
			cfg.Repository = s
		case "base_url":
			cfg.BaseURL = s
		default:
			return Config{}, fmt.Errorf("github: unknown field %q (allowed: environment, repository, base_url)", k)
		}
	}
	if cfg.Environment == "" {
		cfg.Environment = envName
	}
	if cfg.Environment == "" {
		return Config{}, errors.New("github: environment is required")
	}
	if cfg.Repository == "" {
		repo, err := remoteRepository(root)
		if err != nil {
			return Config{}, fmt.Errorf("github: repository not set and could not derive it from git remote origin in %s: %w", root, err)
		}
		cfg.Repository = repo
	}
	if err := validRepository(cfg.Repository); err != nil {
		return Config{}, err
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return cfg, nil
}

func validRepository(repo string) error {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("github: repository %q must be owner/repo", repo)
	}
	return nil
}

func remoteRepository(root string) (string, error) {
	cmd := exec.Command("git", "-C", root, "remote", "get-url", "origin")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return parseRemote(strings.TrimSpace(string(out)))
}

// parseRemote extracts owner/repo from the remote URL forms git produces:
// git@host:o/r.git, ssh://git@host[:port]/o/r, https://host/o/r(.git).
func parseRemote(remote string) (string, error) {
	var path string
	switch {
	case remote == "":
		return "", errors.New("empty remote URL")
	case strings.Contains(remote, "://"):
		u, err := url.Parse(remote)
		if err != nil {
			return "", fmt.Errorf("remote %q: %w", remote, err)
		}
		path = u.Path
	default:
		// scp-like: [user@]host:path
		_, after, ok := strings.Cut(remote, ":")
		if !ok || strings.HasPrefix(remote, "/") || strings.HasPrefix(remote, ".") {
			return "", fmt.Errorf("remote %q is not a GitHub URL", remote)
		}
		path = after
	}
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("remote %q: cannot find owner/repo", remote)
	}
	return parts[0] + "/" + parts[1], nil
}

// GitHub is the destination.
type GitHub struct {
	cfg    Config
	getenv func(string) string
	log    io.Writer
	http   *httpx.Client
}

// New builds the destination. Registered under Name in init(). The token is
// read lazily on first request so `check` can construct without one.
func New(env destination.Env, raw map[string]any) (destination.Destination, error) {
	cfg, err := ParseConfig(env.Root, env.Env, raw)
	if err != nil {
		return nil, err
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	log := env.Log
	if log == nil {
		log = io.Discard
	}
	return &GitHub{cfg: cfg, getenv: getenv, log: log, http: httpx.New()}, nil
}

func init() { destination.Register(Name, New) }

// Name implements destination.Destination.
func (g *GitHub) Name() string { return Name }

// CaseInsensitiveNames implements destination.CaseInsensitiveNames: GitHub
// folds variable and secret names to uppercase.
func (g *GitHub) CaseInsensitiveNames() bool { return true }

// ReadsBackSecrets implements destination.SecretReader: GitHub never returns
// secret values.
func (g *GitHub) ReadsBackSecrets() bool { return false }

// Config returns the resolved configuration.
func (g *GitHub) Config() Config { return g.cfg }

func (g *GitHub) token() (string, error) {
	for _, k := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if v := g.getenv(k); v != "" {
			return v, nil
		}
	}
	return "", errors.New("github: no token: set GH_TOKEN or GITHUB_TOKEN to a PAT with access to Environment variables and secrets")
}

// envPath is the URL path prefix for this repository environment.
func (g *GitHub) envPath() string {
	owner, repo, _ := strings.Cut(g.cfg.Repository, "/")
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/environments/" + url.PathEscape(g.cfg.Environment)
}

// do performs one API call. On 2xx, out (if non-nil) is decoded from the
// body. Non-2xx statuses become descriptive errors.
func (g *GitHub) do(ctx context.Context, method, path string, body any, out any) error {
	tok, err := g.token()
	if err != nil {
		return err
	}
	var data []byte
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	resp, err := g.http.Do(ctx, httpx.Request{
		Method: method,
		URL:    g.cfg.BaseURL + path,
		Headers: map[string]string{
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
			"Authorization":        "Bearer " + tok,
			"User-Agent":           "envc",
		},
		Body: data,
	})
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return g.apiError(method, path, resp)
	}
	if out != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("github: %s %s: decoding response: %w", method, path, err)
		}
	}
	return nil
}

func (g *GitHub) apiError(method, path string, resp *httpx.Response) error {
	var payload struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(resp.Body, &payload)
	msg := payload.Message
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	where := fmt.Sprintf("%s %s", method, path)
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("github: 401 %s (%s): the token in GH_TOKEN/GITHUB_TOKEN was rejected; check it is valid and not expired", msg, where)
	case http.StatusForbidden:
		return fmt.Errorf("github: 403 %s (%s): the token lacks permission on %s; use a fine-grained PAT with \"Environments\" and \"Secrets\"/\"Variables\" read+write (or classic PAT with repo scope). The GitHub Actions-provided GITHUB_TOKEN cannot manage environment secrets", msg, where, g.cfg.Repository)
	case http.StatusNotFound:
		return fmt.Errorf("github: 404 %s (%s): repository %q or environment %q not found, or the token cannot see it (GitHub answers 404 for private repositories the token has no access to)", msg, where, g.cfg.Repository, g.cfg.Environment)
	}
	return fmt.Errorf("github: %d %s (%s)", resp.StatusCode, msg, where)
}

// live is the raw destination state: variables by name and secret names.
type live struct {
	vars    map[string]string
	secrets map[string]struct{}
}

func (g *GitHub) fetch(ctx context.Context) (*live, error) {
	l := &live{vars: map[string]string{}, secrets: map[string]struct{}{}}
	for page := 1; ; page++ {
		var out struct {
			TotalCount int `json:"total_count"`
			Variables  []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"variables"`
		}
		if err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s/variables?per_page=100&page=%d", g.envPath(), page), nil, &out); err != nil {
			return nil, err
		}
		for _, v := range out.Variables {
			l.vars[v.Name] = v.Value
		}
		if len(out.Variables) == 0 || len(l.vars) >= out.TotalCount {
			break
		}
	}
	for page := 1; ; page++ {
		var out struct {
			TotalCount int `json:"total_count"`
			Secrets    []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		}
		if err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s/secrets?per_page=100&page=%d", g.envPath(), page), nil, &out); err != nil {
			return nil, err
		}
		for _, s := range out.Secrets {
			l.secrets[s.Name] = struct{}{}
		}
		if len(out.Secrets) == 0 || len(l.secrets) >= out.TotalCount {
			break
		}
	}
	return l, nil
}

// Live lists environment variables (with values) and secrets (names only).
func (g *GitHub) Live(ctx context.Context) (destination.Snapshot, error) {
	l, err := g.fetch(ctx)
	if err != nil {
		return nil, err
	}
	snap := make(destination.Snapshot, len(l.vars)+len(l.secrets))
	for k, v := range l.vars {
		snap[k] = destination.Entry{Value: v}
	}
	for k := range l.secrets {
		snap[k] = destination.Entry{Secret: true}
	}
	return snap, nil
}

// foldKey returns the live name equal to key under EqualFold, if any.
func foldKey[V any](m map[string]V, key string) (string, bool) {
	if _, ok := m[key]; ok {
		return key, true
	}
	for k := range m {
		if strings.EqualFold(k, key) {
			return k, true
		}
	}
	return "", false
}

type publicKey struct {
	ID  string
	Key [32]byte
}

func (g *GitHub) publicKey(ctx context.Context) (*publicKey, error) {
	var out struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if err := g.do(ctx, http.MethodGet, g.envPath()+"/secrets/public-key", nil, &out); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(out.Key)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("github: environment public key is not a 32-byte base64 key")
	}
	pk := &publicKey{ID: out.KeyID}
	copy(pk.Key[:], raw)
	return pk, nil
}

// seal encrypts value for GitHub with libsodium's sealed box construction.
func seal(value string, pk *publicKey) (string, error) {
	sealed, err := box.SealAnonymous(nil, []byte(value), &pk.Key, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Apply reconciles the environment with want. Secrets cannot be read back, so
// every wanted secret is re-sealed and PUT, and reported Updated (or Created
// if the name was absent). A key that exists as the other kind is deleted
// first. Prune removes variables and secrets not in want.
func (g *GitHub) Apply(ctx context.Context, want destination.Snapshot, opts destination.ApplyOptions) (destination.Report, error) {
	l, err := g.fetch(ctx)
	if err != nil {
		return destination.Report{}, err
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var rep destination.Report
	var pk *publicKey
	seen := map[string]bool{} // live names (as reported) claimed by want
	for _, key := range keys {
		e := want[key]
		varName, isVar := foldKey(l.vars, key)
		secName, isSec := foldKey(l.secrets, key)
		if isVar {
			seen[varName] = true
		}
		if isSec {
			seen[secName] = true
		}
		if e.Secret {
			if isVar && !opts.DryRun {
				if err := g.do(ctx, http.MethodDelete, g.envPath()+"/variables/"+url.PathEscape(varName), nil, nil); err != nil {
					return rep, fmt.Errorf("%s: replacing variable with secret: %w", key, err)
				}
			}
			if !opts.DryRun {
				if pk == nil {
					if pk, err = g.publicKey(ctx); err != nil {
						return rep, err
					}
				}
				enc, err := seal(e.Value, pk)
				if err != nil {
					return rep, fmt.Errorf("%s: sealing secret: %w", key, err)
				}
				name := key
				if isSec {
					name = secName // keep GitHub's stored (uppercased) spelling
				}
				body := map[string]string{"encrypted_value": enc, "key_id": pk.ID}
				if err := g.do(ctx, http.MethodPut, g.envPath()+"/secrets/"+url.PathEscape(name), body, nil); err != nil {
					return rep, fmt.Errorf("%s: %w", key, err)
				}
			}
			if isSec {
				rep.Updated = append(rep.Updated, key)
			} else {
				rep.Created = append(rep.Created, key)
			}
			continue
		}
		// Public variable.
		if isSec && !opts.DryRun {
			if err := g.do(ctx, http.MethodDelete, g.envPath()+"/secrets/"+url.PathEscape(secName), nil, nil); err != nil {
				return rep, fmt.Errorf("%s: replacing secret with variable: %w", key, err)
			}
		}
		switch {
		case isVar && l.vars[varName] == e.Value:
			rep.Unchanged = append(rep.Unchanged, key)
		case isVar:
			if !opts.DryRun {
				body := map[string]string{"name": varName, "value": e.Value}
				if err := g.do(ctx, http.MethodPatch, g.envPath()+"/variables/"+url.PathEscape(varName), body, nil); err != nil {
					return rep, fmt.Errorf("%s: %w", key, err)
				}
			}
			rep.Updated = append(rep.Updated, key)
		default:
			if !opts.DryRun {
				body := map[string]string{"name": key, "value": e.Value}
				if err := g.do(ctx, http.MethodPost, g.envPath()+"/variables", body, nil); err != nil {
					return rep, fmt.Errorf("%s: %w", key, err)
				}
			}
			rep.Created = append(rep.Created, key)
		}
	}

	if opts.Prune {
		var extraVars, extraSecrets []string
		for name := range l.vars {
			if !seen[name] {
				extraVars = append(extraVars, name)
			}
		}
		for name := range l.secrets {
			if !seen[name] {
				extraSecrets = append(extraSecrets, name)
			}
		}
		sort.Strings(extraVars)
		sort.Strings(extraSecrets)
		for _, name := range extraVars {
			if !opts.DryRun {
				if err := g.do(ctx, http.MethodDelete, g.envPath()+"/variables/"+url.PathEscape(name), nil, nil); err != nil {
					return rep, fmt.Errorf("%s: prune: %w", name, err)
				}
			}
			rep.Pruned = append(rep.Pruned, name)
		}
		for _, name := range extraSecrets {
			if !opts.DryRun {
				if err := g.do(ctx, http.MethodDelete, g.envPath()+"/secrets/"+url.PathEscape(name), nil, nil); err != nil {
					return rep, fmt.Errorf("%s: prune: %w", name, err)
				}
			}
			rep.Pruned = append(rep.Pruned, name)
		}
		sort.Strings(rep.Pruned)
	}
	return rep, nil
}
