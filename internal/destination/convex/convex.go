// Package convex syncs to one Convex deployment's environment variables over
// the deployment's HTTP API. Both multi-deployment styles work: several named
// deployments in one project (each envc environment names its own deployment)
// and the older project-per-environment layout. Convex has no public/secret
// distinction and returns every value, so Live reads values back and diff
// compares against them directly, like dotenv.
//
// Auth: a deploy key in CONVEX_DEPLOY_KEY, or the env var named by key_env so
// environments in different projects can each hold their own key. Keys that
// embed a deployment name (prod:name|…, dev:name|…, and dashboard admin keys
// name|…) are checked against the configured deployment before any request,
// so a production key cannot sync another environment. Preview- and
// project-scoped keys carry no deployment name and skip the check.
package convex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/destination/internal/httpx"
)

const Name = "convex"

// Config is sync.<env>.convex.
type Config struct {
	Deployment string `yaml:"deployment"`        // deployment name, e.g. quiet-lion-123
	URL        string `yaml:"url,omitempty"`     // default https://<deployment>.convex.cloud; set for self-hosted
	KeyEnv     string `yaml:"key_env,omitempty"` // env var holding the deploy key; default CONVEX_DEPLOY_KEY
}

// ParseConfig decodes the raw block with defaults applied.
func ParseConfig(raw map[string]any) (Config, error) {
	var cfg Config
	for k, v := range raw {
		s, ok := v.(string)
		if !ok && v != nil {
			return Config{}, fmt.Errorf("convex: %q must be a string", k)
		}
		switch k {
		case "deployment":
			cfg.Deployment = s
		case "url":
			cfg.URL = s
		case "key_env":
			cfg.KeyEnv = s
		default:
			return Config{}, fmt.Errorf("convex: unknown field %q (allowed: deployment, url, key_env)", k)
		}
	}
	if cfg.Deployment == "" && cfg.URL == "" {
		return Config{}, errors.New("convex: deployment is required (the deployment name, e.g. quiet-lion-123; or url for self-hosted)")
	}
	if cfg.URL == "" {
		cfg.URL = "https://" + cfg.Deployment + ".convex.cloud"
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	if cfg.KeyEnv == "" {
		cfg.KeyEnv = "CONVEX_DEPLOY_KEY"
	}
	return cfg, nil
}

// Convex is the destination.
type Convex struct {
	cfg     Config
	envName string
	getenv  func(string) string
	log     io.Writer
	http    *httpx.Client
}

// New builds the destination. Registered under Name in init(). The key is
// read lazily on first request so `check` can construct without one.
func New(env destination.Env, raw map[string]any) (destination.Destination, error) {
	cfg, err := ParseConfig(raw)
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
	return &Convex{cfg: cfg, envName: env.Env, getenv: getenv, log: log, http: httpx.New()}, nil
}

func init() { destination.Register(Name, New) }

// Name implements destination.Destination.
func (c *Convex) Name() string { return Name }

// ReadsBackSecrets implements destination.SecretReader: Convex returns every
// value, so diff compares live values directly and sync keeps no record.
func (c *Convex) ReadsBackSecrets() bool { return true }

// Config returns the resolved configuration.
func (c *Convex) Config() Config { return c.cfg }

// keyDeploymentName extracts the deployment name a key is scoped to, or ""
// when the key carries none (preview:team:project, project:team:project).
func keyDeploymentName(key string) string {
	head, _, ok := strings.Cut(key, "|")
	if !ok {
		return ""
	}
	if typ, rest, ok := strings.Cut(head, ":"); ok {
		if (typ == "prod" || typ == "dev") && !strings.Contains(rest, ":") {
			return rest
		}
		return ""
	}
	return head // bare dashboard admin key: name|hex
}

func (c *Convex) key() (string, error) {
	k := c.getenv(c.cfg.KeyEnv)
	if k == "" {
		return "", fmt.Errorf("convex: no deploy key: set %s (a deploy key for deployment %q — Convex dashboard → Settings → Deploy key, or `npx convex deployment token create`)", c.cfg.KeyEnv, c.cfg.Deployment)
	}
	if name := keyDeploymentName(k); name != "" && c.cfg.Deployment != "" && name != c.cfg.Deployment {
		return "", fmt.Errorf("convex: %s holds a key for deployment %q, but sync.%s.convex.deployment is %q", c.cfg.KeyEnv, name, c.envName, c.cfg.Deployment)
	}
	return k, nil
}

// do performs one API call against the deployment. On 2xx, out (if non-nil)
// is decoded from the body. Non-2xx statuses become descriptive errors.
func (c *Convex) do(ctx context.Context, path string, body any, out any) error {
	key, err := c.key()
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(ctx, httpx.Request{
		Method: http.MethodPost,
		URL:    c.cfg.URL + path,
		Headers: map[string]string{
			"Authorization": "Convex " + key,
			"Content-Type":  "application/json",
			"User-Agent":    "envc",
		},
		Body: data,
	})
	if err != nil {
		return fmt.Errorf("convex: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return c.apiError(path, resp)
	}
	if out != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("convex: POST %s: decoding response: %w", path, err)
		}
	}
	return nil
}

func (c *Convex) apiError(path string, resp *httpx.Response) error {
	var payload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(resp.Body, &payload)
	msg := payload.Message
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	where := fmt.Sprintf("POST %s%s", c.cfg.URL, path)
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("convex: %d %s (%s): %s was rejected; check it holds a valid deploy key for deployment %q — mint one with `npx convex deployment token create` or the dashboard's Deploy key page (older prod deploy keys may lack environment-variable access)", resp.StatusCode, msg, where, c.cfg.KeyEnv, c.cfg.Deployment)
	case http.StatusNotFound:
		return fmt.Errorf("convex: 404 %s (%s): deployment %q not found (set sync.%s.convex.url if it is self-hosted)", msg, where, c.cfg.Deployment, c.envName)
	}
	return fmt.Errorf("convex: %d %s (%s)", resp.StatusCode, msg, where)
}

// liveVars lists the deployment's environment variables via the system query
// the Convex CLI and dashboard use.
func (c *Convex) liveVars(ctx context.Context) (map[string]string, error) {
	body := map[string]any{"path": "_system/cli/queryEnvironmentVariables", "args": map[string]any{}, "format": "json"}
	var out struct {
		Status       string `json:"status"`
		ErrorMessage string `json:"errorMessage"`
		Value        []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"value"`
	}
	if err := c.do(ctx, "/api/query", body, &out); err != nil {
		return nil, err
	}
	if out.Status != "success" {
		return nil, fmt.Errorf("convex: listing environment variables: %s", out.ErrorMessage)
	}
	vars := make(map[string]string, len(out.Value))
	for _, v := range out.Value {
		vars[v.Name] = v.Value
	}
	return vars, nil
}

// Live returns every variable with its value; Convex hides nothing.
func (c *Convex) Live(ctx context.Context) (destination.Snapshot, error) {
	vars, err := c.liveVars(ctx)
	if err != nil {
		return nil, err
	}
	snap := destination.Snapshot{}
	for k, v := range vars {
		snap[k] = destination.Entry{Value: v}
	}
	return snap, nil
}

type change struct {
	Name  string  `json:"name"`
	Value *string `json:"value"` // nil removes the variable
}

// Apply reconciles the deployment with want in one batched update.
func (c *Convex) Apply(ctx context.Context, want destination.Snapshot, opts destination.ApplyOptions) (destination.Report, error) {
	live, err := c.liveVars(ctx)
	if err != nil {
		return destination.Report{}, err
	}

	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var rep destination.Report
	var changes []change
	for _, key := range keys {
		v := want[key].Value
		cur, exists := live[key]
		switch {
		case !exists:
			rep.Created = append(rep.Created, key)
		case cur != v:
			rep.Updated = append(rep.Updated, key)
		default:
			rep.Unchanged = append(rep.Unchanged, key)
			continue
		}
		val := v
		changes = append(changes, change{Name: key, Value: &val})
	}

	if opts.Prune {
		var extra []string
		for k := range live {
			if _, ok := want[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		for _, k := range extra {
			rep.Pruned = append(rep.Pruned, k)
			changes = append(changes, change{Name: k})
		}
	}

	if len(changes) > 0 && !opts.DryRun {
		if err := c.do(ctx, "/api/update_environment_variables", map[string]any{"changes": changes}, nil); err != nil {
			return rep, err
		}
	}
	return rep, nil
}
