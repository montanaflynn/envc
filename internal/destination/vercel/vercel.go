// Package vercel syncs to a Vercel project's environment variables for one
// environment: a standard target (production | preview | development) or a
// custom environment, named by its slug and resolved to its id through the
// project's custom-environments endpoint on first use. secret: true → type
// "sensitive" with visibility "secret", which Vercel never returns; public →
// type "plain". Development is the exception: Vercel allows sensitive
// variables only in production and preview, and `vercel env pull` is how
// development reaches a laptop, so a development secret is type "encrypted"
// (readable by the team, never by the public).
//
// Auth: VERCEL_TOKEN.
//
// Only variables attached to the configured environment (its target list for
// a standard target, its customEnvironmentIds for a custom environment) and
// with no gitBranch are considered ours. A variable shared with any other
// environment — another target or another custom environment — is never
// edited in place because that would silently change the others: Apply
// PATCHes it to drop our attachment, then POSTs a fresh variable for our
// environment only. Prune on a shared variable likewise only detaches.
// Sensitive values cannot be read back, so every wanted secret is re-sent on
// Apply and reported Updated (or Created when absent).
package vercel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/montanaflynn/envc/internal/destination"
	"github.com/montanaflynn/envc/internal/destination/internal/httpx"
)

const Name = "vercel"

const defaultBaseURL = "https://api.vercel.com"

// Config is sync.<env>.vercel.
type Config struct {
	Environment string `yaml:"environment"`        // production | preview | development, or a custom environment slug
	Project     string `yaml:"project,omitempty"`  // name or id; default: .vercel/project.json projectId
	Team        string `yaml:"team,omitempty"`     // team id; default: .vercel/project.json orgId
	BaseURL     string `yaml:"base_url,omitempty"` // default https://api.vercel.com (tests)
}

var validTargets = map[string]bool{"production": true, "preview": true, "development": true}

// ParseConfig decodes the raw block with defaults applied.
func ParseConfig(root string, raw map[string]any) (Config, error) {
	var cfg Config
	for k, v := range raw {
		s, ok := v.(string)
		if !ok && v != nil {
			return Config{}, fmt.Errorf("vercel: %q must be a string", k)
		}
		switch k {
		case "environment":
			cfg.Environment = s
		case "project":
			cfg.Project = s
		case "team":
			cfg.Team = s
		case "base_url":
			cfg.BaseURL = s
		default:
			return Config{}, fmt.Errorf("vercel: unknown field %q (allowed: environment, project, team, base_url)", k)
		}
	}
	if cfg.Environment == "" {
		return Config{}, errors.New("vercel: environment is required (production | preview | development, or a custom environment slug)")
	}
	if cfg.Project == "" || cfg.Team == "" {
		pj, err := readProjectJSON(root)
		if err != nil {
			return Config{}, err
		}
		if cfg.Project == "" {
			cfg.Project = pj.ProjectID
		}
		// Vercel CLI only passes teamId when orgId is a team; personal
		// accounts have a user id there.
		if cfg.Team == "" && strings.HasPrefix(pj.OrgID, "team_") {
			cfg.Team = pj.OrgID
		}
	}
	if cfg.Project == "" {
		return Config{}, fmt.Errorf("vercel: project is required (set sync.<env>.vercel.project or run `vercel link` to create %s)", filepath.Join(root, ".vercel", "project.json"))
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return cfg, nil
}

type projectJSON struct {
	ProjectID string `json:"projectId"`
	OrgID     string `json:"orgId"`
}

// readProjectJSON reads <root>/.vercel/project.json; a missing file is not an
// error (zero values are returned).
func readProjectJSON(root string) (projectJSON, error) {
	path := filepath.Join(root, ".vercel", "project.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return projectJSON{}, nil
	}
	if err != nil {
		return projectJSON{}, fmt.Errorf("vercel: %w", err)
	}
	var pj projectJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return projectJSON{}, fmt.Errorf("vercel: parse %s: %w", path, err)
	}
	return pj, nil
}

// Vercel is the destination.
type Vercel struct {
	cfg      Config
	getenv   func(string) string
	log      io.Writer
	http     *httpx.Client
	customID string // resolved custom environment id; "" until resolveCustom
}

// New builds the destination. Registered under Name in init(). The token is
// read lazily on first request so `check` can construct without one.
func New(env destination.Env, raw map[string]any) (destination.Destination, error) {
	cfg, err := ParseConfig(env.Root, raw)
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
	return &Vercel{cfg: cfg, getenv: getenv, log: log, http: httpx.New()}, nil
}

func init() { destination.Register(Name, New) }

// Name implements destination.Destination.
func (v *Vercel) Name() string { return Name }

// ReadsBackSecrets implements destination.SecretReader: sensitive values are
// write-only.
func (v *Vercel) ReadsBackSecrets() bool { return false }

// Config returns the resolved configuration.
func (v *Vercel) Config() Config { return v.cfg }

func (v *Vercel) token() (string, error) {
	if t := v.getenv("VERCEL_TOKEN"); t != "" {
		return t, nil
	}
	return "", errors.New("vercel: no token: set VERCEL_TOKEN (create one at https://vercel.com/account/tokens)")
}

// endpoint builds a URL under the API base with teamId and extra query
// parameters applied.
func (v *Vercel) endpoint(path string, query url.Values) string {
	q := url.Values{}
	for k, vals := range query {
		q[k] = vals
	}
	if v.cfg.Team != "" {
		q.Set("teamId", v.cfg.Team)
	}
	u := v.cfg.BaseURL + path
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}
	return u
}

func (v *Vercel) projectPath(version string) string {
	return "/" + version + "/projects/" + url.PathEscape(v.cfg.Project) + "/env"
}

// do performs one API call. On 2xx, out (if non-nil) is decoded from the
// body. Non-2xx statuses become descriptive errors.
func (v *Vercel) do(ctx context.Context, method, fullURL string, body any, out any) error {
	tok, err := v.token()
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
	resp, err := v.http.Do(ctx, httpx.Request{
		Method:  method,
		URL:     fullURL,
		Headers: map[string]string{"Authorization": "Bearer " + tok, "User-Agent": "envc"},
		Body:    data,
	})
	if err != nil {
		return fmt.Errorf("vercel: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return v.apiError(method, fullURL, resp)
	}
	if out != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("vercel: %s %s: decoding response: %w", method, redact(fullURL), err)
		}
	}
	return nil
}

// redact strips the query string (teamId etc.) for error messages.
func redact(fullURL string) string {
	if i := strings.IndexByte(fullURL, '?'); i >= 0 {
		return fullURL[:i]
	}
	return fullURL
}

// apiErr carries the HTTP status so call sites can attach context-specific
// hints (e.g. plan gating) without re-parsing the message.
type apiErr struct {
	status int
	msg    string
}

func (e *apiErr) Error() string { return e.msg }

func (v *Vercel) apiError(method, fullURL string, resp *httpx.Response) error {
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(resp.Body, &payload)
	msg := payload.Error.Message
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	where := fmt.Sprintf("%s %s", method, redact(fullURL))
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return &apiErr{resp.StatusCode, fmt.Sprintf("vercel: 401 %s (%s): VERCEL_TOKEN was rejected; check it is valid, not expired, and scoped to the right team", msg, where)}
	case http.StatusForbidden:
		return &apiErr{resp.StatusCode, fmt.Sprintf("vercel: 403 %s (%s): VERCEL_TOKEN cannot access project %q; if the project belongs to a team, set sync.<env>.vercel.team to its team id", msg, where, v.cfg.Project)}
	case http.StatusNotFound:
		return &apiErr{resp.StatusCode, fmt.Sprintf("vercel: 404 %s (%s): project %q not found for this token/team (team=%q)", msg, where, v.cfg.Project, v.cfg.Team)}
	}
	return &apiErr{resp.StatusCode, fmt.Sprintf("vercel: %d %s (%s)", resp.StatusCode, msg, where)}
}

// custom reports whether the configured environment is a custom environment
// slug rather than a standard target.
func (v *Vercel) custom() bool { return !validTargets[v.cfg.Environment] }

// resolveCustom looks up the custom environment id for the configured slug,
// once per destination instance. Standard targets need no lookup.
func (v *Vercel) resolveCustom(ctx context.Context) error {
	if !v.custom() || v.customID != "" {
		return nil
	}
	var out struct {
		Environments []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"environments"`
	}
	path := "/v9/projects/" + url.PathEscape(v.cfg.Project) + "/custom-environments"
	if err := v.do(ctx, http.MethodGet, v.endpoint(path, nil), nil, &out); err != nil {
		var ae *apiErr
		if errors.As(err, &ae) && (ae.status == http.StatusPaymentRequired || ae.status == http.StatusForbidden || ae.status == http.StatusNotFound) {
			return fmt.Errorf("%w — note: custom environments exist only on Vercel Pro and Enterprise teams; check the team's plan and that %q is the environment's slug", err, v.cfg.Environment)
		}
		return err
	}
	slugs := make([]string, 0, len(out.Environments))
	for _, e := range out.Environments {
		if e.Slug == v.cfg.Environment {
			v.customID = e.ID
			return nil
		}
		slugs = append(slugs, e.Slug)
	}
	sort.Strings(slugs)
	if len(slugs) == 0 {
		return fmt.Errorf("vercel: no custom environment %q: project %q has none (standard environments are production, preview, development)", v.cfg.Environment, v.cfg.Project)
	}
	return fmt.Errorf("vercel: no custom environment %q in project %q (custom: %s; standard: production, preview, development)", v.cfg.Environment, v.cfg.Project, strings.Join(slugs, ", "))
}

// envVar is the subset of Vercel's env var object we use.
type envVar struct {
	ID                   string   `json:"id"`
	Key                  string   `json:"key"`
	Value                string   `json:"value"`
	Type                 string   `json:"type"`
	Target               []string `json:"target"`
	GitBranch            string   `json:"gitBranch"`
	CustomEnvironmentIDs []string `json:"customEnvironmentIds"`
	Decrypted            bool     `json:"decrypted"`
	UpdatedAt            int64    `json:"updatedAt"` // unix ms
}

// hidden reports whether the list gave no usable value. Sensitive values never
// come back, and an encrypted one comes back as ciphertext with
// decrypted: false even when the list asks for decrypt=true; comparing that to
// the file would report every development secret as changed.
func (e envVar) hidden() bool {
	return e.Type == "sensitive" || e.Type == "secret" || (e.Type == "encrypted" && !e.Decrypted)
}

func (e envVar) hasTarget(t string) bool {
	for _, x := range e.Target {
		if x == t {
			return true
		}
	}
	return false
}

func (e envVar) hasCustom(id string) bool {
	for _, x := range e.CustomEnvironmentIDs {
		if x == id {
			return true
		}
	}
	return false
}

// shared reports whether e is attached to any environment besides ours —
// another target or another custom environment. Editing a shared variable in
// place would silently change those, so Apply and prune split or detach it.
func (v *Vercel) shared(e envVar) bool {
	if v.custom() {
		return len(e.Target) > 0 || len(e.CustomEnvironmentIDs) > 1
	}
	return len(e.Target) > 1 || len(e.CustomEnvironmentIDs) > 0
}

// attach returns the body fields that scope a variable to our environment
// alone.
func (v *Vercel) attach() map[string]any {
	if v.custom() {
		return map[string]any{"customEnvironmentIds": []string{v.customID}}
	}
	return map[string]any{"target": []string{v.cfg.Environment}}
}

// list fetches every env var of the project, following pagination.
func (v *Vercel) list(ctx context.Context) ([]envVar, error) {
	var all []envVar
	seen := map[string]bool{}
	var until int64
	for page := 0; page < 1000; page++ {
		q := url.Values{"decrypt": {"true"}}
		if until != 0 {
			q.Set("until", fmt.Sprint(until))
		}
		var out struct {
			Envs       []envVar `json:"envs"`
			Pagination struct {
				Next int64 `json:"next"`
			} `json:"pagination"`
		}
		if err := v.do(ctx, http.MethodGet, v.endpoint(v.projectPath("v10"), q), nil, &out); err != nil {
			return nil, err
		}
		for _, e := range out.Envs {
			if e.ID != "" && seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			all = append(all, e)
		}
		next := out.Pagination.Next
		if next == 0 || next == until || len(out.Envs) == 0 {
			break
		}
		until = next
	}
	return all, nil
}

// mine filters to the variables that belong to our environment, keyed by name.
func (v *Vercel) mine(all []envVar) map[string]envVar {
	out := map[string]envVar{}
	for _, e := range all {
		if e.GitBranch != "" {
			continue
		}
		if v.custom() {
			if !e.hasCustom(v.customID) {
				continue
			}
		} else if !e.hasTarget(v.cfg.Environment) {
			continue
		}
		out[e.Key] = e
	}
	return out
}

// Live returns the variables for our environment. Sensitive ones have no
// value, only when they were last updated.
func (v *Vercel) Live(ctx context.Context) (destination.Snapshot, error) {
	if err := v.resolveCustom(ctx); err != nil {
		return nil, err
	}
	all, err := v.list(ctx)
	if err != nil {
		return nil, err
	}
	snap := destination.Snapshot{}
	for k, e := range v.mine(all) {
		if e.hidden() {
			entry := destination.Entry{Secret: true}
			if e.UpdatedAt > 0 {
				entry.Updated = time.UnixMilli(e.UpdatedAt).UTC()
			}
			snap[k] = entry
		} else {
			snap[k] = destination.Entry{Value: e.Value}
		}
	}
	return snap, nil
}

// kind returns the type and visibility fields for a value. Vercel pairs the
// two and refuses a mismatch ("Environment variables with `type: sensitive`
// must use `visibility: secret`"), so both are always sent.
func (v *Vercel) kind(secret bool) map[string]any {
	switch {
	case !secret:
		return map[string]any{"type": "plain", "visibility": "config"}
	case !v.custom() && v.cfg.Environment == "development":
		// "You can only create sensitive environment variables in the
		// preview and production environments."
		return map[string]any{"type": "encrypted", "visibility": "config"}
	default:
		return map[string]any{"type": "sensitive", "visibility": "secret"}
	}
}

func (v *Vercel) create(ctx context.Context, key string, e destination.Entry) error {
	body := map[string]any{"key": key, "value": e.Value}
	for k, val := range v.kind(e.Secret) {
		body[k] = val
	}
	for k, val := range v.attach() {
		body[k] = val
	}
	var out struct {
		Failed []struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		} `json:"failed"`
	}
	if err := v.do(ctx, http.MethodPost, v.endpoint(v.projectPath("v10"), url.Values{"upsert": {"true"}}), body, &out); err != nil {
		return err
	}
	if len(out.Failed) > 0 {
		f := out.Failed[0].Error
		return fmt.Errorf("vercel: create %s: %s: %s", key, f.Code, f.Message)
	}
	return nil
}

func (v *Vercel) patch(ctx context.Context, id string, body map[string]any) error {
	return v.do(ctx, http.MethodPatch, v.endpoint(v.projectPath("v9")+"/"+url.PathEscape(id), nil), body, nil)
}

func (v *Vercel) delete(ctx context.Context, id string) error {
	return v.do(ctx, http.MethodDelete, v.endpoint(v.projectPath("v9")+"/"+url.PathEscape(id), nil), nil, nil)
}

// detach removes our attachment from a shared variable, leaving the others.
func (v *Vercel) detach(ctx context.Context, e envVar) error {
	if v.custom() {
		rest := make([]string, 0, len(e.CustomEnvironmentIDs))
		for _, id := range e.CustomEnvironmentIDs {
			if id != v.customID {
				rest = append(rest, id)
			}
		}
		return v.patch(ctx, e.ID, map[string]any{"customEnvironmentIds": rest})
	}
	rest := make([]string, 0, len(e.Target))
	for _, t := range e.Target {
		if t != v.cfg.Environment {
			rest = append(rest, t)
		}
	}
	return v.patch(ctx, e.ID, map[string]any{"target": rest})
}

// Apply reconciles our environment with want. See the package comment.
func (v *Vercel) Apply(ctx context.Context, want destination.Snapshot, opts destination.ApplyOptions) (destination.Report, error) {
	if err := v.resolveCustom(ctx); err != nil {
		return destination.Report{}, err
	}
	all, err := v.list(ctx)
	if err != nil {
		return destination.Report{}, err
	}
	live := v.mine(all)

	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var rep destination.Report
	for _, key := range keys {
		e := want[key]
		cur, exists := live[key]
		switch {
		case !exists:
			if !opts.DryRun {
				if err := v.create(ctx, key, e); err != nil {
					return rep, fmt.Errorf("%s: %w", key, err)
				}
			}
			rep.Created = append(rep.Created, key)
		case !e.Secret && !cur.hidden() && cur.Value == e.Value:
			rep.Unchanged = append(rep.Unchanged, key)
		case v.shared(cur):
			// Shared with other environments: split rather than edit in place.
			if !opts.DryRun {
				if err := v.detach(ctx, cur); err != nil {
					return rep, fmt.Errorf("%s: detaching %s from shared variable: %w", key, v.cfg.Environment, err)
				}
				if err := v.create(ctx, key, e); err != nil {
					return rep, fmt.Errorf("%s: %w", key, err)
				}
			}
			rep.Updated = append(rep.Updated, key)
		default:
			if !opts.DryRun {
				body := map[string]any{"value": e.Value}
				for k, val := range v.kind(e.Secret) {
					body[k] = val
				}
				for k, val := range v.attach() {
					body[k] = val
				}
				if err := v.patch(ctx, cur.ID, body); err != nil {
					return rep, fmt.Errorf("%s: %w", key, err)
				}
			}
			rep.Updated = append(rep.Updated, key)
		}
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
			cur := live[k]
			if !opts.DryRun {
				var err error
				if v.shared(cur) {
					err = v.detach(ctx, cur)
				} else {
					err = v.delete(ctx, cur.ID)
				}
				if err != nil {
					return rep, fmt.Errorf("%s: prune: %w", k, err)
				}
			}
			rep.Pruned = append(rep.Pruned, k)
		}
	}
	return rep, nil
}
