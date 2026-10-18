package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/montanaflynn/envc/internal/roster"
)

func TestEnvAdd(t *testing.T) {
	r := newRepo(t)
	r.gitRemote("git@github.com:acme/app.git")
	a := r.open()
	wantExit(t, a.EnvAdd("bad/name", EnvAddOptions{}), ExitUsage, "invalid environment name")
	wantExit(t, a.EnvAdd("prod", EnvAddOptions{Override: ".env.x"}), ExitUsage, "--override requires --dotenv")
	wantExit(t, a.EnvAdd("prod", EnvAddOptions{VercelProject: "x"}), ExitUsage, "--vercel-project requires")

	must(t, a.EnvAdd("prod", EnvAddOptions{GitHub: "production", Vercel: "production", VercelProject: "my-app"}))
	envs, err := a.EnvList()
	must(t, err)
	if !reflect.DeepEqual(envs, []string{"local", "prod"}) {
		t.Fatalf("envs = %v", envs)
	}
	rs, _ := roster.Load(r.root)
	want := map[string]roster.DestConfig{
		"github": {"environment": "production", "repository": "acme/app"},
		"vercel": {"environment": "production", "project": "my-app"},
	}
	if !reflect.DeepEqual(rs.Sync["prod"], want) {
		t.Fatalf("sync = %v", rs.Sync["prod"])
	}
	// A convex destination stores its deployment name.
	must(t, a.EnvAdd("prod", EnvAddOptions{Convex: "quiet-lion-123"}))
	rs, _ = roster.Load(r.root)
	if rs.Sync["prod"]["convex"]["deployment"] != "quiet-lion-123" {
		t.Fatalf("sync.prod.convex = %v", rs.Sync["prod"]["convex"])
	}

	// A custom environment slug is accepted and stored verbatim.
	must(t, a.EnvAdd("edge", EnvAddOptions{Vercel: "edge", VercelProject: "my-app"}))
	rs, _ = roster.Load(r.root)
	if rs.Sync["edge"]["vercel"]["environment"] != "edge" {
		t.Fatalf("sync.edge = %v", rs.Sync["edge"])
	}
	must(t, a.EnvRemove("edge", false))

	// Second add only merges destinations.
	must(t, a.Set("prod", "P", publicVal("p")))
	must(t, a.EnvAdd("prod", EnvAddOptions{Dotenv: ".env.prod"}))
	rs, _ = roster.Load(r.root)
	if rs.Sync["prod"]["dotenv"]["path"] != ".env.prod" || rs.Sync["prod"]["github"]["environment"] != "production" {
		t.Fatalf("sync = %v", rs.Sync["prod"])
	}
	if _, ok := r.load("prod").Config["P"]; !ok {
		t.Fatal("env add clobbered the file")
	}
	// Override alone is fine once dotenv exists.
	must(t, a.EnvAdd("prod", EnvAddOptions{Override: ".env.prod.local"}))
	rs, _ = roster.Load(r.root)
	if rs.Sync["prod"]["dotenv"]["override"] != ".env.prod.local" {
		t.Fatalf("sync = %v", rs.Sync["prod"])
	}
}

func TestEnvRemove(t *testing.T) {
	r := newRepo(t)
	r.gitRemote("git@github.com:acme/app.git")
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	must(t, a.EnvAdd("prod", EnvAddOptions{GitHub: "production"}))
	r.withPrincipal(a, "alice", alice, "prod")
	must(t, a.Set("prod", "S", secretVal("s")))
	r.write(".envc/state/prod/sync.yaml", "github:\n  at: 2026-08-29T23:00:00Z\n  key_id: x\n  keys: {}\n")

	wantExit(t, a.EnvRemove("prod", false), ExitUsage, "--force")
	must(t, a.EnvRemove("prod", true))
	for _, p := range []string{".envc/environments/prod.yaml", ".envc/state/prod/envelope.yaml", ".envc/state/prod/sync.yaml", ".envc/state/prod"} {
		if _, err := os.Stat(filepath.Join(r.root, p)); err == nil {
			t.Fatalf("%s still exists", p)
		}
	}
	rs, _ := roster.Load(r.root)
	if _, ok := rs.Sync["prod"]; ok {
		t.Fatal("sync.prod still present")
	}
	wantExit(t, a.EnvRemove("prod", true), ExitUsage, "unknown environment")
}

func TestEnvMove(t *testing.T) {
	r := newRepo(t)
	r.gitRemote("git@github.com:acme/app.git")
	alice := newEd25519(t, "")
	r.useKey(alice)
	a := r.open()
	must(t, a.EnvAdd("v2", EnvAddOptions{GitHub: "v2", Dotenv: ".env"}))
	r.withPrincipal(a, "alice", alice, "v2")
	must(t, a.Set("v2", "S", secretVal("s")))
	must(t, a.Set("v2", "P", publicVal("p")))
	must(t, a.Set("base", "B", secretVal("b"))) // check verifies base readers after the move
	r.write(".envc/state/v2/sync.yaml", "github:\n  at: 2026-08-29T23:00:00Z\n  key_id: x\n  keys: {}\n")
	// A hand-edited github block that leans on the default Environment
	// name (the envc environment's name).
	rs, _ := roster.Load(r.root)
	delete(rs.Sync["v2"]["github"], "environment")
	must(t, rs.Save(r.root))

	for _, c := range []struct{ from, to, msg string }{
		{"base", "app", "base"},
		{"v2", "base", "base"},
		{"v2", "bad/name", "invalid environment name"},
		{"nope", "app", "unknown environment"},
		{"v2", "local", "already exists"},
		{"v2", "v2", "already exists"},
	} {
		wantExit(t, r.open().EnvMove(c.from, c.to), ExitUsage, c.msg)
	}

	// --dry-run reports the pin and touches nothing.
	r.dryRun = true
	d := r.open()
	must(t, d.EnvMove("v2", "app"))
	r.dryRun = false
	moved := []string{
		"move .envc/environments/v2.yaml to .envc/environments/app.yaml",
		"move .envc/state/v2/ to .envc/state/app/",
		"move .env.v2.example to .env.app.example",
		"move sync.v2 to sync.app in .envc.yaml",
		"pin sync.app.github.environment to v2: the GitHub Environment keeps its name",
	}
	if got := d.Effects(); !reflect.DeepEqual(got, moved) {
		t.Fatalf("dry-run effects = %q", got)
	}
	if _, err := os.Stat(filepath.Join(r.root, ".envc/environments/app.yaml")); err == nil {
		t.Fatal("dry run wrote app.yaml")
	}

	before, err := r.open().inspect("")
	must(t, err)

	// Renaming needs no private key: nothing is decrypted or re-keyed.
	r.noKey()
	m := r.open()
	must(t, m.EnvMove("v2", "app"))
	if got := m.Effects(); !reflect.DeepEqual(got, moved) {
		t.Fatalf("effects = %q", got)
	}
	for _, p := range []string{".envc/environments/v2.yaml", ".envc/state/v2", ".env.v2.example"} {
		if _, err := os.Stat(filepath.Join(r.root, p)); err == nil {
			t.Fatalf("%s still exists", p)
		}
	}
	if !strings.Contains(r.read(".envc/state/app/envelope.yaml"), "environments/app.yaml") {
		t.Fatalf("envelope header not updated:\n%s", r.read(".envc/state/app/envelope.yaml"))
	}
	if !strings.Contains(r.read(".envc/state/app/sync.yaml"), "key_id: x") {
		t.Fatal("sync record not carried over")
	}
	if !strings.Contains(r.read(".env.app.example"), "template for app") {
		t.Fatalf("example not regenerated:\n%s", r.read(".env.app.example"))
	}
	rs, _ = roster.Load(r.root)
	if _, ok := rs.Sync["v2"]; ok {
		t.Fatal("sync.v2 still present")
	}
	want := map[string]roster.DestConfig{
		"github": {"environment": "v2", "repository": "acme/app"},
		"dotenv": {"path": ".env"},
	}
	if !reflect.DeepEqual(rs.Sync["app"], want) {
		t.Fatalf("sync.app = %v, want %v", rs.Sync["app"], want)
	}

	r.useKey(alice)
	got, err := r.open().Get("app", "S")
	must(t, err)
	if got != "s" {
		t.Fatalf("app S = %q", got)
	}
	// check sees the same repo as before, under the new name.
	after, err := r.open().inspect("")
	must(t, err)
	if b, a := strings.ReplaceAll(fmt.Sprint(before), "v2", "app"), fmt.Sprint(after); a != b {
		t.Fatalf("check after mv:\n%s\nbefore:\n%s", a, b)
	}
	// An explicit Environment needs no pin.
	n := r.open()
	must(t, n.EnvMove("app", "web"))
	if got := n.Effects(); len(got) != 4 || strings.HasPrefix(got[len(got)-1], "pin ") {
		t.Fatalf("effects = %q", got)
	}
}

// env add pins the Vercel project/team and the GitHub repository it can
// discover, so check (and CI, where .vercel/ is gitignored and git may have
// no origin) never has to derive them.
func TestEnvAddPinsDiscoveredSettings(t *testing.T) {
	t.Run("vercel from project.json", func(t *testing.T) {
		r := newRepo(t)
		a := r.open()
		r.write(".vercel/project.json", `{"projectId":"prj_123","orgId":"team_abc"}`)
		must(t, a.EnvAdd("prod", EnvAddOptions{Vercel: "production"}))
		rs, _ := roster.Load(r.root)
		want := roster.DestConfig{"environment": "production", "project": "prj_123", "team": "team_abc"}
		if !reflect.DeepEqual(rs.Sync["prod"]["vercel"], want) {
			t.Fatalf("vercel = %v, want %v", rs.Sync["prod"]["vercel"], want)
		}
		// The regression: check passes once the local link file is gone.
		must(t, os.RemoveAll(filepath.Join(r.root, ".vercel")))
		probs, err := r.open().inspect("")
		must(t, err)
		if len(probs) != 0 {
			t.Fatalf("check after removing .vercel: %v", probs)
		}
	})
	t.Run("vercel personal org pins no team", func(t *testing.T) {
		r := newRepo(t)
		r.write(".vercel/project.json", `{"projectId":"prj_123","orgId":"usr_me"}`)
		must(t, r.open().EnvAdd("prod", EnvAddOptions{Vercel: "preview"}))
		rs, _ := roster.Load(r.root)
		if _, ok := rs.Sync["prod"]["vercel"]["team"]; ok || rs.Sync["prod"]["vercel"]["project"] != "prj_123" {
			t.Fatalf("vercel = %v", rs.Sync["prod"]["vercel"])
		}
	})
	t.Run("vercel explicit project wins", func(t *testing.T) {
		r := newRepo(t)
		r.write(".vercel/project.json", `{"projectId":"prj_123","orgId":"team_abc"}`)
		must(t, r.open().EnvAdd("prod", EnvAddOptions{Vercel: "production", VercelProject: "my-app"}))
		rs, _ := roster.Load(r.root)
		if rs.Sync["prod"]["vercel"]["project"] != "my-app" || rs.Sync["prod"]["vercel"]["team"] != "team_abc" {
			t.Fatalf("vercel = %v", rs.Sync["prod"]["vercel"])
		}
	})
	t.Run("vercel without any project is usage", func(t *testing.T) {
		r := newRepo(t)
		wantExit(t, r.open().EnvAdd("prod", EnvAddOptions{Vercel: "production"}), ExitUsage, "--vercel-project")
		rs, _ := roster.Load(r.root)
		if _, ok := rs.Sync["prod"]; ok {
			t.Fatalf("sync.prod written despite error: %v", rs.Sync["prod"])
		}
	})
	t.Run("github from git remote", func(t *testing.T) {
		r := newRepo(t)
		r.gitRemote("git@github.com:acme/app.git")
		must(t, r.open().EnvAdd("prod", EnvAddOptions{GitHub: "production"}))
		rs, _ := roster.Load(r.root)
		want := roster.DestConfig{"environment": "production", "repository": "acme/app"}
		if !reflect.DeepEqual(rs.Sync["prod"]["github"], want) {
			t.Fatalf("github = %v, want %v", rs.Sync["prod"]["github"], want)
		}
		// Pinned: check no longer needs the remote.
		if out, err := exec.Command("git", "-C", r.root, "remote", "remove", "origin").CombinedOutput(); err != nil {
			t.Fatalf("git remote remove: %v\n%s", err, out)
		}
		probs, err := r.open().inspect("")
		must(t, err)
		if len(probs) != 0 {
			t.Fatalf("check after removing origin: %v", probs)
		}
	})
	t.Run("github keeps an existing repository", func(t *testing.T) {
		r := newRepo(t)
		a := r.open()
		a.Roster.Sync["prod"] = map[string]roster.DestConfig{"github": {"environment": "x", "repository": "acme/other"}}
		must(t, a.saveRoster())
		must(t, a.EnvAdd("prod", EnvAddOptions{GitHub: "production"}))
		rs, _ := roster.Load(r.root)
		if rs.Sync["prod"]["github"]["repository"] != "acme/other" || rs.Sync["prod"]["github"]["environment"] != "production" {
			t.Fatalf("github = %v", rs.Sync["prod"]["github"])
		}
	})
	t.Run("github without a remote is usage", func(t *testing.T) {
		r := newRepo(t)
		wantExit(t, r.open().EnvAdd("prod", EnvAddOptions{GitHub: "production"}), ExitUsage, "repository")
	})
}

func TestEnvAddGitHubRepositoryScope(t *testing.T) {
	r := newRepo(t)
	r.gitRemote("git@github.com:acme/app.git")
	a := r.open()
	wantExit(t, a.EnvAdd("prod", EnvAddOptions{GitHub: "production", GitHubScope: "repository"}), ExitUsage, "--github NAME does not apply")
	wantExit(t, a.EnvAdd("prod", EnvAddOptions{GitHubScope: "org"}), ExitUsage, `scope "org"`)
	wantExit(t, a.EnvAdd("prod", EnvAddOptions{GitHubScope: "environment"}), ExitUsage, "--github-scope environment requires --github")

	must(t, a.EnvAdd("prod", EnvAddOptions{GitHubScope: "repository"}))
	rs, _ := roster.Load(r.root)
	want := roster.DestConfig{"scope": "repository", "repository": "acme/app"}
	if !reflect.DeepEqual(rs.Sync["prod"]["github"], want) {
		t.Fatalf("github = %v, want %v", rs.Sync["prod"]["github"], want)
	}
	probs, err := r.open().inspect("")
	must(t, err)
	if len(probs) != 0 {
		t.Fatalf("check: %v", probs)
	}

	// Repository scope is shared: a second environment on the same
	// repository would overwrite the first on every sync.
	wantExit(t, a.EnvAdd("staging", EnvAddOptions{GitHubScope: "repository"}), ExitUsage, "prod already syncs to acme/app")
	rs, _ = roster.Load(r.root)
	if _, ok := rs.Sync["staging"]; ok {
		t.Fatalf("sync.staging written despite conflict: %v", rs.Sync["staging"])
	}
	if _, err := os.Stat(filepath.Join(r.root, ".envc/environments/staging.yaml")); err == nil {
		t.Fatal("refused env add left .envc/environments/staging.yaml behind")
	}
	// Environment scope on the same repository is fine.
	must(t, a.EnvAdd("staging", EnvAddOptions{GitHub: "staging"}))

	// Switching scopes rewrites the block instead of leaving a stale field.
	must(t, a.EnvAdd("prod", EnvAddOptions{GitHub: "production"}))
	rs, _ = roster.Load(r.root)
	want = roster.DestConfig{"environment": "production", "repository": "acme/app"}
	if !reflect.DeepEqual(rs.Sync["prod"]["github"], want) {
		t.Fatalf("github = %v, want %v", rs.Sync["prod"]["github"], want)
	}
	must(t, a.EnvAdd("prod", EnvAddOptions{GitHubScope: "repository"}))
	rs, _ = roster.Load(r.root)
	want = roster.DestConfig{"scope": "repository", "repository": "acme/app"}
	if !reflect.DeepEqual(rs.Sync["prod"]["github"], want) {
		t.Fatalf("github = %v, want %v", rs.Sync["prod"]["github"], want)
	}
}
