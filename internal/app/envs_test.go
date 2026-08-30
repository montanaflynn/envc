package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
