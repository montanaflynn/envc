# envc

**env config** — config *and* secrets in one reviewable file per environment, committed to git and synced to `.env`, GitHub Actions, Vercel, Convex, and anywhere else you deploy.

One YAML file per environment. Public values stay plaintext so a PR can review them; secret values are encrypted in place to SSH keys you already have — your GitHub keys for humans, a dedicated key for CI. Git is the source of truth; every host is a destination.

```bash
envc set local DATABASE_URL=postgres://localhost/app --secret
envc run local -- bun dev

envc set production STRIPE_SECRET_KEY=sk_live_… --secret
envc diff production
envc sync production
```

## Why

The default config and secret management for a new startup is passing credentials over Slack and pasting them into web UIs.

You paste a Stripe key into Vercel as “sensitive.” Six months later nobody can read it back. Convex needs the same key. GitHub Actions needs it too. Someone DMs a `.env`. **The intern’s laptop is now the source of truth.** Rotation means hunting three UIs and missing preview.

| You need | Command |
|---|---|
| Read a prod value again | `envc get production KEY` |
| Change it once, push everywhere | `envc set` + `envc sync` |
| See if a dashboard drifted | `envc diff` |
| Review public config in a PR | `secret: false` stays plaintext |
| Run the app with the right env | `envc run local -- bun dev` — no `.env` needed |
| Stop DMing `.env` files | `envc sync` writes `.env` if you ask; you own `.env.local` |
| Offboard someone | `envc deny` — re-encrypts, one git diff |

Built for teams on GitHub that already use SSH keys and ship to Vercel plus other env-var hosts. Not a web UI, not contractor-for-48-hours invites without git, not automatic Stripe key issuance — use Doppler or Infisical for those.

---

## Install

```bash
go install github.com/montanaflynn/envc/cmd/envc@latest
envc version
```

One static binary. No `sops`, `age`, `gh`, or `vercel` CLI required at runtime.

---

## Quick start

```bash
envc init                          # .envc.yaml, .gitignore entries

envc principal add alice --github alice
envc principal add deploy --ssh-key deploy.pub
envc group add engineers alice

envc env add local
envc set base APP_NAME=my-app --public   # every environment gets this
envc allow local engineers
envc set local DATABASE_URL=postgres://localhost/app --secret
envc set local LOG_LEVEL=debug --public
envc run local -- bun dev

envc env add production --github production --vercel production --vercel-project my-app
envc allow production engineers deploy
envc set production DATABASE_URL=postgres://prod/app --secret
envc set production LOG_LEVEL=warn --public

envc sync production               # → GitHub Environment + Vercel; records it in .envc/state/production/sync.yaml
envc diff production
git add -A && git commit -m 'production config'
```

Every command that reads an environment takes it as the first argument.

Same thing works as YAML: write `.envc.yaml` and `.envc/environments/*.yaml` by hand, then `envc ensure`.

---

## Destinations

A destination is anything `envc sync` writes the resolved values to. Destinations never win over the file.

| Name | Writes | Auth |
|---|---|---|
| **dotenv** | `.env` (generated). `.env.local` is a hand override; envc never writes it | filesystem |
| **github** | GitHub Actions Environment variables (`secret: false`) and secrets (`secret: true`) | `GH_TOKEN` / `GITHUB_TOKEN` — a PAT with Environment write, see [GitHub Actions](#github-actions) |
| **vercel** | Project env vars, for a standard target (`production` \| `preview` \| `development`) or a [custom environment](https://vercel.com/docs/deployments/environments) named by its slug; `sensitive` from `secret:` | `VERCEL_TOKEN` |
| **convex** | One deployment's env vars — a named deployment in a multi-deployment project, or the deployment of a project-per-environment setup | `CONVEX_DEPLOY_KEY`, or the env var named by `key_env` so each environment can hold its own key |

GitHub and Vercel will not return secret values. `diff` uses the [sync record](#envcstateenvsyncyaml) for those keys. Convex returns every value, so `diff` compares live values directly and `sync` keeps no record for it.

---

## Compared to SOPS, dotenvx, Doppler, and Infisical

| | SOPS | dotenvx | Doppler | Infisical | envc |
|---|---|---|---|---|---|
| Source of truth | encrypted file in git | encrypted `.env` in git | their cloud | their cloud or your cluster | file in git |
| Read a value later | `sops -d` | `dotenvx get` | their app | their app | `envc get` |
| Public + secret in one reviewable file | awkward | all-or-nothing per file | kv map | kv map | `secret: true\|false` |
| Who can decrypt, per environment | recipients per file | one key per file | roles | roles | `access:` + groups |
| Sync to Vercel / GitHub Actions | you build it | no | yes | yes | yes |
| Sync to Convex / other hosts | you build it | no | if they ship it | if they ship it | Convex built in; others via the [contributor interface](#adding-a-destination) |
| Drift detection against the host | no | no | no | no | `envc diff` |
| Auto-rotate Stripe / OpenAI | no | no | limited rotators | limited rotators | no |
| Human identity | age / PGP / KMS | generated keypair | email + SSO | email + SSO | GitHub / SSH keys |
| Vendor in the middle sees plaintext | no | no | yes | cloud: yes | no |
| Per-seat cost | no | no | yes | cloud: yes | no |
| `git show v1.4` | yes | yes | export | export | yes |

SOPS encrypts files and stops there — teams still paste into Vercel. dotenvx encrypts `.env` files but has one key per file and nothing after that. Doppler and Infisical already solve sync and “I can read it again”; they are a second store with seats and a dashboard. envc is that job with the store in git and identities you already have.

---

## How a repo looks

```text
.envc.yaml                        # principals, groups, destinations — you edit this
.envc/
  base.yaml                       # entries every environment inherits — you edit this
  environments/
    local.yaml                    # access + config — you edit these
    preview.yaml
    production.yaml
  state/
    base/
      envelope.yaml               # never delete — holds the data key
    local/
      envelope.yaml
    production/
      envelope.yaml
      sync.yaml                   # safe to delete — the next sync rewrites it
.env                              # only if dotenv is configured; gitignored
.env.local                        # your overrides; gitignored
.env.local.example                # generated from the manifest; commit it
.env.production.example           # one per environment
```

Run envc from anywhere inside the repo — it finds `.envc.yaml` by walking up from your current directory, the way git finds `.git`.

Same shape as Yarn's `.yarnrc.yml` + `.yarn/`: the one file you edit sits at the root, tool-owned files live under `.envc/`.

`.envc.yaml` and `.envc/environments/*.yaml` are the source of truth and the only files you edit. Everything under `.envc/state/` is generated and committed: `envelope.yaml` is the environment’s wrapped data key (an environment with secrets cannot be read without it), `sync.yaml` is what was last pushed to each destination (lose it and the next `sync` re-records everything).

**Environment** — `local`, `preview`, `production`. One file each.  
**Destination** — dotenv, GitHub Environment, Vercel, Convex, …  
**Principal** — a name with one or more public keys. envc does not care whether a person, a CI job, or an agent holds the private key.  
**Group** — named set of principals.  
**Access** — who may decrypt that file. Access is read *and* write: adding or changing a secret requires unwrapping the file’s data key, so you cannot set a secret in an environment you cannot read. The one exception is the very first secret in an environment — there is no envelope to unwrap yet, so anyone who can push can create it (encrypted to the listed access, which may not include them).

GitHub Actions *runners* are not environments. GitHub’s Environment feature is a destination (and a lock on the job). Process `environ` is what `envc run` builds.

---

## Tutorial: Next.js on Vercel + GitHub Actions

```bash
envc init

envc principal add alice --github alice
envc principal add bob   --github bob
ssh-keygen -t ed25519 -f deploy -N '' -C envc-deploy
envc principal add deploy --ssh-key deploy.pub
# put the private key on GitHub Environments as ENVC_PRIVATE_KEY — do not commit it

envc group add engineers alice bob
envc group add leads bob

envc env add local
envc env add preview    --github preview    --vercel preview    --vercel-project my-app
envc env add production --github production --vercel production --vercel-project my-app

envc allow local      engineers
envc allow preview    engineers deploy
envc allow production leads deploy

envc set local NEXT_PUBLIC_APP_URL=http://localhost:3000 --public --description 'Public site URL'
envc set local LOG_LEVEL=debug --public --enum debug,info,warn,error
envc set local DATABASE_URL=postgres://postgres:postgres@localhost:5432/app --secret

envc set production NEXT_PUBLIC_APP_URL=https://my-app.vercel.app --public
envc set production LOG_LEVEL=warn --public --enum debug,info,warn,error
envc set production DATABASE_URL=postgres://prod/app --secret
```

Local:

```bash
envc run local -- bun dev
# echo LOG_LEVEL=trace >> .env.local    # optional personal override; run picks it up
```

If a tool needs a real `.env` file:

```bash
envc env add local --dotenv .env --override .env.local   # adds the dotenv destination to local
envc sync local           # writes .env
envc diff local           # yaml vs .env; ignores .env.local
```

Ship (bob, who is in `leads`):

```bash
envc ensure
envc sync preview
envc sync production
git add .envc && git commit -m 'sync production'
```

Optionally, add a CI workflow that runs `envc ensure --dry-run` on pull requests and `envc diff` on `main`, so drift shows up as a red check — [GitHub Actions](#github-actions) has a copy-paste example.

---

## File reference

### `.envc.yaml`

Never encrypted. Commit it.

```yaml
principals:
  alice:
    github: alice                 # discovery only; keys below are pinned
    keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaa… alice@mac
      - ssh-rsa AAAAB3NzaC1yc2E… alice@old-laptop
  deploy:
    keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdd… envc-deploy
    # age: age1deploy…            # optional extra recipient

groups:
  engineers: [alice]
  leads: [alice]

sync:
  local:
    dotenv:
      path: .env
      override: .env.local
  preview:
    github:
      environment: preview        # default: env name
      # repository: owner/repo    # default: git remote origin
    vercel:
      environment: preview        # production | preview | development, or a custom environment slug
      project: my-app             # default: .vercel/project.json
      # team: team_…
  production:
    github: { environment: production }
    vercel: { environment: production, project: my-app }
    convex:
      deployment: quiet-lion-123  # deployment name; url: overrides for self-hosted
      # key_env: CONVEX_DEPLOY_KEY_PROD   # default: CONVEX_DEPLOY_KEY
```

| Field | Meaning |
|---|---|
| `principals.<name>.github` | GitHub user for `principal add --github` / `principal sync`. Not used at encrypt time. |
| `principals.<name>.keys` | Pinned OpenSSH public keys (`ssh-ed25519`, `ssh-rsa`). Any one key can decrypt. |
| `principals.<name>.age` | Optional `age1…` recipient. |
| `groups.<name>` | List of principal names only. No nesting. A name is a principal **or** a group, never both. |
| `sync.<env>` | Destinations for that environment. Omitted ⇒ `sync` / `diff` error for that env. |

Unknown keys under `sync.<env>` fail `ensure` unless a destination with that name is registered.

### `.envc/base.yaml`

Values every environment shares — the app name, a Sentry DSN, a third-party key that has no per-environment variant — live once, here, instead of in every manifest. The file has the manifest schema minus `access`:

```yaml
config:
  APP_NAME:
    secret: false
    value: my-app
  SENTRY_DSN:
    secret: true
    value: ENC[envc1,…]
```

`envc set base KEY=… --public|--secret` creates it; `unset`, `get`, `ls`, `show`, `ensure`, and `who` take `base` too. It is not an environment: `run`, `export`, `sync`, `diff`, `allow`, and `deny` refuse it, and no environment may be named `base`.

**Resolution.** An environment's resolved values are base's entries with the environment's own layered on top, per key: `envc set production APP_NAME=… ` overrides base for production only (`set` says so), `envc unset production APP_NAME` goes back to inheriting (`unset` says so), and a key an environment only inherits cannot be unset there. `get`, `export`, `run`, `sync`, `diff`, and `.env.<env>.example` all see the merged view; `ls` shows where each key comes from; `show` prints one file.

**Access.** Base has no `access:` because it is derived: **a secret in base is readable by everyone who can read any environment that inherits it.** The base envelope is wrapped to the union of every inheriting environment's principals, and every command that changes an environment's access (`allow`, `deny`, `env rm`, `principal rm`, `group` edits, `ensure`) brings base along — additions update its readers, removals re-key it. `who base` prints the union; `envc ensure` recomputes it after a hand edit, and `envc ensure --dry-run` reports when the envelope and the union disagree. If the intern should not see the Sentry DSN, it does not belong in base — put it in each environment that needs it.

**Opting out.** An environment that should not inherit base says so in its manifest:

```yaml
access: [deploy]
base: false
config:
  RELEASE_TOKEN: { secret: true, value: ENC[envc1,…] }
```

Typical case: a `ci` environment for a GitHub Actions job with a small, unrelated set of variables. With `base: false` the environment resolves only its own entries, its template has no inherited lines, and its principals do not join the base union — `deploy` above cannot read base. Flip the field by editing the YAML and running `envc ensure ci`; base is re-derived. Base has no sync record: an environment's record covers the inherited values, so a base change shows up as `changed in file` on every inheriting environment until it is synced.

**What you see.** Nothing about base is silent. Every command that changes access reports what it did to base and who that affects, one effect per line:

```text
$ envc allow production carol
allow carol on production
  updated production readers: carol now reads production secrets
  updated base readers: carol now reads base secrets

$ envc deny production carol
deny carol on production
  re-keyed production: carol no longer reads production secrets
  re-keyed base: carol no longer reads base secrets

$ envc ensure production            # after a hand-edited access list
ensure production
  updated production readers: carol now reads production secrets
  updated base readers: carol now reads base secrets

$ envc env rm production --force
remove environment production
  re-keyed base: bob no longer reads base secrets

$ envc who production
access: leads, carol
principals:
  alice
  carol
inherits base: these principals also decrypt base secrets
```

`--dry-run` prints the same lines prefixed with `would`. If base's envelope ever falls behind an environment's access — a hand edit, an interrupted ensure — a reader of that environment does not get a wall of fingerprints:

```text
envc: cannot decrypt .envc/base.yaml: production inherits base, but base's envelope is behind production's access; run envc ensure base (or ask someone who can read base)
```

### `.envc/environments/<env>.yaml`

```yaml
access: [leads, deploy]

config:
  NEXT_PUBLIC_APP_URL:
    description: Public site URL
    secret: false
    value: https://my-app.vercel.app

  LOG_LEVEL:
    description: Server log verbosity
    secret: false
    value: warn
    enum: [debug, info, warn, error]

  DATABASE_URL:
    description: Postgres connection string
    secret: true
    value: ENC[envc1,…]
    pattern: 'postgres(ql)?://.*'
```

Only top-level keys: `access`, `config`, and the optional `base` (see [`.envc/base.yaml`](#envcbaseyaml)). Everything in this file is yours to edit; the only machine-written bytes are the `ENC[…]` ciphertexts, and those are the value. The key that unlocks them lives in [`.envc/state/<env>/envelope.yaml`](#envcstateenvenvelopeyaml).

`access` is principal and group names. Empty `access` is allowed only if there are no `secret: true` entries.

`base: false` opts the environment out of the base layer; absent or `true` inherits it. Any other value is a schema error.

`config.KEY` is the export name. Must match `^[A-Za-z_][A-Za-z0-9_]*$`. Export does not rename.

| Field | Required | Meaning |
|---|---|---|
| `value` | yes | String, may be multiline. Secrets become `ENC[envc1,…]`. |
| `secret` | yes | Encrypt this value. Always written explicitly. |
| `description` | no | Shown by `envc ls`. |
| `enum` | no | Allowed strings; checked after decrypt. |
| `pattern` | no | Go regexp matched against the whole value — anchors are implied, so a prefix match needs a trailing `.*` (`postgres(ql)?://.*`). |
| `required` | no | Default `true`. |
| `kind` | no | `env` (default). `file` is reserved and rejected in v1. |

Top-level `base` (not under `config`): `false` to opt out of the base layer; default `true`.

### `.env.<env>.example`

Generated from the manifest, one per environment, at the repo root. Every command that writes the manifest (`set`, `unset`, `env add`, `allow`, `deny`, `ensure`) and `sync` regenerate it; reads never touch it; `envc ensure` regenerates it when it is missing or stale, and `ensure --dry-run` reports that. Commit it. Never edit it.

```bash
# .env template for production, written by envc. Secrets are blank; do not edit — it is regenerated from .envc/environments/production.yaml.
# Copy any line into .env.local to override it for `envc run`.

# Postgres connection string
# secret
# pattern: postgres(ql)?://.*
DATABASE_URL=

# Server log verbosity
# enum: debug, info, warn, error
LOG_LEVEL=warn
```

Metadata becomes comments (`description`, `secret`, `optional`, `enum`, `pattern`, and `from base` for inherited entries); public values are filled in `.env` quoting; secrets are blank. It is the onboarding file for people and tools that expect one, and the menu of lines to copy into `.env.local`.

### `.envc/state/<env>/envelope.yaml`

Written by envc the first time an environment gets a secret, and rewritten by `allow`, `deny`, and `ensure`. Removed when the last secret goes.

```yaml
# Written by envc. Commit it. Never edit or delete: it holds the data key that
# unlocks the ENC[…] values in environments/production.yaml.
version: 1
recipients:                       # access → principals → keys, resolved and pinned
  - SHA256:…                      # ssh key fingerprint, or age1… recipient
  - SHA256:…
key: BASE64…                      # data key, age-encrypted to every recipient
mac: BASE64…
```

**Never delete it.** It is not regenerable: the data key inside is the only thing that opens the `ENC[…]` values in the manifest. If it is missing, every command that needs a secret exits 2 with the fix:

```text
.envc/state/production/envelope.yaml is missing; it holds the data key — restore it: git checkout -- .envc/state/production/envelope.yaml
```

envc never creates an empty envelope in that situation. A merge conflict in this file resolves by keeping either side and running `envc ensure` — both sides wrap the same data key unless one of them was re-keyed (a `deny`), in which case take that side whole.

`ensure --dry-run` verifies manifest against envelope the way `npm ci` verifies a lockfile: `recipients` must match the resolved `access`, and with a key the MAC must verify. `ensure` brings them in line.

### Encryption

Age (`filippo.io/age` + `agessh`) is the engine. Humans use SSH keys. CI uses an extra SSH key or an age identity. Nobody has to run `age-keygen`.

Per file:

1. Random 32-byte `data_key`. Three 32-byte subkeys are derived with HKDF-SHA256 (salt empty, info `envc/v1/enc`, `envc/v1/mac`, `envc/v1/sync`): `enc` (values), `mac` (envelope MAC), `sync` (sync records). The `key_id` in sync records is the first 8 hex characters of SHA-256(`data_key`).
2. `data_key` is age-encrypted once to every unique public key on the resolved `access` list (SSH via `agessh`, plus optional `age1…`). Stored as `key` in the envelope, standard base64. The envelope’s `recipients` lists recipient IDs — `SHA256:` OpenSSH fingerprints (no padding) for SSH keys, the `age1…` string itself for age — so `ensure --dry-run` can compare against `access` without a private key.
3. Each `secret: true` value: AES-256-GCM with the `enc` subkey, 12-byte random nonce, AAD = the config key name as UTF-8. Token: `ENC[envc1,` + base64(nonce ‖ ciphertext ‖ tag) + `]`.
4. The envelope’s `mac` = HMAC-SHA256(`mac` subkey, canonical secret payload), standard base64. Payload, keys sorted:

   ```text
   KEY \0 decrypted-value \n
   ```

5. Sync records: the first 16 hex characters of HMAC-SHA256(`sync` subkey, `KEY \0 value`). A public-only environment has no `data_key`, so its records use the all-zero key — deterministic, and there is nothing to protect.

MAC is verified after decrypt, before any command returns secret material. Public fields are not in the MAC, so you can change `LOG_LEVEL` without a private key.

Two operations change the envelope; every command picks the right one and says which it did:

- **Update readers** — same `data_key`, re-wrapped to the current recipient list. Ciphertext tokens unchanged. What `allow` does, and what `ensure` does after a reader was added by hand. Cheap.
- **Re-key** — new `data_key`, every secret re-encrypted, new MAC. What `deny`, `principal rm`, `group rm-member`, a `principal sync` that drops a key, and `ensure` after a reader was removed by hand do — always, because anyone who could unwrap the old `data_key` from an earlier commit could otherwise keep reading *new* secrets added under it. Anyone who already decrypted a value still has that value; a re-key does not rotate the Stripe key itself. The sync record is carried across to the new key, so a re-key with no value changes leaves `diff` clean.

**Which private keys work.** Decrypting to an SSH key needs the private key material itself, so envc — like SOPS and age — reads the private key *file*. It cannot use `ssh-agent`, 1Password’s agent, FIDO (`sk-ssh-ed25519`) keys, or PIV/GPG-backed YubiKey keys; those only sign and never expose the key. Passphrase-protected `id_ed25519` / `id_rsa` files are fine: envc prompts once per key per invocation on a TTY (the answer is memoized for that run), never stores the passphrase, and never prompts in CI.

Identity search order: `ENVC_PRIVATE_KEY` (key contents) → `ENVC_PRIVATE_KEY_FILE` (path) → `~/.ssh/id_ed25519` → `~/.ssh/id_rsa`. The two variables take either an SSH private key or an age secret key; the format is detected from the contents. Only keys whose fingerprint appears in the envelope’s `recipients` are tried, so you are not asked for a passphrase on a key that cannot open the file. No usable key: exit 2.

`https://github.com/<user>.keys` is **not** live at encrypt time. `principal add --github` / `principal sync` fetch, you pin, encrypt uses the pins.

### Resolved values

The resolved values of an environment are what `export` prints, `run` injects, and `sync` pushes: the entries of [`.envc/base.yaml`](#envcbaseyaml) (unless the manifest says `base: false`) overridden per key by the environment's own, each `config.KEY` with `kind` omitted or `env` → `KEY=value`, secrets decrypted. `secret` does not change the name.

`.env` encoding: unquoted if `^[A-Za-z0-9_./:@+-]+$`, otherwise double-quoted with `\n \r \t \\ \"`.

### `envc run`

`envc run ENV -- cmd` builds the child’s environment with the same precedence as dotenv, Next.js, and Bun — the real environment always wins over files:

1. The existing process environment (highest)
2. `.env.local` — the `dotenv.override` path if configured for this environment, otherwise `./.env.local` if it exists
3. The resolved values of the chosen environment (lowest)

So `DATABASE_URL=… envc run local -- bun dev` does what you expect, and a line in `.env.local` beats the file without editing YAML. `--pure` skips step 2. None of this needs a `.env` file; add the dotenv destination only when a tool insists on reading one itself. `.env.local.example` is the menu of lines you can copy into `.env.local`.

### `.envc/state/<env>/sync.yaml`

After a successful sync to a destination that cannot read values back (github, vercel), envc records what it pushed:

```yaml
# Written by envc sync. Commit it. Safe to delete; the next sync recreates it.
github:
  at: 2026-08-29T23:00:00Z
  key_id: 9b1f2e07                # the data_key these were computed under
  keys:
    DATABASE_URL: 7c11a0b3e9f04d21  # first 16 hex of HMAC-SHA256(sync subkey, KEY \0 value)
    LOG_LEVEL: 0d4a9e21c7b3f815
vercel:
  …
```

They are HMACs, not plain hashes: a committed SHA-256 of `ADMIN_PASSWORD=hunter2` is an offline dictionary attack, an HMAC keyed by something only readers hold is not. Sixteen hex characters (64 bits) is plenty to notice a changed value and short enough to read in a diff. Commit it in the same commit as the config change — a PR that changes a value without touching its sync hash is visibly unsynced, and `ensure --dry-run` says so on any machine with a key. Deleting the file is harmless: `diff` treats every key as never synced until the next `sync`.

`diff` is file vs destination. Per destination, per key in the resolved values:

| sync record | live | result |
|---|---|---|
| missing | — | `never synced` (drift) |
| `key_id` ≠ current | — | `stale sync record (re-keyed elsewhere)` (drift) |
| hmac ≠ current | — | `changed in file` (drift) |
| = | readable, ≠ value | `changed at destination` (drift) |
| = | hidden | `ok (unverifiable)` |
| = | missing at destination | `missing at destination` (drift) |
| = | = | `ok` |

Keys that exist at the destination but not in the resolved values are listed as **extra** — never deleted without `--prune`, never drift; Vercel integrations and hand-added variables are normal. Destinations that can read secrets back (dotenv, convex) are compared directly against the live values, ignoring the record. GitHub declares case-insensitive names, so `diff` folds case for it. Resolved values include inherited base entries, so a base change is `changed in file` on every inheriting environment until it is synced. A record made under another `data_key` (a re-key on a different branch) is refreshed by one `sync` with no destination writes.

One-way: file wins. Never pull destination values into YAML.

---

## CLI reference

Global flags apply to every command:

```text
Usage: envc [global flags] <command> [flags] [args]

      --dry-run         print what would happen
      --json            machine-readable output where noted
  -h, --help
```

Commands work from any directory inside the repo: envc finds `.envc.yaml` by walking up from where you run it, like git. Without one it exits 3: `no .envc.yaml in this directory or any parent; run envc init at the repo root`. Relative paths you type (`--file`, `--ssh-key`) resolve against your current directory; paths stored in `.envc.yaml` (dotenv `path:`/`override:`) are relative to the repo root; `envc run` starts the command in the directory you ran it from.

Commands that read an environment take it as the first argument: `envc set production KEY=… --secret`, `envc get production STRIPE_SECRET_KEY`. The shared layer is addressed as `base` where a manifest is meant (`set`, `unset`, `get`, `ls`, `show`, `ensure`, `who`); `run`, `export`, `sync`, `diff`, `allow`, and `deny` refuse it. After editing files by hand, `envc ensure` makes the generated state match them; `envc ensure --dry-run` only reports.

Values go to stdout. Everything else — progress, warnings, prompts — goes to stderr. A mutation reports the action on one line and each effect indented under it (`updated production readers: carol now reads production secrets`, `re-keyed base: carol no longer reads base secrets`, `production now inherits APP_NAME from base`); `--dry-run` prefixes every line with `would`. Exit codes: `0` ok · `1` drift or problems remain · `2` cannot decrypt · `3` usage / schema.

```text
COMMANDS
  init              create .envc.yaml and gitignore entries
  version           print version

  env               add, list, remove environments
  principal         add, list, remove, sync keys
  group             create and edit groups

  allow             grant decrypt access
  deny              revoke decrypt access; re-keys
  who               show who can decrypt

  set               create or update a config entry
  unset             delete a config entry
  get               print one value
  ls                list keys
  show              print the environment file (secrets redacted)

  export            KEY=value on stdout
  run               exec a process with the resolved values
  sync              push the resolved values to destinations
  diff              compare file to destinations

  ensure            make the generated state match the files; --dry-run only reports
```

### `envc init`

```text
Usage: envc init

Creates .envc.yaml (principals: {}) and .gitignore entries for .env,
.env.local, *.agekey. No environments yet; run envc env add NAME.
```

### `envc env`

```text
Usage: envc env add NAME [destination flags]
       envc env ls
       envc env rm NAME [--force]

  --dotenv PATH
  --override PATH
  --github NAME                 GitHub Environment name
  --vercel ENVIRONMENT          production|preview|development, or a custom
                                environment slug (resolved at sync time)
  --vercel-project NAME
  --convex NAME                 Convex deployment name

add  writes .envc/environments/NAME.yaml (access: [], config: {}) if missing and
     merges destination flags into sync.NAME. Running add on an existing
     environment only adds destinations. add pins what it discovers so
     ensure and CI never depend on local state: --vercel records project:
     (and team:) from --vercel-project or .vercel/project.json, --github
     records repository: from git remote origin.
rm   deletes the manifest, .envc/state/NAME/, .env.NAME.example, and sync.NAME.
     Refuses if the file has secrets unless --force.
```

### `envc principal`

```text
Usage: envc principal add NAME --github USER
       envc principal add NAME --ssh-key FILE|-
       envc principal add NAME --age age1…
       envc principal ls
       envc principal show NAME
       envc principal rm NAME
       envc principal sync NAME
       envc principal sync --all

  --github USER     fetch https://github.com/USER.keys
  --ssh-key FILE    public key file, or - for stdin
  --age RECIPIENT
  --all-keys        pin every fetched key (default: interactive / TTY)
  --ed25519-only    skip ssh-rsa when fetching

add --github lists keys and pins the selection into .envc.yaml.
sync refetches GitHub keys, shows +/-, applies pins. Added keys update
the readers; removed keys re-key the environments that include this
principal, so the old key is locked out. rm also drops the name from
groups and access, then re-keys.
```

### `envc group`

```text
Usage: envc group add NAME PRINCIPAL [PRINCIPAL…]
       envc group ls
       envc group show NAME
       envc group rm NAME
       envc group add-member NAME PRINCIPAL
       envc group rm-member NAME PRINCIPAL

Members must be principals. add-member updates the readers of, and
rm-member re-keys, the environments that list this group on access.
```

### `envc allow` / `deny` / `who`

```text
Usage: envc allow ENV NAME [NAME…]
       envc deny  ENV NAME [NAME…]
       envc who   ENV [--keys]

NAME is a principal or group. allow edits access: and updates the readers.
deny edits access: and re-keys. Both bring base along (its access is the union of
every inheriting environment's) and say so: one line per effect, naming who
gained or lost base secrets. who prints groups as listed, then expanded
principals, and notes when they also decrypt base secrets; who base prints
the derived union. --keys adds fingerprints.
```

### `envc set` / `unset` / `get` / `ls` / `show`

```text
Usage: envc set   ENV KEY=VALUE  (--secret | --public) [flags]
       envc set   ENV KEY --stdin (--secret | --public) [flags]
       envc set   ENV KEY --file PATH (--secret | --public) [flags]
       envc set   ENV KEY --description TEXT --enum a,b --pattern RE
       envc unset ENV KEY
       envc get   ENV KEY
       envc ls    ENV
       envc show  ENV [--secrets]

  --secret / --public   required when creating a key; an update keeps the
                        existing setting unless one is given
  --stdin               value from stdin, trailing newline stripped
  --file PATH           value from file (PEM etc.), verbatim
  --description TEXT
  --enum a,b,c
  --pattern REGEXP

set KEY with no value and only metadata flags patches metadata.
Flipping --public on a secret, or --secret on a public value, prints a
warning to stderr (treat the old value as compromised either way).

ENV may be base for all five. set on a key the environment inherits creates
an override (stderr: "overrides base"); unset on an override restores
inheritance (stderr says so); unset on a key only inherited from base is
a usage error pointing at `envc unset base KEY`.
get prints the value and a newline to stdout, TTY or not; a key the
   environment inherits is read from base.
   `psql "$(envc get production DATABASE_URL)"` is the point.
ls shows KEY, secret|public, origin (base or the environment), description;
   --json adds "origin".
show redacts secret values unless --secrets; it prints one file, no merge.
```

### `envc export` / `run` / `sync` / `diff`

```text
Usage: envc export  ENV
       envc run     ENV [--pure] -- COMMAND [ARGS…]
       envc sync    ENV [--only NAME] [--prune] [--dry-run]
       envc diff    ENV [--only NAME]

export    KEY=value on stdout, .env encoding, secrets in the clear.
run       process env > .env.local > resolved values, then exec.
          --pure skips .env.local.
sync      decrypt, resolve, Apply each destination for this env, record
          what was pushed in .envc/state/<env>/sync.yaml (github, vercel;
          dotenv and convex read values back and need no record).
          --only NAME limits to one registered destination.
          --prune deletes destination keys not in the resolved values
          (off by default).
diff      file vs destinations, never env vs env.
          Exit 1 if a key is changed or missing; extras are listed only.
```

### `envc ensure`

```text
Usage: envc ensure [ENV]
       envc ensure [ENV] --dry-run

ensure validates the files, fixes what it can, and reports the rest.
Run it after editing YAML by hand. Without ENV every environment and base
are ensured; ENV may be base.

Validated (reported, never changed):
  - schema of .envc.yaml, .envc/environments/*.yaml, .envc/base.yaml,
    .envc/state/*/envelope.yaml; key names, unknown fields
  - every access name exists; groups contain only principals
  - an environment with ENC[envc1,…] values has its envelope
  - sync.<env> names only registered destinations
  - with a key: MAC, enum, and pattern of secret values; values changed
    since the last recorded sync; a configured .env that is missing or
    stale (warnings; run envc sync)

Fixed (each reported as an effect line):
  - a MAC broken by a hand edit (a deleted secret, say) is recomputed,
    as long as every remaining secret still decrypts
  - hand-written plaintext secrets are encrypted
  - the envelope's readers are brought in line with access; a reader that
    was removed by hand gets a new data key (re-key)
  - base's envelope is brought in line with the union of every inheriting
    environment's access
  - a missing or stale .env.<env>.example is regenerated

A target with an unfixable error is left untouched and says what it is
waiting on: "not fixed: resolve the problem(s) above, then run envc ensure
ENV again to …". --dry-run writes
nothing: fixes are printed as "would …" and count as pending.
Exit 0 consistent · 1 problems remain or pending · 2 a fix needs a key
that cannot open the file · 3 usage.
```

```text
$ envc ensure --dry-run
ensure production
  would encrypt 1 plaintext secret: STRIPE_KEY
  would regenerate .env.production.example
envc: ensure: 2 pending

$ envc ensure
ensure production
  encrypted 1 plaintext secret: STRIPE_KEY
  regenerated .env.production.example
```

---

## GitHub Actions

Optional. envc has no CI integration built in — if you want checks, this hand-maintained workflow is all it takes. Copy it to `.github/workflows/envc.yml` and adjust the environments to yours:

```yaml
name: envc
on:
  pull_request:
    paths: [.envc.yaml, .envc/**]
  push:
    branches: [main]
    paths: [.envc.yaml, .envc/**]

jobs:
  ensure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: envc ensure --dry-run

  diff-production:
    if: github.ref == 'refs/heads/main'
    needs: ensure
    runs-on: ubuntu-latest
    environment: production
    env:
      ENVC_PRIVATE_KEY: ${{ secrets.ENVC_PRIVATE_KEY }}
      GH_TOKEN: ${{ secrets.ENVC_GH_TOKEN }}
      VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
    steps:
      - uses: actions/checkout@v4
      - run: envc diff production
```

The example installs envc with `go install`. `envc ensure --dry-run` needs no key for most rules. `envc diff` needs the deploy principal's private key — store it as the `ENVC_PRIVATE_KEY` secret on the GitHub Environment — plus the destination tokens.

Nothing in CI writes. `sync` runs on a laptop; the **github destination** is just another host it pushes to, over the GitHub API, using a personal access token (or GitHub App token) with permission to manage Environment variables and secrets — put it in `GH_TOKEN` or `GITHUB_TOKEN` where you run `sync`. The `GITHUB_TOKEN` that GitHub Actions hands a job cannot manage secrets, which is one more reason the workflow only reads. `diff` in CI needs a read-capable token to list variables and secret *names*; `ensure --dry-run` needs nothing.

---

## Security

In scope: secret values in git are ciphertext; only listed recipients can unwrap; MAC detects silent edits to secret leaves; public config is reviewable without decrypt; sync records do not leak values.

Assume: a lost laptop with a private key file and a weak passphrase can decrypt whatever that principal can; dashboard edits of secret values are not visible to `diff` (only the names are); a leaked `ENVC_PRIVATE_KEY` is as bad as a leaked Doppler service token.

Passphrases are typed at a TTY, never stored. GitHub key lists are pinned, not live. The deploy key is unencrypted and lives only on the GitHub Environment that runs `diff`.

---

## Architecture

The README is the spec. When README and code disagree, the README wins — fix the code.

```text
cmd/envc/                 entrypoint → cli.Main
internal/cli/             cobra commands: parse flags, call app, print. No business logic.
internal/app/             orchestration: load roster + manifests, resolve the base layer, derive access,
                          unwrap, decrypt, set/unset, ensure, sync, diff, run-env, the .env.<env>.example
                          templates. Owns exit codes.
internal/roster/          .envc.yaml — principals, groups, sync config
internal/envfile/         .envc/environments/<env>.yaml (the manifest) and .envc/base.yaml
internal/state/           .envc/state/<env>/envelope.yaml and sync.yaml
internal/crypto/          data key, HKDF subkeys, AES-GCM tokens, MAC, sync HMAC, age wrap/unwrap,
                          identity discovery (~/.ssh, env vars, passphrase prompt)
internal/sshkey/          OpenSSH public keys, fingerprints, github.com/<user>.keys
internal/resolve/         KEY=value encoding/decoding (.env format)
internal/destination/     Destination interface + registry; dotenv, github, vercel; all/ blank-imports
                          every built-in; internal/httpx is the shared HTTP client (timeout, retry)
scripts/e2e.sh            end-to-end test against the built binary (make e2e)
```

Dependency direction, no cycles:

```text
cli → app → {roster, envfile, state, crypto, sshkey, resolve, destination/*}
envfile → state        the in-memory manifest carries its envelope; it is never written to the manifest
crypto → sshkey
destination/* → resolve   (dotenv only)
```

`roster`, `state`, `resolve`, `sshkey` import nothing else from this module.

### Process

- Every package has table-driven `_test.go` files that test the contract, not private helpers. `go test -race ./...`, `go vet ./...`, and `gofmt -l .` must be clean; `make e2e` must print `ALL PASSED`.
- No new dependencies without discussion. Approved: `filippo.io/age`, `golang.org/x/crypto`, `golang.org/x/term`, `gopkg.in/yaml.v3`, `github.com/spf13/cobra`.
- Errors wrap with `%w` and name the file or key. No `panic` outside `init()`.
- No globals other than the destination registry; anything that touches the environment or filesystem takes it as a parameter so tests can inject.
- `context.Context` on anything that does network I/O.

### Output

- **Stdout is for values.** Only `get`, `export`, `show`, `ls`, `who`, the `ls`/`show` subcommands of `env`, `principal`, `group`, `version`, and `--json` output write to stdout. Progress, effect lines, warnings, and prompts go to stderr; passphrase prompts open `/dev/tty` when stdin is not a terminal.
- **Mutations report an action line plus one indented line per effect**: `allow carol on production` / `  updated production readers: carol now reads production secrets`. Under `--dry-run` every line is prefixed `would `. Vocabulary: *readers* (who can decrypt), *encrypted*, *updated readers*, *re-keyed*, *regenerated*. App records effects; cli prints them.
- Exit codes are listed under [CLI reference](#cli-reference) and owned by `app`.

### Files

- YAML output is canonical: map keys sorted, 2-space indent, multiline strings as literal blocks. Files are written atomically (temp file + rename), mode `0644`; `.env` is `0600`. Comments are not preserved on save.
- The envelope is written before the manifest, so an interrupted write cannot leave `ENC[…]` tokens without their key; the environment's template is refreshed afterwards.
- The repo root is the nearest ancestor of the cwd containing `.envc.yaml` (walk-up, like git; `Options.Root` overrides it in tests). Relative paths the user types resolve against their cwd; paths stored in `.envc.yaml` are root-relative; `run` execs in the caller's cwd; `init` acts on the cwd only and refuses inside an existing repo.
- `.env.<env>.example` is derived from the manifest: written by manifest saves and after `sync`, regenerated by `ensure`, deleted by `env rm`, never touched by reads (`get`, `run`, `export`, `diff`, `ensure --dry-run`). A base save refreshes every environment's template; base itself has none.

### Base layer

- Resolved, not copied: an environment's view is base entries overridden per key by its own, unless its manifest says `base: false`. Everything that consumes resolved values goes through that view — `export`, `run`, `sync`, `diff`, the template, `ensure`'s sync-record warning.
- `base` is a reserved name, accepted by the manifest commands and refused by the environment-only ones (see [CLI reference](#cli-reference)); one table in cli (`envArg`), one guard in app.
- Base access is derived: the union of resolved principals over every inheriting environment. The base file rejects an `access:` key.
- Every access change — `allow`, `deny`, `env rm`, `principal` and `group` edits, `ensure` — ends by resealing base: no-op when the envelope already matches, a readers update on additions, a re-key on removals. Under `--dry-run` the union is computed from the manifests the command staged in memory, so the report matches a real run.
- Base has no sync record; each environment's record covers inherited values under its own `data_key`.

### ensure

- `ensure` is the only command that writes without a specific edit. Per target — every environment then base, or one — it validates read-only first, skips fixes on a target with an unfixable error (reporting what is blocked), then encrypts plaintext secrets, updates readers or re-keys, reseals base, regenerates a stale template, and removes an envelope whose last secret is gone.
- `--dry-run` is the CI mode: nothing is written, the plan is reported as pending, pending counts toward exit 1. Reporting needs no key; secret-value checks (MAC, enum, pattern) run only when a key is available and never prompt.
- Removal always re-keys: `deny`, `principal rm`, `group rm-member`, a hand-removed reader found by `ensure`, and `principal sync` dropping a key all generate a new `data_key`. There is no flag to keep the old one.

### Adding a destination

`sync` and `diff` talk to vendors only through this interface. If adding a host requires touching encryption or `access:`, the interface is wrong.

```go
package destination

type Snapshot map[string]Entry

type Entry struct {
    Value  string
    Secret bool // Live may leave Value empty when the host hides it
}

type ApplyOptions struct {
    Prune, DryRun bool
}

type Report struct {
    Created, Updated, Unchanged, Pruned, Skipped []string
}

type Destination interface {
    Name() string // "vercel", "convex", …
    Live(ctx context.Context) (Snapshot, error)
    Apply(ctx context.Context, want Snapshot, opts ApplyOptions) (Report, error)
}
```

1. Put the implementation in `internal/destination/<name>/`.
2. Register the name so `sync.<env>.<name>` unmarshals into a typed config struct.
3. Map `secret: true` to the host’s sensitive flag. If it has none, still set the value; `Live` returns empty `Value` and `Secret: true` when the API hides it.
4. Core writes the sync record from `want` + `Name()` after a successful `Apply`.
5. Document the auth env var. Map the host's permission and plan failures
   to actionable messages: a 401/403 should say which env var was rejected and
   how to mint a working credential, and a plan-gated feature (Vercel custom
   environments, say) should name the gate — `sync` and `diff` print a
   destination's error verbatim, so the message is the whole UX.
6. Add a row to the table under [Destinations](#destinations).
7. `--only <name>` works if registration is by name.

Do not implement two-way sync. Do not decrypt in the destination package; it receives an already-resolved `Snapshot`. A CLI wrapper (`fly secrets set`, say) is fine until an HTTP API is worth it.

#### Candidates

Same interface. Weekend-sized if the host has an env-var API.

| Name | Mapping | Auth |
|---|---|---|
| **fly** | Fly app secrets | `FLY_API_TOKEN` |
| **render** | env groups | API token |
| **railway** | project environment | API token |
| **netlify** | site env | token |
| **cloudflare** | Workers / Pages secrets | API token |

---

## Design decisions

| Decision | Why |
|---|---|
| The environment is a required first positional; there is no default environment | A default makes `envc run -- bun dev` silently mean whatever `.envc.yaml` says. Naming it every time is one word and never wrong. |
| No sticky `envc use production` | Wrong env, silent. |
| `.envc.yaml` at the root, everything else under `.envc/` | Same shape as `.yarnrc.yml` + `.yarn/` and `.sops.yaml`: the one file you edit is visible, tool-owned files sit in one dotdir. |
| The envelope lives in `.envc/state/`, not in the manifest | The manifest stays fully hand-editable; the wrapped data key is not regenerable, so it sits apart with its own "never delete" header. Not a `-lock` file — lockfiles get deleted. |
| Sync state is overwritten, not appended | Git is the history; `diff` only needs the latest snapshot; append-only files conflict on every merge. |
| A `base` layer with derived access, `base: false` to opt out — not `extends:` | One layer covers the real need; base secrets are readable by whoever can read any inheriting environment, so its readers are computed, not configured. A CI environment with its own vars opts out. |
| One `ensure` verb instead of `check` / `rewrap` / `reencrypt` | Nobody should decide between wrapping and re-keying; the tool does the strong thing when a reader was removed. `--dry-run` is the read-only mode, so CI needs no second command. |
| `.env.<env>.example` is always generated, by writes, never by reads | Derived from the manifest like a lockfile; `run` and `get` must not dirty the tree. |
| `export`, not `flatten` | "Flatten" named the mechanism; `export` is what every comparable tool calls it. |
| Effect lines, not parentheticals | `(rewrap)` reads as an aside; "updated base readers: carol now reads base secrets" cannot be missed. |
| GitHub Environments are destinations, not identities | Wrong layer for a recipient type. |
| No AWS KMS for GitHub Actions | Nobody here has or wants that identity; a dedicated SSH key does the job. |
| Pinned `github.com/<user>.keys`, never live at encrypt time | Surprise keys, surprise revokes. |
| One-way sync; extras listed, never deleted without `--prune` | Dashboards must not become the source of truth. |
| envc’s own file format, not SOPS’s | SOPS cannot express “encrypt `value` when `secret: true`” plus metadata. Age is the engine. |
| No home-grown crypto | age + AES-GCM + HKDF. |
| No ssh-agent, YubiKey, or FIDO keys | They sign; they never expose the key. Same limitation as SOPS and age. |
| No "rotate" anywhere | It collides with rotating the real Stripe key. A re-key changes envc’s data key, nothing upstream. |
| `kind: file` / Kubernetes: reserved, not built | On the object for later. |
| `diff` is file vs destination, never local vs production | The other question is not the one that bites. |

Open on purpose: Go over TypeScript because it drops the `sops`/`gh` binaries; auto-rotation of third-party API keys is out of scope for everyone in this category.

---

## FAQ

**Do I have to run envc from the repo root?**  
No — it walks up to find `.envc.yaml`, like git, so every command works from any subdirectory and files still land at the root. `init` is the exception: it creates the root where you run it, and refuses inside an existing repo.

**Can I just edit the YAML?**  
Yes. CLI and YAML are two editors of the same files. After editing by hand, run `envc ensure`: it encrypts plaintext secrets, brings every envelope in line with `access`, repairs the MAC if you deleted a secret by hand, and regenerates the `.env.<env>.example` files — and `envc ensure --dry-run` tells you what it would do.

**Why not SOPS files?**  
The document is objects with `secret:`, descriptions, and `access:`. SOPS cannot express “encrypt `value` when `secret: true`.” Age is the engine; the file format is envc’s.

**Why not Doppler?**  
If you want a dashboard, seats, and fifty integrations you will not write, use Doppler. If the repo must be the store and GitHub keys must be identity, use envc.

**Why can’t it use my ssh-agent?**  
Agents sign; they do not decrypt. See [Encryption](#encryption). Same as SOPS and age.

**What about `.env.example`?**  
envc writes `.env.<env>.example` for every environment automatically — metadata as comments, public values filled, secrets blank. Commit them; they hold nothing secret. See [`.env.<env>.example`](#envenvexample).

**Where do values shared by every environment go?**  
`envc set base KEY=… --public|--secret`. [`.envc/base.yaml`](#envcbaseyaml) is layered under every environment; an environment overrides per key with its own `set`, or opts out entirely with `base: false` in its manifest. Base secrets are readable by everyone who can read any inheriting environment.

**Can destinations pull values back?**  
No.
