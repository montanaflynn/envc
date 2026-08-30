#!/usr/bin/env bash
# End-to-end smoke test for the envc binary. Exercises the README quick start
# with generated keys in a temp repo. No network. Usage: scripts/e2e.sh [path-to-envc]
set -euo pipefail

ENVC=$(cd "$(dirname "${1:-./envc}")" && pwd)/$(basename "${1:-./envc}")
[ -x "$ENVC" ] || { echo "build first: go build -o envc ./cmd/envc" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK/home"
mkdir -p "$HOME/.ssh" "$WORK/repo" "$WORK/bobhome"
cd "$WORK/repo"
git init -q && git config user.email t@t && git config user.name t && git remote add origin git@github.com:acme/app.git

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1" >&2; exit 1; }
expect_exit() { # code cmd...
  local want=$1; shift
  set +e; "$@" >"$WORK/out" 2>"$WORK/err"; local got=$?; set -e
  [ "$got" = "$want" ] || { cat "$WORK/out" "$WORK/err" >&2; fail "exit $got != $want: $*"; }
}

# keys: alice (unencrypted ed25519), bob (rsa), deploy (ed25519 via ENVC_PRIVATE_KEY)
ssh-keygen -q -t ed25519 -N '' -f "$HOME/.ssh/id_ed25519" -C alice@test
ssh-keygen -q -t rsa -b 2048 -N '' -f "$WORK/bob" -C bob@test
ssh-keygen -q -t ed25519 -N '' -f "$WORK/deploy" -C envc-deploy

echo "== init"
expect_exit 0 "$ENVC" init
[ -f .envc.yaml ] && [ ! -d .envc ] && grep -q '^.env$' .gitignore && pass "files created, no environments" || fail "init files"
expect_exit 3 "$ENVC" init   # already exists → usage
pass "init refuses twice"
expect_exit 3 "$ENVC" ls local
grep -qF 'run `envc env add local`' "$WORK/err" && pass "no environments yet → usage error points at env add" || fail "no-env message: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" env add local
[ -f .envc/environments/local.yaml ] && pass "env add local" || fail "env add local"

echo "== principals & groups"
expect_exit 0 "$ENVC" principal add alice --ssh-key "$HOME/.ssh/id_ed25519.pub"
expect_exit 0 "$ENVC" principal add bob --ssh-key "$WORK/bob.pub"
expect_exit 0 "$ENVC" principal add deploy --ssh-key "$WORK/deploy.pub"
expect_exit 0 "$ENVC" group add engineers alice bob
expect_exit 0 "$ENVC" group add leads bob
expect_exit 0 "$ENVC" principal ls
grep -q alice "$WORK/out" && pass "principal ls" || fail "principal ls"

echo "== local values, run"
expect_exit 0 "$ENVC" allow local engineers
expect_exit 3 "$ENVC" set local DATABASE_URL=postgres://localhost/app        # no --secret/--public on create
pass "set requires --secret|--public on create"
expect_exit 0 "$ENVC" set local DATABASE_URL=postgres://localhost/app --secret
expect_exit 0 "$ENVC" set local LOG_LEVEL=debug --public --enum debug,info,warn,error --description 'Log verbosity'
expect_exit 0 "$ENVC" set local LOG_LEVEL=info                               # update keeps public
grep -q 'ENC\[envc1,' .envc/environments/local.yaml && pass "secret encrypted in file" || fail "secret not encrypted"
! grep -q '^crypto:' .envc/environments/local.yaml && [ -f .envc/state/local/envelope.yaml ] && grep -q '^key:' .envc/state/local/envelope.yaml && pass "envelope in .envc/state, not in the manifest" || fail "envelope location"
grep -q 'value: info' .envc/environments/local.yaml && pass "public plaintext in file" || fail "public not plaintext"
expect_exit 0 "$ENVC" get local DATABASE_URL
[ "$(cat "$WORK/out")" = "postgres://localhost/app" ] && pass "get decrypts (to a pipe, no -y)" || fail "get: $(cat "$WORK/out")"
printf 'multi\nline\n' | "$ENVC" set local PEM --stdin --secret
expect_exit 0 "$ENVC" get local PEM
[ "$(cat "$WORK/out")" = "$(printf 'multi\nline')" ] && pass "stdin multiline roundtrip" || fail "multiline: $(cat "$WORK/out")"
expect_exit 3 "$ENVC" set local LOG_LEVEL=trace                              # enum violation
pass "enum enforced"
expect_exit 0 "$ENVC" run local -- sh -c 'test "$LOG_LEVEL" = info && test "$DATABASE_URL" = postgres://localhost/app'
pass "run injects resolved values"
echo 'LOG_LEVEL=trace' > .env.local
expect_exit 0 "$ENVC" run local -- sh -c 'test "$LOG_LEVEL" = trace'
pass "run: .env.local overrides resolved values"
expect_exit 0 env LOG_LEVEL=shell "$ENVC" run local -- sh -c 'test "$LOG_LEVEL" = shell'
pass "run: process env wins"
expect_exit 0 "$ENVC" run local --pure -- sh -c 'test "$LOG_LEVEL" = info'
pass "run --pure skips .env.local"
expect_exit 0 "$ENVC" export local
grep -q '^DATABASE_URL=' "$WORK/out" && pass "export prints" || fail "export"
[ -f .env.local.example ] && grep -q '^# secret$' .env.local.example && grep -q '^DATABASE_URL=$' .env.local.example && grep -q '^LOG_LEVEL=info$' .env.local.example && grep -q '^# enum: debug, info, warn, error$' .env.local.example && ! grep -q 'postgres://localhost' .env.local.example && pass ".env.local.example generated: metadata as comments, secrets blank" || fail ".env.local.example: $(cat .env.local.example 2>&1)"
rm .env.local.example
expect_exit 0 "$ENVC" run local -- true
[ ! -f .env.local.example ] && pass "run does not regenerate .env.local.example" || fail "run wrote the template"
expect_exit 1 "$ENVC" ensure local --dry-run
grep -q '^ensure local$' "$WORK/err" && grep -q '^  would regenerate .env.local.example$' "$WORK/err" && grep -q 'ensure: 1 pending' "$WORK/err" && [ ! -f .env.local.example ] && pass "ensure --dry-run reports the missing template, writes nothing, exits 1" || fail "ensure dry-run: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" ensure local
grep -q '^  regenerated .env.local.example$' "$WORK/err" && [ -f .env.local.example ] && pass "ensure regenerates .env.local.example" || fail "ensure template: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" show local
grep -q 'ENC\[\|redacted' "$WORK/out" && ! grep -q 'postgres://localhost' "$WORK/out" && pass "show redacts" || fail "show leaks"
expect_exit 0 "$ENVC" ls local
expect_exit 0 "$ENVC" who local
grep -q alice "$WORK/out" && pass "who" || fail "who"
expect_exit 0 "$ENVC" ensure
grep -q '^ok$' "$WORK/err" && pass "ensure clean" || fail "ensure: $(cat "$WORK/err")"

echo "== dotenv destination + diff"
expect_exit 0 "$ENVC" env add local --dotenv .env --override .env.local
expect_exit 1 "$ENVC" diff local                                             # never synced
pass "diff drift before sync"
expect_exit 0 "$ENVC" sync local
[ -f .env ] && grep -q '^LOG_LEVEL=info$' .env && pass ".env written" || fail ".env"
expect_exit 0 "$ENVC" diff local
pass "diff clean after sync"
echo 'LOG_LEVEL=warn' >> .env
expect_exit 1 "$ENVC" diff local
pass "diff sees .env edit"
expect_exit 0 "$ENVC" sync local
expect_exit 0 "$ENVC" ensure local --dry-run
! grep -q 'stale' "$WORK/err" && pass "ensure: .env in sync" || fail "ensure .env: $(cat "$WORK/err")"
echo 'LOG_LEVEL=warn' >> .env
expect_exit 0 "$ENVC" ensure local --dry-run
grep -q '^warning: .env: stale; run envc sync local' "$WORK/err" && pass "ensure warns about stale .env" || fail "ensure stale: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" sync local
expect_exit 3 "$ENVC" status
expect_exit 3 "$ENVC" check
expect_exit 3 "$ENVC" rewrap local
expect_exit 3 "$ENVC" reencrypt local
pass "status, check, rewrap, reencrypt are gone"

echo "== production, access, re-key"
expect_exit 0 "$ENVC" env add production --github production --vercel production --vercel-project my-app
[ -f .env.production.example ] && pass ".env.production.example generated" || fail ".env.production.example"
expect_exit 0 "$ENVC" allow production leads deploy
expect_exit 0 "$ENVC" set production BOOTSTRAP=1 --secret              # first secret: no envelope yet, anyone can create it
expect_exit 2 "$ENVC" get production BOOTSTRAP                          # …but alice is not a recipient
expect_exit 2 "$ENVC" set production SECRET=1 --secret                 # and now writes need the key
pass "write requires read access once an envelope exists"
# bob sets it (bob's key via ENVC_PRIVATE_KEY_FILE)
expect_exit 0 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY_FILE="$WORK/bob" "$ENVC" set production SECRET=one --secret
expect_exit 0 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY_FILE="$WORK/bob" "$ENVC" allow production alice
expect_exit 0 "$ENVC" get production SECRET
[ "$(cat "$WORK/out")" = one ] && pass "allow → alice can read" || fail "allow"
KEY_BEFORE=$(grep '^key:' .envc/state/production/envelope.yaml)
expect_exit 0 "$ENVC" deny production leads
expect_exit 2 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY_FILE="$WORK/bob" "$ENVC" get production SECRET
pass "deny → bob locked out"
expect_exit 0 "$ENVC" get production SECRET
[ "$(cat "$WORK/out")" = one ] && pass "alice still reads after deny" || fail "post-deny read"
expect_exit 0 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY="$(cat "$WORK/deploy")" "$ENVC" get production SECRET
[ "$(cat "$WORK/out")" = one ] && pass "ENVC_PRIVATE_KEY contents works" || fail "ENVC_PRIVATE_KEY"
expect_exit 0 "$ENVC" ensure
expect_exit 3 "$ENVC" deny production alice --no-reencrypt
pass "--no-reencrypt is gone"
expect_exit 0 "$ENVC" get production SECRET
[ "$(cat "$WORK/out")" = one ] && pass "re-key keeps values" || fail "re-key"
[ "$(grep '^key:' .envc/state/production/envelope.yaml)" != "$KEY_BEFORE" ] && pass "deny re-keyed the envelope" || fail "envelope key unchanged"

echo "== state files"
[ ! -f .envc/state/production/sync.yaml ] && pass "no sync record before a non-dotenv sync" || fail "unexpected sync record"
[ ! -d .envc/state/local ] || [ ! -f .envc/state/local/sync.yaml ] && pass "dotenv sync writes no sync record" || fail "dotenv sync record"
cp .envc/state/production/envelope.yaml "$WORK/envelope.bak"
rm .envc/state/production/envelope.yaml
expect_exit 2 "$ENVC" get production SECRET
grep -qF 'git checkout -- .envc/state/production/envelope.yaml' "$WORK/err" && pass "missing envelope → exit 2 with restore hint" || fail "missing envelope message: $(cat "$WORK/err")"
[ ! -f .envc/state/production/envelope.yaml ] && pass "missing envelope is never regenerated" || fail "envelope regenerated"
expect_exit 1 "$ENVC" ensure production
grep -qF 'git checkout -- .envc/state/production/envelope.yaml' "$WORK/err" && [ ! -f .envc/state/production/envelope.yaml ] && pass "ensure reports the missing envelope and never recreates it" || fail "ensure message: $(cat "$WORK/err")"
cp "$WORK/envelope.bak" .envc/state/production/envelope.yaml
expect_exit 0 "$ENVC" get production SECRET
pass "restored envelope reads again"

echo "== environment is a required first argument"
expect_exit 0 "$ENVC" set local SECRET=local-one --secret               # local has its own SECRET
expect_exit 0 "$ENVC" get local SECRET
[ "$(cat "$WORK/out")" = local-one ] && pass "get local KEY reads local" || fail "get local: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" get production SECRET
[ "$(cat "$WORK/out")" = one ] && pass "get production KEY reads production" || fail "get production: $(cat "$WORK/out")"
expect_exit 3 "$ENVC" get SECRET                                        # no environment → usage, never a default
pass "get KEY without an environment is a usage error"
expect_exit 3 "$ENVC" get nope SECRET
grep -qF 'unknown environment "nope" (environments: local, production)' "$WORK/err" && pass "unknown environment is a usage error" || fail "unknown env message: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" set nosuchenv K=v --public
pass "set on unknown environment is a usage error"
expect_exit 3 "$ENVC" get production                                   # environment given, KEY missing
pass "env without KEY is a usage error"
expect_exit 3 "$ENVC" allow engineers                                  # NAME without an environment
pass "allow NAME without an environment is a usage error"
expect_exit 3 "$ENVC" run -- sh -c 'true'
pass "run without an environment is a usage error"
expect_exit 0 "$ENVC" run production -- sh -c 'test "$SECRET" = one'
expect_exit 0 "$ENVC" run production --pure -- sh -c 'test "$SECRET" = one'
expect_exit 0 "$ENVC" run local -- sh -c 'test "$SECRET" = local-one'
pass "run ENV -- CMD"
expect_exit 0 "$ENVC" ls production
grep -q '^SECRET' "$WORK/out" && pass "ls ENV" || fail "ls production"
# A key may share its name with an environment; the first argument is always the environment.
expect_exit 0 "$ENVC" set local production=1 --public
expect_exit 0 "$ENVC" get local production
[ "$(cat "$WORK/out")" = 1 ] && pass "key named like an env: envc get local production" || fail "get local production"
expect_exit 0 "$ENVC" sync local   # keep .env current so ensure stays warning-free
expect_exit 0 "$ENVC" ensure --dry-run
grep -q 'warning:' "$WORK/err" && fail "unexpected warning: $(cat "$WORK/err")" || pass "ensure has no collision warning"
expect_exit 0 "$ENVC" unset local production
expect_exit 0 "$ENVC" unset local SECRET

echo "== base layer"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/carol" -C carol@test
expect_exit 0 "$ENVC" set base APP_NAME=envc --public
expect_exit 0 "$ENVC" set base SHARED_SECRET=s --secret                # first base secret: access is derived, no allow
[ -f .envc/base.yaml ] && ! grep -q '^access' .envc/base.yaml && grep -q 'ENC\[envc1,' .envc/base.yaml && [ -f .envc/state/base/envelope.yaml ] && pass "base.yaml (no access key) + state/base/envelope.yaml" || fail "base files"
expect_exit 0 "$ENVC" export local
grep -q '^APP_NAME=envc$' "$WORK/out" && grep -q '^SHARED_SECRET=s$' "$WORK/out" && pass "export local includes base" || fail "export local: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" export production
grep -q '^APP_NAME=envc$' "$WORK/out" && grep -q '^SHARED_SECRET=s$' "$WORK/out" && pass "export production includes base" || fail "export production: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" set production APP_NAME=prod --public
grep -q 'overrides base' "$WORK/err" && pass "set on an inherited key says it overrides base" || fail "override hint: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" export production
grep -q '^APP_NAME=prod$' "$WORK/out" && pass "override wins in production" || fail "override: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" export local
grep -q '^APP_NAME=envc$' "$WORK/out" && pass "override is per environment" || fail "local after override: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" unset production APP_NAME
grep -q 'production now inherits APP_NAME from base' "$WORK/err" && pass "unset restores inheritance with a hint" || fail "unset hint: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" unset local APP_NAME
grep -q 'inherited from base; run `envc unset base APP_NAME`' "$WORK/err" && pass "unset of an inherited-only key is a usage error" || fail "inherited unset: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" run base -- true
grep -q 'base is not an environment' "$WORK/err" && pass "run base is a usage error" || fail "run base: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" env add base
expect_exit 3 "$ENVC" sync base
expect_exit 3 "$ENVC" allow base alice
expect_exit 0 "$ENVC" ensure base
pass "env add/sync/allow refuse base; ensure accepts it"
expect_exit 0 "$ENVC" who base
grep -q derived "$WORK/out" && grep -q alice "$WORK/out" && grep -q bob "$WORK/out" && grep -q deploy "$WORK/out" && pass "who base lists the union" || fail "who base: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" ls local
grep -Eq '^APP_NAME +public +base' "$WORK/out" && grep -Eq '^LOG_LEVEL +public +local' "$WORK/out" && pass "ls shows origin" || fail "ls origin: $(cat "$WORK/out")"
grep -q '^# from base$' .env.local.example && grep -q '^APP_NAME=envc$' .env.local.example && pass ".env.local.example marks inherited entries" || fail "template: $(cat .env.local.example)"
expect_exit 0 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY_FILE="$WORK/bob" "$ENVC" get base SHARED_SECRET
[ "$(cat "$WORK/out")" = s ] && pass "bob (local only) reads base" || fail "bob base read"
expect_exit 0 "$ENVC" group rm-member engineers bob                    # bob's only remaining access
grep -q '^  re-keyed base: bob no longer reads base secrets$' "$WORK/err" && pass "group rm-member reports the base effect" || fail "rm-member report: $(cat "$WORK/err")"
expect_exit 2 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY_FILE="$WORK/bob" "$ENVC" get base SHARED_SECRET
pass "leaving the union locks bob out of base"
expect_exit 0 "$ENVC" who local
grep -q '^inherits base: these principals also decrypt base secrets$' "$WORK/out" && pass "who ENV notes inherited base secrets" || fail "who local: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" who base
! grep -q bob "$WORK/out" && pass "who base drops bob" || fail "who base still lists bob"
expect_exit 0 "$ENVC" ensure --dry-run
! grep -q 'pending\|problem' "$WORK/err" && pass "ensure clean with base" || fail "ensure with base: $(cat "$WORK/err")"
# opt-out: an environment with base: false neither inherits nor joins the union
expect_exit 0 "$ENVC" principal add carol --ssh-key "$WORK/carol.pub"
expect_exit 0 "$ENVC" allow local carol
grep -q '^allow carol on local$' "$WORK/err" && grep -q '^  updated local readers: carol now reads local secrets$' "$WORK/err" && grep -q '^  updated base readers: carol now reads base secrets$' "$WORK/err" && pass "allow reports env + base effects" || fail "allow report: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" --dry-run deny local carol
grep -q '^would deny carol on local$' "$WORK/err" && grep -q '^  would re-key base: carol no longer reads base secrets$' "$WORK/err" && pass "dry-run reports the same effects with would" || fail "dry-run report: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" deny local carol
grep -q '^  re-keyed local: carol no longer reads local secrets$' "$WORK/err" && grep -q '^  re-keyed base: carol no longer reads base secrets$' "$WORK/err" && pass "deny reports env + base effects" || fail "deny report: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" env add ci
printf 'access: [carol]\nbase: false\nconfig: {}\n' > .envc/environments/ci.yaml
expect_exit 0 "$ENVC" ensure ci
expect_exit 0 "$ENVC" set ci CI_TOKEN=t --public
expect_exit 0 "$ENVC" export ci
! grep -q APP_NAME "$WORK/out" && grep -q '^CI_TOKEN=t$' "$WORK/out" && pass "base: false → export ci has no base keys" || fail "export ci: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" who base
! grep -q carol "$WORK/out" && pass "base: false → carol is not in the base union" || fail "who base lists carol"
expect_exit 2 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY_FILE="$WORK/carol" "$ENVC" get base SHARED_SECRET
pass "carol cannot read base"
! grep -q 'from base' .env.ci.example && pass ".env.ci.example has no base lines" || fail "ci template"
expect_exit 0 "$ENVC" who ci
! grep -q 'inherits base' "$WORK/out" && pass "who ci (base: false) has no inherits line" || fail "who ci: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" ensure --dry-run
expect_exit 0 "$ENVC" env rm ci
expect_exit 0 "$ENVC" principal rm carol

echo "== tamper detection"
cp .envc/environments/production.yaml "$WORK/production.bak"
python3 - <<'EOF'
import re
p='.envc/environments/production.yaml'; s=open(p).read()
s=re.sub(r'ENC\[envc1,([A-Za-z0-9+/=]+)\]', lambda m: 'ENC[envc1,'+m.group(1)[:-4]+'AAAA]', s, count=1)
open(p,'w').write(s)
EOF
expect_exit 2 "$ENVC" get production SECRET
pass "corrupted token rejected"
cp "$WORK/production.bak" .envc/environments/production.yaml

echo "== hand-broken MAC: ensure repairs"
expect_exit 0 "$ENVC" set production SECOND=two --secret
python3 - <<'PY'
import re
p='.envc/environments/production.yaml'; s=open(p).read()
s=re.sub(r'  SECOND:\n(?:    .*\n)+', '', s, count=1)
open(p,'w').write(s)
PY
expect_exit 2 "$ENVC" get production SECRET
grep -q 'run `envc ensure production` to repair' "$WORK/err" && pass "broken MAC names ensure as the fix" || fail "mac hint: $(cat "$WORK/err")"
expect_exit 1 "$ENVC" ensure production --dry-run
grep -q 'would repair MAC: secrets edited by hand' "$WORK/err" && pass "ensure --dry-run reports the MAC repair" || fail "dry mac: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" ensure production
grep -q 'repaired MAC: secrets edited by hand' "$WORK/err" && pass "ensure repairs a hand-broken MAC" || fail "repair: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" get production SECRET
[ "$(cat "$WORK/out")" = one ] && pass "values still read after MAC repair" || fail "post-repair read: $(cat "$WORK/out")"
cp .envc/environments/production.yaml "$WORK/production.bak2"
python3 - <<'PY'
import re
p='.envc/environments/production.yaml'; s=open(p).read()
s=re.sub(r'ENC\[envc1,([A-Za-z0-9+/=]+)\]', lambda m: 'ENC[envc1,'+m.group(1)[:-4]+'AAAA]', s, count=1)
open(p,'w').write(s)
PY
expect_exit 1 "$ENVC" ensure production
! grep -q 'repair MAC' "$WORK/err" && pass "a corrupt token is a problem, never a repair" || fail "corrupt repaired: $(cat "$WORK/err")"
cp "$WORK/production.bak2" .envc/environments/production.yaml
expect_exit 0 "$ENVC" ensure production

echo "== hand-edited yaml + ensure"
cat > .envc/environments/preview.yaml <<'EOF'
access: [engineers]
config:
  API_KEY:
    secret: true
    value: plain-until-ensure
  NAME:
    secret: false
    value: preview
EOF
expect_exit 1 "$ENVC" ensure --dry-run                                 # plaintext secret
grep -q '^ensure preview$' "$WORK/err" && grep -q '^  would encrypt 1 plaintext secret: API_KEY$' "$WORK/err" && grep -q '^  would update preview readers: ' "$WORK/err" && grep -q 'pending' "$WORK/err" && pass "ensure --dry-run reports the plaintext secret" || fail "ensure dry-run: $(cat "$WORK/err")"
[ ! -f .envc/state/preview/envelope.yaml ] && grep -q 'plain-until-ensure' .envc/environments/preview.yaml && pass "dry run wrote nothing" || fail "dry run wrote"
expect_exit 0 "$ENVC" ensure preview
grep -q '^  encrypted 1 plaintext secret: API_KEY$' "$WORK/err" && grep -q '^  updated preview readers: ' "$WORK/err" && pass "ensure reports what it did" || fail "ensure report: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" ensure --dry-run
expect_exit 0 "$ENVC" get preview API_KEY
[ "$(cat "$WORK/out")" = plain-until-ensure ] && pass "ensure encrypted the hand-written secret" || fail "ensure value"
[ -f .envc/state/preview/envelope.yaml ] && pass "ensure created the envelope" || fail "no envelope after ensure"
# a reader removed by hand: ensure re-keys (new data key), not just a readers update
expect_exit 0 "$ENVC" allow preview deploy
sed -i.bak '/^  - deploy$/d' .envc/environments/preview.yaml && rm -f .envc/environments/preview.yaml.bak
! grep -q deploy .envc/environments/preview.yaml || fail "hand edit of preview access did not apply"
expect_exit 1 "$ENVC" ensure preview --dry-run
grep -q '^  would re-key preview: deploy no longer reads preview secrets$' "$WORK/err" && pass "hand-removed reader → ensure --dry-run says re-key" || fail "re-key dry-run: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" ensure preview
grep -q '^  re-keyed preview: deploy no longer reads preview secrets$' "$WORK/err" && pass "hand-removed reader → ensure re-keys" || fail "re-key: $(cat "$WORK/err")"

echo "== global flags, version"
expect_exit 0 "$ENVC" version
grep -q '^envc ' "$WORK/out" && pass "version" || fail "version: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" env ls --json
grep -q '"local"' "$WORK/out" && pass "env ls --json" || fail "env ls --json: $(cat "$WORK/out")"
mkdir -p "$WORK/elsewhere"
( cd "$WORK/elsewhere" && expect_exit 3 "$ENVC" env ls )
grep -qF 'no .envc.yaml in this directory or any parent; run `envc init` at the repo root' "$WORK/err" && pass "outside a repo → no-root usage error" || fail "no repo: $(cat "$WORK/err")"
( cd "$WORK/elsewhere" && expect_exit 3 "$ENVC" -C "$WORK/repo" env ls )
grep -q 'unknown shorthand flag' "$WORK/err" && pass "-C is gone (unknown flag)" || fail "-C: $(cat "$WORK/err")"

echo "== walk-up root discovery"
mkdir -p apps/web
( cd apps/web && expect_exit 0 "$ENVC" env ls )
grep -q '^local$' "$WORK/out" && pass "env ls from a subdirectory" || fail "walk-up env ls: $(cat "$WORK/out")"
( cd apps/web && expect_exit 0 "$ENVC" set local WALKUP=1 --public )
( cd apps/web && expect_exit 0 "$ENVC" get local WALKUP )
[ "$(cat "$WORK/out")" = 1 ] && pass "set/get from a subdirectory" || fail "walk-up get: $(cat "$WORK/out")"
[ -f .env.local.example ] && [ ! -e apps/web/.env.local.example ] && [ ! -e apps/web/.envc ] && pass "files land at the root, not the cwd" || fail "walk-up file locations"
( cd apps/web && expect_exit 0 "$ENVC" run local -- pwd )
[ "$(cat "$WORK/out")" = "$(cd apps/web && pwd)" ] && pass "run execs in the caller's directory" || fail "run cwd: $(cat "$WORK/out")"
( cd apps/web && expect_exit 3 "$ENVC" init )
grep -q 'refusing to init inside an existing envc repo' "$WORK/err" && pass "init refuses inside an existing repo" || fail "init inside: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" unset local WALKUP

echo "== env add flag combinations"
expect_exit 3 "$ENVC" env add staging --override .env.staging.local
grep -q -- '--override requires --dotenv' "$WORK/err" && pass "--override without dotenv is a usage error" || fail "override: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" env add staging --vercel preview
grep -q 'vercel-project' "$WORK/err" && pass "--vercel without a project is a usage error" || fail "vercel: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" env add staging --github staging
grep -q 'repository: acme/app' .envc.yaml && pass "--github pins the repository from git remote origin" || fail "github pin: $(cat .envc.yaml)"
expect_exit 0 "$ENVC" env add staging --dotenv .env.staging --override .env.staging.local
grep -q 'path: .env.staging' .envc.yaml && pass "env add on an existing environment adds destinations" || fail "second env add"
expect_exit 0 "$ENVC" env add staging --vercel edge --vercel-project my-app
grep -q 'environment: edge' .envc.yaml && pass "custom Vercel environment slug is accepted" || fail "vercel custom slug: $(cat .envc.yaml)"
expect_exit 0 "$ENVC" env add staging --convex quiet-lion-123
grep -q 'deployment: quiet-lion-123' .envc.yaml && pass "--convex pins the deployment name" || fail "convex: $(cat .envc.yaml)"
expect_exit 0 "$ENVC" env ls
grep -q '^staging$' "$WORK/out" && [ -f .env.staging.example ] && pass "env ls + template for staging" || fail "env ls staging"
expect_exit 3 "$ENVC" env add 'bad/name'
grep -q 'invalid environment name' "$WORK/err" && pass "invalid environment name is a usage error" || fail "bad name: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" env rm local
grep -q 'pass --force' "$WORK/err" && pass "env rm refuses an environment with secrets" || fail "env rm local: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" env rm staging
[ ! -f .envc/environments/staging.yaml ] && [ ! -f .env.staging.example ] && ! grep -q 'staging' .envc.yaml && pass "env rm without secrets needs no --force; sync config and template removed" || fail "env rm staging"

echo "== principal add variants"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/dave" -C dave@test
ssh-keygen -q -t ed25519 -N '' -f "$WORK/alice2" -C alice2@test
expect_exit 0 sh -c "cat '$WORK/dave.pub' | '$ENVC' principal add dave --ssh-key -"
pass "principal add --ssh-key - (stdin)"
AGE_RECIPIENT=age1h6qq5mn5v8zfpam6qpdxxjd0nwx27tesjxmxudafzmx3pr0m9uhqhnnvs9
AGE_IDENTITY=AGE-SECRET-KEY-18H5P2Y40JLNH5NGSY0JWC9YFWGS4T97MUHLPK2RJP4Y2JFZK48GQRVAGCX   # test-only pair
expect_exit 0 "$ENVC" principal add eve --age "$AGE_RECIPIENT"
pass "principal add --age"
expect_exit 3 "$ENVC" principal add zed
grep -q 'one of --github, --ssh-key, or --age' "$WORK/err" && pass "principal add needs a key source" || fail "principal add: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" principal add zed --github zed --ssh-key "$WORK/dave.pub"
pass "--github and --ssh-key are mutually exclusive"
expect_exit 0 "$ENVC" principal add alice --ssh-key "$WORK/alice2.pub"
expect_exit 0 "$ENVC" principal show alice
[ "$(grep -c '  key: ' "$WORK/out")" = 2 ] && pass "principal add on an existing principal appends a key; show lists both" || fail "principal show: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" principal show alice --json
grep -q '"keys"' "$WORK/out" && grep -q '"name": "alice"' "$WORK/out" && pass "principal show --json" || fail "principal show json"
expect_exit 0 "$ENVC" principal ls --json
grep -q '"dave"' "$WORK/out" && grep -q '"eve"' "$WORK/out" && pass "principal ls --json" || fail "principal ls json"
expect_exit 3 "$ENVC" principal rm nosuch
pass "principal rm unknown → usage error"
expect_exit 3 "$ENVC" principal sync alice
grep -q 'no github: user' "$WORK/err" && pass "principal sync without github: is a usage error" || fail "principal sync: $(cat "$WORK/err")"

echo "== groups"
expect_exit 3 "$ENVC" group add g2 nosuch
pass "group add with an unknown principal → usage error"
expect_exit 3 "$ENVC" group add g3 engineers
grep -q 'is not a principal' "$WORK/err" && pass "groups may contain only principals (no nesting)" || fail "group nesting: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" group ls
grep -q '^engineers' "$WORK/out" && pass "group ls" || fail "group ls: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" group ls --json
grep -q '"engineers"' "$WORK/out" && pass "group ls --json" || fail "group ls json"
expect_exit 0 "$ENVC" group show engineers --json
grep -q '"alice"' "$WORK/out" && grep -q '"members"' "$WORK/out" && pass "group show --json" || fail "group show json: $(cat "$WORK/out")"
expect_exit 3 "$ENVC" group rm-member engineers dave
grep -q 'is not a member' "$WORK/err" && pass "group rm-member of a non-member → usage error" || fail "rm-member: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" group rm engineers
grep -q 'still on access' "$WORK/err" && pass "group rm refuses a group still on access" || fail "group rm: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" group add-member engineers dave
grep -q '^add dave to group engineers$' "$WORK/err" && grep -q '^  updated base readers: dave now reads base secrets$' "$WORK/err" && pass "group add-member reports env + base reader updates" || fail "add-member report: $(cat "$WORK/err")"
expect_exit 0 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY_FILE="$WORK/dave" "$ENVC" get base SHARED_SECRET
[ "$(cat "$WORK/out")" = s ] && pass "new group member reads base" || fail "dave base read"
expect_exit 0 "$ENVC" group rm-member engineers dave
grep -q '^  re-keyed base: dave no longer reads base secrets$' "$WORK/err" && pass "group rm-member re-keys base" || fail "rm-member report: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" group add temp dave eve
expect_exit 0 "$ENVC" group rm temp
expect_exit 0 "$ENVC" group ls
! grep -q '^temp' "$WORK/out" && pass "group rm of an unused group" || fail "group rm temp"

echo "== who"
expect_exit 0 "$ENVC" who local --keys
grep -q 'SHA256:' "$WORK/out" && pass "who --keys shows fingerprints" || fail "who --keys: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" who local --json
grep -q '"environment": "local"' "$WORK/out" && grep -q '"inherits_base": true' "$WORK/out" && pass "who --json (inherits_base)" || fail "who json: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" who base --json
grep -q '"derived": true' "$WORK/out" && pass "who base --json is derived" || fail "who base json: $(cat "$WORK/out")"
expect_exit 3 "$ENVC" who
expect_exit 3 "$ENVC" who nope
pass "who without / with an unknown environment → usage error"

echo "== set, get, unset, ls, show, export details"
expect_exit 3 "$ENVC" set local A=1 --secret --public
grep -q 'mutually exclusive' "$WORK/err" && pass "--secret and --public are mutually exclusive" || fail "set both: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" set local A=1 --public --stdin
pass "KEY=VALUE cannot be combined with --stdin"
expect_exit 3 "$ENVC" set local 1BAD=1 --public
grep -q 'invalid key' "$WORK/err" && pass "key names are validated" || fail "bad key: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" set base Q=1
pass "set base also requires --secret|--public on create"
printf 'line1\nline2\n' > "$WORK/f.txt"
expect_exit 0 "$ENVC" set local F --file "$WORK/f.txt" --public
expect_exit 0 "$ENVC" get local F
printf 'line1\nline2\n\n' | cmp -s - "$WORK/out" && [ ! -s "$WORK/err" ] && pass "--file stores verbatim (trailing newline kept); get prints value + newline, nothing on stderr" || fail "file value: $(od -c "$WORK/out")"
expect_exit 0 "$ENVC" set local X=12 --public --pattern '^[0-9]+$'
expect_exit 3 "$ENVC" set local X=abc
grep -q 'does not match pattern' "$WORK/err" && pass "pattern enforced" || fail "pattern: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" set local X=abc --pattern ''
pass "--pattern '' clears the pattern"
expect_exit 0 "$ENVC" set local ANCH=123 --public --pattern '[0-9]+'
expect_exit 3 "$ENVC" set local ANCH=a1b
grep -q 'does not match pattern' "$WORK/err" && pass "pattern is anchored: substring match rejected" || fail "anchor: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" unset local ANCH
expect_exit 0 "$ENVC" set local D=1 --public --description 'The D'
expect_exit 0 "$ENVC" ls local
grep -Eq '^D +public +local +The D' "$WORK/out" && pass "ls shows the description" || fail "ls desc: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" set local D=2 --description ''
expect_exit 0 "$ENVC" ls local
! grep -q 'The D' "$WORK/out" && pass "--description '' clears it" || fail "desc not cleared"
expect_exit 0 "$ENVC" set local LOG_LEVEL=trace --enum ''
expect_exit 0 "$ENVC" get local LOG_LEVEL
[ "$(cat "$WORK/out")" = trace ] && pass "--enum '' clears the enum" || fail "enum clear"
expect_exit 0 "$ENVC" set local LOG_LEVEL=info --enum debug,info,warn,error
expect_exit 0 "$ENVC" set local FLIP=hidden --secret
expect_exit 0 "$ENVC" set local FLIP=shown --public
grep -q 'was secret and is now public' "$WORK/err" && grep -q 'value: shown' .envc/environments/local.yaml && pass "secret → public warns and stores plaintext" || fail "flip: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" set local FLIP=hidden --secret
grep -q 'ENC\[envc1,' .envc/environments/local.yaml && pass "public → secret encrypts again" || fail "flip back"
expect_exit 3 "$ENVC" get local NOPE
expect_exit 3 "$ENVC" unset local NOPE
pass "get/unset of a missing key → usage error"
expect_exit 0 "$ENVC" get local APP_NAME
[ "$(cat "$WORK/out")" = envc ] && pass "get falls through to base" || fail "get base fallthrough: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" ls local --json
grep -q '"origin": "base"' "$WORK/out" && grep -q '"origin": "local"' "$WORK/out" && pass "ls --json carries origin" || fail "ls json: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" show local --secrets
grep -q 'postgres://localhost/app' "$WORK/out" && pass "show --secrets decrypts" || fail "show --secrets"
expect_exit 0 "$ENVC" show base
grep -q 'APP_NAME' "$WORK/out" && pass "show base" || fail "show base"
expect_exit 0 "$ENVC" set local WEIRD='a "b" $c' --public
expect_exit 0 "$ENVC" export local
grep -qF 'WEIRD="a \"b\" $c"' "$WORK/out" && pass "export quotes special characters" || fail "export quoting: $(cat "$WORK/out")"
cut -d= -f1 "$WORK/out" | sort -c && pass "export is sorted by key" || fail "export order"
expect_exit 0 "$ENVC" run local -- sh -c '[ "$WEIRD" = "a \"b\" \$c" ] && [ "$PEM" = "$(printf "multi\nline")" ] && [ "$(printf %s "$F" | wc -c | tr -d " ")" = 12 ]'
pass "run passes quoted, multiline, and verbatim values through unchanged"
expect_exit 7 "$ENVC" run local -- sh -c 'exit 7'
pass "run passes the child's exit code through"
expect_exit 3 "$ENVC" run local
grep -q 'put the command after --' "$WORK/err" && pass "run without -- is a usage error" || fail "run no dashes: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" run local -- envc-no-such-command-xyz
pass "run of a missing executable → exit 3"
rm .env.local.example
expect_exit 0 "$ENVC" get local X
expect_exit 0 "$ENVC" ls local
expect_exit 0 "$ENVC" export local
[ ! -f .env.local.example ] && pass "get/ls/export never write the template" || fail "a read wrote the template"
expect_exit 0 "$ENVC" ensure local
expect_exit 0 "$ENVC" unset local WEIRD
expect_exit 0 "$ENVC" unset local F
expect_exit 0 "$ENVC" unset local X
expect_exit 0 "$ENVC" unset local D
expect_exit 0 "$ENVC" unset local FLIP

echo "== base refusals and acceptances"
for c in "export base" "diff base" "deny base alice" "who base --keys"; do :; done
expect_exit 3 "$ENVC" export base
expect_exit 3 "$ENVC" diff base
expect_exit 3 "$ENVC" deny base alice
grep -q 'base is not an environment' "$WORK/err" && pass "export/diff/deny refuse base" || fail "base refusal: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" ls base
grep -Eq '^APP_NAME +public +base' "$WORK/out" && pass "ls base" || fail "ls base: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" get base APP_NAME
[ "$(cat "$WORK/out")" = envc ] && pass "get base" || fail "get base"

echo "== dotenv sync/diff details"
expect_exit 3 "$ENVC" diff local --only nope
grep -q 'not configured for local' "$WORK/err" && pass "diff --only unknown destination → usage error" || fail "diff --only: $(cat "$WORK/err")"
expect_exit 3 "$ENVC" sync local --only nope
pass "sync --only unknown destination → usage error"
cp .env.local "$WORK/env.local.before"
rm .env
expect_exit 0 "$ENVC" sync local --dry-run
[ ! -f .env ] && grep -q 'would' "$WORK/err" && pass "sync --dry-run writes nothing" || fail "sync dry-run: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" sync local
cmp -s .env.local "$WORK/env.local.before" && pass "sync never touches .env.local" || fail ".env.local changed"
expect_exit 0 "$ENVC" diff local --only dotenv
pass "diff --only dotenv"
echo 'EXTRA=1' >> .env
expect_exit 0 "$ENVC" diff local
cat "$WORK/out" "$WORK/err" | grep -q 'EXTRA' && cat "$WORK/out" "$WORK/err" | grep -q 'extra' && pass "extra keys are listed (report on stderr) and do not fail diff" || fail "diff extra: $(cat "$WORK/out" "$WORK/err")"
expect_exit 0 "$ENVC" diff local --json
grep -q '"EXTRA": "extra"' "$WORK/out" && pass "diff --json" || fail "diff json: $(cat "$WORK/out")"
expect_exit 0 "$ENVC" sync local --prune
grep -q '1 pruned' "$WORK/err" && ! grep -q '^EXTRA=' .env && pass "sync --prune removes extra keys" || fail "prune: $(cat "$WORK/err")"

echo "== private keys: env vars, age, passphrase without a TTY"
expect_exit 2 env ENVC_PRIVATE_KEY=garbage "$ENVC" get local DATABASE_URL
grep -q 'ENVC_PRIVATE_KEY' "$WORK/err" && pass "malformed ENVC_PRIVATE_KEY → exit 2 naming the variable" || fail "garbage key: $(cat "$WORK/err")"
expect_exit 2 env ENVC_PRIVATE_KEY_FILE="$WORK/nope" "$ENVC" get local DATABASE_URL
grep -q 'ENVC_PRIVATE_KEY_FILE' "$WORK/err" && pass "missing ENVC_PRIVATE_KEY_FILE → exit 2" || fail "missing key file: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" allow local eve
expect_exit 0 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY="$AGE_IDENTITY" "$ENVC" get local DATABASE_URL
[ "$(cat "$WORK/out")" = "postgres://localhost/app" ] && pass "age identity via ENVC_PRIVATE_KEY (auto-detected)" || fail "age contents"
printf '# created: test\n# public key: %s\n%s\n' "$AGE_RECIPIENT" "$AGE_IDENTITY" > "$WORK/age.txt"
expect_exit 0 env HOME="$WORK/bobhome" ENVC_PRIVATE_KEY_FILE="$WORK/age.txt" "$ENVC" get local DATABASE_URL
[ "$(cat "$WORK/out")" = "postgres://localhost/app" ] && pass "age key file with comment lines via ENVC_PRIVATE_KEY_FILE" || fail "age file"
expect_exit 0 "$ENVC" deny local eve
mkdir -p "$WORK/frankhome/.ssh"
ssh-keygen -q -t ed25519 -N 'passphrase' -f "$WORK/frankhome/.ssh/id_ed25519" -C frank@test
expect_exit 0 "$ENVC" principal add frank --ssh-key "$WORK/frankhome/.ssh/id_ed25519.pub"
expect_exit 0 "$ENVC" allow local frank
expect_exit 2 env HOME="$WORK/frankhome" "$ENVC" get local DATABASE_URL </dev/null
grep -q 'passphrase-protected and no TTY' "$WORK/err" && pass "passphrase-protected key is skipped with a notice when there is no TTY" || fail "passphrase notice: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" deny local frank
expect_exit 0 "$ENVC" principal rm frank

echo "== ensure: json, blocked target, no key, envelope removal"
expect_exit 0 "$ENVC" sync local
expect_exit 0 "$ENVC" ensure --json
grep -q '"pending": 0' "$WORK/out" && pass "ensure --json" || fail "ensure json: $(cat "$WORK/out")"
cat > .envc/environments/blocked.yaml <<'EOF'
access: [alice, ghost]
config:
  P:
    secret: true
    value: plain
  E:
    secret: false
    value: bad
    enum: [good]
EOF
expect_exit 1 "$ENVC" ensure blocked
grep -q 'access: unknown principal or group "ghost"' "$WORK/err" && grep -q 'config.E.enum: value "bad" is not one of good' "$WORK/err" && grep -q 'not fixed: resolve the problem(s) above, then run envc ensure blocked again to encrypt 1 plaintext secret: P' "$WORK/err" && grep -q 'value: plain' .envc/environments/blocked.yaml && [ ! -f .env.blocked.example ] && pass "unfixable problems block fixes and name what is waiting" || fail "blocked: $(cat "$WORK/err")"
rm .envc/environments/blocked.yaml
printf 'access: [alice]\nbase: maybe\nconfig: {}\n' > .envc/environments/badbase.yaml
expect_exit 1 "$ENVC" ensure badbase
grep -q 'cannot unmarshal' "$WORK/err" && pass "base: must be a bool" || fail "badbase: $(cat "$WORK/err")"
rm .envc/environments/badbase.yaml
expect_exit 3 "$ENVC" ensure nope
pass "ensure of an unknown environment → usage error"
# a fix that needs a key the caller does not hold
python3 - <<'EOF'
p='.envc/environments/preview.yaml'; s=open(p).read()
s=s.replace("config:\n","config:\n  LATER:\n    secret: true\n    value: typed-by-hand\n",1)
open(p,'w').write(s)
EOF
expect_exit 2 env HOME="$WORK/bobhome" "$ENVC" ensure preview
grep -q 'alice' "$WORK/err" && grep -q 'typed-by-hand' .envc/environments/preview.yaml && pass "ensure without a usable key → exit 2 naming readers who can, nothing written" || fail "ensure no key: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" ensure preview
expect_exit 0 "$ENVC" get preview LATER
[ "$(cat "$WORK/out")" = typed-by-hand ] && pass "a reader's ensure encrypts it" || fail "ensure preview"
expect_exit 0 "$ENVC" unset preview LATER
expect_exit 0 "$ENVC" unset preview API_KEY
[ ! -f .envc/state/preview/envelope.yaml ] && pass "removing the last secret removes the envelope" || fail "envelope kept after last secret"
expect_exit 0 "$ENVC" ensure --dry-run
grep -q '^ok$' "$WORK/err" && pass "ensure clean after envelope removal" || fail "ensure: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" set preview API_KEY=again --secret
[ -f .envc/state/preview/envelope.yaml ] && pass "first secret recreates the envelope" || fail "envelope not recreated"
expect_exit 0 "$ENVC" principal rm dave
expect_exit 0 "$ENVC" principal rm eve

echo "== principal rm, unset, env rm"
expect_exit 0 "$ENVC" principal rm bob
! grep -q bob .envc.yaml && pass "principal rm" || fail "principal rm"
expect_exit 0 "$ENVC" unset preview NAME
rm .env.production.example
expect_exit 1 "$ENVC" ensure production --dry-run
grep -q '^  would regenerate .env.production.example$' "$WORK/err" && pass "ensure --dry-run reports missing .env.production.example" || fail "ensure template: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" ensure production
expect_exit 0 "$ENVC" ensure production --dry-run
pass "ensure recreates .env.production.example; dry run clean"
echo 'EDITED=1' >> .env.production.example
expect_exit 1 "$ENVC" ensure production --dry-run
grep -q '^  would regenerate .env.production.example$' "$WORK/err" && pass "ensure --dry-run reports stale .env.production.example" || fail "ensure stale: $(cat "$WORK/err")"
expect_exit 0 "$ENVC" ensure production
expect_exit 3 "$ENVC" env rm production
expect_exit 0 "$ENVC" env rm production --force
[ ! -f .envc/environments/production.yaml ] && [ ! -d .envc/state/production ] && [ ! -f .env.production.example ] && pass "env rm --force removes manifest, state, and template" || fail "env rm"

echo "ALL PASSED"
