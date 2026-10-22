#!/usr/bin/env bash
# `make demo`: seeds two tenants, starts the API, and walks through the curl
# calls in the README. Expects the env from .env.example and a running
# database (make db-up).
set -euo pipefail
cd "$(dirname "$0")/.."

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
api="http://${HTTP_ADDR:-127.0.0.1:8080}"

go build -o bin/server ./cmd/server
go build -o bin/mint-token ./cmd/mint-token
go run ./cmd/seed

bin/server 2>/tmp/rls-kit-demo-server.log &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -fsS "$api/healthz" >/dev/null 2>&1 && break; sleep 0.1; done

ACME=$(bin/mint-token user_acme_admin)
ACME_MEMBER=$(bin/mint-token user_acme_member)
GLOBEX=$(bin/mint-token user_globex_admin)
NEWBIE=$(bin/mint-token user_new_signup)
ACME_PROJECT=11111111-1111-4111-8111-1111111111f1
GLOBEX_PROJECT=22222222-2222-4222-8222-2222222222f1

call() { # call <label> <token> <method> <path> [json]
  local label=$1 token=$2 method=$3 path=$4 data=${5:-}
  printf '\n$ %s %s   # %s\n' "$method" "$path" "$label"
  if [[ -n $data ]]; then
    curl -sS -X "$method" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
      -d "$data" -w '\n-> HTTP %{http_code}\n' "$api$path"
  else
    curl -sS -X "$method" -H "Authorization: Bearer $token" -w '\n-> HTTP %{http_code}\n' "$api$path"
  fi
}

bold "Each tenant sees only its own projects (no tenant filter in the SQL)"
call "acme admin"   "$ACME"   GET /v1/projects
call "globex admin" "$GLOBEX" GET /v1/projects

bold "Cross-tenant: acme asks for globex's project by id"
call "acme admin -> globex project"       "$ACME" GET  "/v1/projects/$GLOBEX_PROJECT"
call "acme admin -> globex project notes" "$ACME" GET  "/v1/projects/$GLOBEX_PROJECT/notes"
call "acme admin -> plant a note"         "$ACME" POST "/v1/projects/$GLOBEX_PROJECT/notes" '{"body":"planted"}'

bold "Gates inside the tenant: a MEMBER cannot archive or promote itself"
call "acme member -> archive"   "$ACME_MEMBER" POST  "/v1/projects/$ACME_PROJECT/archive"
call "acme member -> self-promote" "$ACME_MEMBER" PATCH /v1/members/11111111-1111-4111-8111-1111111111a2 '{"role":"ADMIN"}'

bold "A signed-up user with no tenant yet"
call "new signup -> projects" "$NEWBIE" GET /v1/projects

bold "No token"
printf '\n$ GET /v1/projects   # no Authorization header\n'
curl -sS -w '\n-> HTTP %{http_code}\n' "$api/v1/projects"

bold "The pool refuses unsafe logins (BYPASSRLS, the schema owner)"
for name in BYPASS OWNER; do
  var="${name}_DATABASE_URL"
  login=$(sed -E 's#^[a-z]+://([^:]+):.*#\1#' <<<"${!var}")
  printf '\n$ APP_DATABASE_URL=<%s login> bin/server\n' "$login"
  APP_DATABASE_URL="${!var}" HTTP_ADDR=127.0.0.1:0 timeout 10 bin/server 2>&1 | sed -E 's/^time=[^ ]+ //' | tail -1 || true
done
