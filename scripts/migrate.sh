#!/usr/bin/env bash
# Apply sql/migrations/*.sql in order, each in its own transaction.
#
#   OWNER_DATABASE_URL=postgres://owner@host/db scripts/migrate.sh
#   scripts/migrate.sh --status
#
# Uses the owner connection. Applied files are recorded with a SHA-256; editing
# an applied file is refused, so a schema change is always a new file.
# Plain psql on purpose: the same files can be applied by a Go service later.
# (docker compose applies them directly at first start; use this anywhere else.)
set -euo pipefail

: "${OWNER_DATABASE_URL:?set OWNER_DATABASE_URL to an owner connection string}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dir="$here/../sql/migrations"
psql_base=(psql "$OWNER_DATABASE_URL" --no-psqlrc --quiet --set=ON_ERROR_STOP=1)
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

"${psql_base[@]}" <<'SQL'
SET client_min_messages = warning;
CREATE SCHEMA IF NOT EXISTS app_migrations;
CREATE TABLE IF NOT EXISTS app_migrations.schema_migrations (
  version text PRIMARY KEY,
  sha256 text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
SQL

status_only=false
[[ "${1:-}" == "--status" ]] && status_only=true

applied=0
for file in "$dir"/*.sql; do
  version="$(basename "$file" .sql)"
  sum="$(sha256 "$file")"
  recorded="$("${psql_base[@]}" --tuples-only --no-align \
    -c "SELECT sha256 FROM app_migrations.schema_migrations WHERE version = '$version'")"

  if [[ -n "$recorded" ]]; then
    if [[ "$recorded" != "$sum" ]]; then
      echo "error: $version was edited after it was applied (recorded $recorded, now $sum)" >&2
      exit 1
    fi
    $status_only && echo "applied  $version"
    continue
  fi

  if $status_only; then
    echo "pending  $version"
    continue
  fi

  echo "applying $version"
  "${psql_base[@]}" --single-transaction \
    -f "$file" \
    -c "INSERT INTO app_migrations.schema_migrations (version, sha256) VALUES ('$version', '$sum')"
  applied=$((applied + 1))
done

$status_only || echo "done: $applied applied"
