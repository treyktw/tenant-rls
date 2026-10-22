#!/usr/bin/env bash
# Local-development database setup, run once by the postgres image as the
# bootstrap superuser. Passwords are local placeholders, not secrets.
#
#   rls_owner        owns schema app and runs migrations. CREATEROLE (to make
#                    the group roles), but not a superuser and not BYPASSRLS,
#                    so FORCE RLS binds it like everyone else.
#   app_login        member of app_user        -> APP_DATABASE_URL
#   platform_login   member of platform_admin  -> PLATFORM_DATABASE_URL
#   relay_login      member of outbox_relay    -> RELAY_DATABASE_URL
#   bypass_login     member of app_user WITH BYPASSRLS: exists only so the
#                    tests and demo can show the pool refusing it.
set -euo pipefail
psql=(psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --no-psqlrc --quiet)

"${psql[@]}" --dbname postgres <<'SQL'
CREATE ROLE rls_owner LOGIN CREATEROLE PASSWORD 'owner-local-only';
CREATE DATABASE rls_kit OWNER rls_owner;
SQL

for f in /migrations/*.sql; do
  echo "applying $(basename "$f")"
  PGPASSWORD=owner-local-only psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet \
    --host /var/run/postgresql --username rls_owner --dbname rls_kit --single-transaction -f "$f"
done

"${psql[@]}" --dbname rls_kit <<'SQL'
CREATE ROLE app_login LOGIN PASSWORD 'app-local-only'
  INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT app_user TO app_login WITH INHERIT TRUE, SET FALSE;
CREATE ROLE platform_login LOGIN PASSWORD 'platform-local-only'
  INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT platform_admin TO platform_login WITH INHERIT TRUE, SET FALSE;
CREATE ROLE relay_login LOGIN PASSWORD 'relay-local-only'
  INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT outbox_relay TO relay_login WITH INHERIT TRUE, SET FALSE;
CREATE ROLE bypass_login LOGIN PASSWORD 'bypass-local-only'
  INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
GRANT app_user TO bypass_login WITH INHERIT TRUE, SET FALSE;
SQL
