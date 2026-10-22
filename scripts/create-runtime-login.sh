#!/usr/bin/env bash
# Create (or rotate) a runtime login and write its connection string into a
# gitignored env file.
#
#   OWNER_DATABASE_URL=... scripts/create-runtime-login.sh <env-file> [app|platform|relay]
#
#   app       app_runtime       (member of app_user)       -> APP_DATABASE_URL       (default)
#   platform  platform_runtime  (member of platform_admin) -> PLATFORM_DATABASE_URL
#   relay     relay_runtime     (member of outbox_relay)   -> RELAY_DATABASE_URL
#
# Each login is a plain member of one group role (README, "Roles"). The
# password is generated here, sent to Postgres over stdin, and written only to
# <env-file>. Nothing secret is printed.
set -euo pipefail

usage="usage: create-runtime-login.sh <env-file> [app|platform|relay]"
env_file="${1:?$usage}"
kind="${2:-app}"
: "${OWNER_DATABASE_URL:?set OWNER_DATABASE_URL to an owner connection string}"
case "$kind" in
  app)      group="app_user" ;;
  platform) group="platform_admin" ;;
  relay)    group="outbox_relay" ;;
  *) echo "$usage" >&2; exit 1 ;;
esac
login="${kind}_runtime"
env_var="$(echo "$kind" | tr '[:lower:]' '[:upper:]')_DATABASE_URL"

if ! git -C "$(dirname "$env_file")" check-ignore -q "$(basename "$env_file")"; then
  echo "error: $env_file is not gitignored; refusing to write a credential there" >&2
  exit 1
fi

# One Python step generates the password, hands it to psql on stdin and writes
# the env file. The password never appears in argv or the environment, where
# `ps` could read it, and the env file is created owner-only.
LOGIN="$login" GROUP="$group" ENV_VAR="$env_var" ENV_FILE="$env_file" python3 - <<'PY'
import os, re, secrets, subprocess
from urllib.parse import quote, urlsplit, urlunsplit

password = secrets.token_urlsafe(32)  # [A-Za-z0-9_-] only: safe in a SQL literal
assert re.fullmatch(r"[A-Za-z0-9_-]+", password)

login, group = os.environ["LOGIN"], os.environ["GROUP"]
assert re.fullmatch(r"[a-z]+_runtime", login) and re.fullmatch(r"[a-z_]+", group)
sql = f"""
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{login}') AS create_it \\gset
\\if :create_it
  CREATE ROLE {login} LOGIN PASSWORD '{password}'
    INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\\else
  -- Rotation only. Some managed providers refuse to restate SUPERUSER-class
  -- attributes here, and the role already has them from CREATE ROLE.
  ALTER ROLE {login} WITH LOGIN PASSWORD '{password}';
\\endif
GRANT {group} TO {login} WITH INHERIT TRUE, SET FALSE;
"""
# Never let a failure print the command: its argv holds the owner URL.
proc = subprocess.run(
    # One transaction: a failed GRANT must not leave a half-made login behind.
    ["psql", os.environ["OWNER_DATABASE_URL"], "--no-psqlrc", "--quiet", "--set=ON_ERROR_STOP=1",
     "--single-transaction"],
    input=sql, text=True, stdout=subprocess.DEVNULL,
)
if proc.returncode != 0:
    raise SystemExit(f"error: psql failed creating or rotating {login} (see its message above)")

# Same host and options as the owner URL; only the credentials change.
u = urlsplit(os.environ["OWNER_DATABASE_URL"])
host = u.hostname + (f":{u.port}" if u.port else "")
netloc = f"{quote(os.environ['LOGIN'])}:{password}@{host}"
url = urlunsplit((u.scheme, netloc, u.path, u.query, u.fragment))

path = os.environ["ENV_FILE"]
lines = open(path).read().splitlines() if os.path.exists(path) else []
env_var = os.environ["ENV_VAR"]
lines = [l for l in lines if not re.match(rf"\s*{env_var}=", l)]
lines.append(f"{env_var}={url}")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("\n".join(lines) + "\n")
os.chmod(path, 0o600)
PY

echo "$login ready; $env_var written to $env_file"
