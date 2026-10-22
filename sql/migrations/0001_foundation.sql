-- 0001 foundation: schema, tenant context, roles, outbox, tenancy and a tiny
-- demo domain (projects and notes).
--
-- Conventions used in every migration:
--   * Every tenant-owned row carries `tenant_id`, and RLS restricts it to the
--     transaction's `app.tenant_id` setting. No setting, no rows.
--   * Parents expose UNIQUE (tenant_id, id) so children reference them with a
--     composite foreign key. A child can never point at another tenant's
--     parent, even through a bug in application code.
--   * Statuses are text with CHECK constraints, not enums, so a new state is
--     one ALTER rather than a type migration.
--
-- Run as the schema owner: a plain login with CREATEROLE, not a superuser
-- (docker/initdb/00_owner.sh creates one). FORCE RLS then binds the owner too.

CREATE SCHEMA IF NOT EXISTS app;

-- ---------------------------------------------------------------------------
-- Roles. Group roles only; login roles are created per environment (see
-- scripts/create-runtime-login.sh) and granted exactly one of these. None may
-- bypass RLS.
--
--   app_user        tenant requests, under app.tenant_id
--   platform_admin  cross-tenant work (auth path, back office, verifiers),
--                   only with app.platform = 'on'
--   outbox_relay    drains app.outbox_events; reads no tenant table
-- ---------------------------------------------------------------------------
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'platform_admin') THEN
    CREATE ROLE platform_admin NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'outbox_relay') THEN
    CREATE ROLE outbox_relay NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
END
$roles$;

REVOKE ALL ON SCHEMA app FROM PUBLIC;
GRANT USAGE ON SCHEMA app TO app_user, platform_admin, outbox_relay;

-- ---------------------------------------------------------------------------
-- Tenant context. The data service runs every request in a transaction that
-- starts with:
--   SELECT set_config('app.tenant_id', '<uuid>', true);
--   SELECT set_config('app.member_id', '<uuid>', true);
-- Platform work uses a platform_admin login and additionally sets
-- 'app.platform' to 'on'. Both conditions are required, so a leaked setting on
-- an ordinary runtime login grants nothing.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.current_tenant_id() RETURNS uuid
  LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION app.current_member_id() RETURNS uuid
  LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('app.member_id', true), '')::uuid $$;

CREATE OR REPLACE FUNCTION app.is_platform() RETURNS boolean
  LANGUAGE sql STABLE
  AS $$
    SELECT coalesce(current_setting('app.platform', true), '') = 'on'
       AND pg_has_role(current_user, 'platform_admin', 'MEMBER')
  $$;

CREATE OR REPLACE FUNCTION app.touch_updated_at() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
  BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
  END
  $$;

-- ---------------------------------------------------------------------------
-- Outbox. Written in the same transaction as the domain change; drained by the
-- relay into whatever consumes it (a cache, a search index, a realtime store).
-- `version` lets the consumer ignore stale or replayed events.
-- ---------------------------------------------------------------------------
CREATE TABLE app.outbox_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  -- No foreign key: events outlive the tenant they describe.
  tenant_id uuid,
  aggregate text NOT NULL CHECK (length(aggregate) > 0),
  aggregate_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  event_type text NOT NULL CHECK (length(event_type) > 0),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_at timestamptz,
  attempts integer NOT NULL DEFAULT 0,
  last_error text
);
CREATE INDEX outbox_unpublished ON app.outbox_events (id) WHERE published_at IS NULL;
CREATE UNIQUE INDEX outbox_aggregate_version ON app.outbox_events (aggregate, aggregate_id, version);

-- ---------------------------------------------------------------------------
-- Tenancy
-- ---------------------------------------------------------------------------
CREATE TABLE app.tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  -- Platform-controlled: a tenant never writes these.
  plan text NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'team', 'enterprise')),
  suspended_at timestamptz,
  suspension_reason text,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- A member is a person bound to at most one tenant. `subject` is the verified
-- identity-provider subject (the JWT `sub`); a member without a tenant is
-- signed up but not yet onboarded.
CREATE TABLE app.members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid REFERENCES app.tenants (id) ON DELETE RESTRICT,
  subject text UNIQUE CHECK (length(subject) > 0),
  email text NOT NULL UNIQUE CHECK (position('@' IN email) > 1),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  role text NOT NULL DEFAULT 'MEMBER' CHECK (role IN ('ADMIN', 'MANAGER', 'MEMBER')),
  platform_role text CHECK (platform_role IN ('SUPPORT', 'SUPERADMIN')),
  is_active boolean NOT NULL DEFAULT true,
  needs_onboarding boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id, id),
  CHECK (tenant_id IS NOT NULL OR needs_onboarding)
);
CREATE INDEX members_tenant ON app.members (tenant_id);

-- ---------------------------------------------------------------------------
-- Demo domain
-- ---------------------------------------------------------------------------
CREATE TABLE app.projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES app.tenants (id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
  created_by uuid NOT NULL,
  archived_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by) REFERENCES app.members (tenant_id, id),
  CHECK ((status = 'archived') = (archived_at IS NOT NULL))
);
CREATE INDEX projects_tenant ON app.projects (tenant_id, created_at DESC);

CREATE TABLE app.notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  author_id uuid NOT NULL,
  body text NOT NULL CHECK (length(body) BETWEEN 1 AND 10000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (tenant_id, project_id) REFERENCES app.projects (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, author_id) REFERENCES app.members (tenant_id, id)
);
CREATE INDEX notes_project ON app.notes (tenant_id, project_id, created_at);

-- Append-only audit trail. No foreign key on tenant_id: the trail outlives
-- the tenant.
CREATE TABLE app.audit_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid,
  actor_id uuid,
  action text NOT NULL CHECK (length(action) > 0),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX audit_log_tenant ON app.audit_log (tenant_id, created_at DESC);
