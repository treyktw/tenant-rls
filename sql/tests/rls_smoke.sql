-- Tenant-isolation smoke test. Runs entirely inside one transaction and rolls
-- back, so it is safe against any database the migrations have been applied
-- to (it needs the owner connection, which has CREATEROLE):
--
--   psql "$OWNER_DATABASE_URL" --no-psqlrc --quiet --set=ON_ERROR_STOP=1 -f sql/tests/rls_smoke.sql
--
-- Each check raises on failure; reaching the final NOTICE means every check
-- passed. Probe roles stand in for the runtime logins: rls_probe_app is a
-- member of app_user exactly as a real app login is, and so on.
BEGIN;

CREATE ROLE rls_probe_app NOLOGIN;
GRANT app_user TO rls_probe_app;
CREATE ROLE rls_probe_platform NOLOGIN;
GRANT platform_admin TO rls_probe_platform;
CREATE ROLE rls_probe_relay NOLOGIN;
GRANT outbox_relay TO rls_probe_relay;
GRANT rls_probe_app, rls_probe_platform, rls_probe_relay TO current_user;

-- ===========================================================================
-- Catalogue checks
-- ===========================================================================

-- 1. Tenant writes are deny-by-default (0004). Every write the runtime role
-- holds must be listed here. Each write path adds its rows (and the checks
-- that exercise its gate) in the same change.
DO $$
DECLARE
  unexpected text;
  missing text;
BEGIN
  WITH actual AS (
    SELECT DISTINCT c.relname AS tbl, a.privilege_type AS priv,
           CASE WHEN att.attacl IS NOT NULL THEN att.attname::text ELSE '*' END AS col
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_attribute att ON att.attrelid = c.oid AND att.attnum > 0 AND NOT att.attisdropped,
    LATERAL aclexplode(coalesce(att.attacl, c.relacl)) a
    WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p')
      AND a.grantee = 'app_user'::regrole
      AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
  ), allowlist (tbl, priv, col) AS (
    -- 0007: tenant rename by ADMIN or MANAGER. Check 13.
    VALUES
      ('tenants'::name, 'UPDATE', 'name'),
      ('tenants'::name, 'UPDATE', 'updated_at'),
      -- 0007: own display name; colleague role by ADMIN. Checks 11-12.
      ('members'::name, 'UPDATE', 'display_name'),
      ('members'::name, 'UPDATE', 'role'),
      ('members'::name, 'UPDATE', 'updated_at'),
      -- 0007: projects. Check 14.
      ('projects'::name, 'INSERT', 'tenant_id'),
      ('projects'::name, 'INSERT', 'name'),
      ('projects'::name, 'INSERT', 'created_by'),
      ('projects'::name, 'UPDATE', 'name'),
      ('projects'::name, 'UPDATE', 'status'),
      ('projects'::name, 'UPDATE', 'archived_at'),
      ('projects'::name, 'UPDATE', 'updated_at'),
      ('projects'::name, 'DELETE', '*'),
      -- 0007: notes. Check 15.
      ('notes'::name, 'INSERT', 'tenant_id'),
      ('notes'::name, 'INSERT', 'project_id'),
      ('notes'::name, 'INSERT', 'author_id'),
      ('notes'::name, 'INSERT', 'body'),
      ('notes'::name, 'UPDATE', 'body'),
      ('notes'::name, 'UPDATE', 'updated_at'),
      ('notes'::name, 'DELETE', '*'),
      -- 0007: audit appends as yourself. Check 18.
      ('audit_log'::name, 'INSERT', 'tenant_id'),
      ('audit_log'::name, 'INSERT', 'actor_id'),
      ('audit_log'::name, 'INSERT', 'action'),
      ('audit_log'::name, 'INSERT', 'detail')
  )
  SELECT string_agg(format('%s.%s(%s)', tbl, priv, col), ', ') INTO unexpected
  FROM (SELECT tbl, priv, col FROM actual EXCEPT SELECT tbl, priv, col FROM allowlist) x;
  IF unexpected IS NOT NULL THEN
    RAISE EXCEPTION 'app_user holds writes not on the allowlist: %', unexpected;
  END IF;
  -- And the other way round: an allowlisted path that is no longer granted
  -- means a check below is testing something that does not exist.
  WITH actual AS (
    SELECT DISTINCT c.relname AS tbl, a.privilege_type AS priv,
           CASE WHEN att.attacl IS NOT NULL THEN att.attname::text ELSE '*' END AS col
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_attribute att ON att.attrelid = c.oid AND att.attnum > 0 AND NOT att.attisdropped,
    LATERAL aclexplode(coalesce(att.attacl, c.relacl)) a
    WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p')
      AND a.grantee = 'app_user'::regrole
      AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
  )
  SELECT string_agg(format('%s.%s', tbl, priv), ', ') INTO missing
  FROM (VALUES ('projects'::name, 'INSERT'), ('notes'::name, 'INSERT'), ('audit_log'::name, 'INSERT'))
       expected (tbl, priv)
  WHERE NOT EXISTS (SELECT 1 FROM actual WHERE actual.tbl = expected.tbl AND actual.priv = expected.priv);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'allowlisted write paths are not granted: %', missing;
  END IF;
END $$;

-- 2. Structure: every table forces RLS; the three group roles cannot log in,
-- are not superusers and cannot bypass RLS; outbox_relay holds no privilege
-- on any tenant table; no runtime group can TRUNCATE anything.
DO $$
DECLARE
  bad text;
BEGIN
  SELECT string_agg(c.relname, ', ') INTO bad
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p')
    AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'tables without forced RLS: %', bad; END IF;

  SELECT string_agg(rolname, ', ') INTO bad
  FROM pg_roles
  WHERE rolname IN ('app_user', 'platform_admin', 'outbox_relay')
    AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb);
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'group roles with dangerous attributes: %', bad; END IF;

  SELECT string_agg(DISTINCT c.relname || '.' || a.privilege_type, ', ') INTO bad
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_attribute att ON att.attrelid = c.oid AND att.attnum > 0 AND NOT att.attisdropped,
  LATERAL aclexplode(coalesce(att.attacl, c.relacl)) a
  WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p') AND c.relname <> 'outbox_events'
    AND a.grantee = 'outbox_relay'::regrole;
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'outbox_relay holds tenant-table privileges: %', bad; END IF;

  SELECT string_agg(DISTINCT c.relname || ' to ' || a.grantee::regrole::text, ', ') INTO bad
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace,
  LATERAL aclexplode(c.relacl) a
  WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p') AND a.privilege_type = 'TRUNCATE'
    AND a.grantee IN ('app_user'::regrole, 'platform_admin'::regrole, 'outbox_relay'::regrole);
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'TRUNCATE granted on: %', bad; END IF;
END $$;

-- ===========================================================================
-- Fixtures. They go in through the platform role: FORCE RLS binds the table
-- owner too, so this is the only path that works everywhere (and the one real
-- platform writes use).
-- ===========================================================================
SET LOCAL ROLE rls_probe_platform;
SELECT set_config('app.platform', 'on', true) \g /dev/null
INSERT INTO app.tenants (id, name, slug) VALUES
  ('00000000-0000-0000-0000-00000000000a', 'Tenant A', 'probe-tenant-a'),
  ('00000000-0000-0000-0000-00000000000b', 'Tenant B', 'probe-tenant-b');
INSERT INTO app.members (id, tenant_id, subject, email, display_name, role) VALUES
  ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000000a', 'user_probe_a1', 'a1@example.test', 'Admin A', 'ADMIN'),
  ('00000000-0000-0000-0000-0000000000a2', '00000000-0000-0000-0000-00000000000a', 'user_probe_a2', 'a2@example.test', 'Member A', 'MEMBER'),
  ('00000000-0000-0000-0000-0000000000a3', '00000000-0000-0000-0000-00000000000a', 'user_probe_a3', 'a3@example.test', 'Manager A', 'MANAGER'),
  ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-00000000000b', 'user_probe_b1', 'b1@example.test', 'Admin B', 'ADMIN');
INSERT INTO app.members (id, subject, email, display_name, needs_onboarding) VALUES
  ('00000000-0000-0000-0000-0000000000c1', 'user_probe_unbound', 'unbound@example.test', 'Unbound', true);
INSERT INTO app.projects (id, tenant_id, name, created_by) VALUES
  ('00000000-0000-0000-0000-0000000000a5', '00000000-0000-0000-0000-00000000000a', 'Project A', '00000000-0000-0000-0000-0000000000a1'),
  ('00000000-0000-0000-0000-0000000000b5', '00000000-0000-0000-0000-00000000000b', 'Project B', '00000000-0000-0000-0000-0000000000b1');
INSERT INTO app.notes (id, tenant_id, project_id, author_id, body) VALUES
  ('00000000-0000-0000-0000-0000000000a6', '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a5', '00000000-0000-0000-0000-0000000000a2', 'Note by Member A'),
  ('00000000-0000-0000-0000-0000000000a7', '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a5', '00000000-0000-0000-0000-0000000000a1', 'Note by Admin A'),
  ('00000000-0000-0000-0000-0000000000b6', '00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-0000000000b5', '00000000-0000-0000-0000-0000000000b1', 'Note by Admin B');
INSERT INTO app.audit_log (tenant_id, actor_id, action) VALUES
  ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a1', 'probe.a'),
  ('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-0000000000b1', 'probe.b');
SELECT set_config('app.platform', '', true) \g /dev/null
RESET ROLE;

-- Tenant-scoped tables and the column that scopes them. tenants scopes by id.
CREATE TEMP TABLE probe_tables (tbl text, scope_col text) ON COMMIT DROP;
INSERT INTO probe_tables VALUES
  ('tenants', 'id'), ('members', 'tenant_id'), ('projects', 'tenant_id'),
  ('notes', 'tenant_id'), ('audit_log', 'tenant_id');
GRANT SELECT ON probe_tables TO rls_probe_app, rls_probe_platform, rls_probe_relay;

-- ===========================================================================
-- Reads: every table x every role
-- ===========================================================================

-- 3. No tenant context: zero rows in every tenant table.
SET LOCAL ROLE rls_probe_app;
DO $$
DECLARE
  r record;
  n bigint;
BEGIN
  FOR r IN SELECT * FROM probe_tables LOOP
    EXECUTE format('SELECT count(*) FROM app.%I', r.tbl) INTO n;
    IF n <> 0 THEN RAISE EXCEPTION 'no-context read of % leaked % rows', r.tbl, n; END IF;
  END LOOP;
END $$;

-- 4. Tenant A sees only its own rows, in every table, without a WHERE clause.
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000a', true) \g /dev/null
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a1', true) \g /dev/null
DO $$
DECLARE
  r record;
  foreign_rows bigint;
  own_rows bigint;
BEGIN
  FOR r IN SELECT * FROM probe_tables LOOP
    EXECUTE format('SELECT count(*) FILTER (WHERE %1$I <> %2$L), count(*) FILTER (WHERE %1$I = %2$L) FROM app.%3$I',
                   r.scope_col, '00000000-0000-0000-0000-00000000000a', r.tbl)
      INTO foreign_rows, own_rows;
    IF foreign_rows <> 0 THEN RAISE EXCEPTION 'tenant A saw % foreign rows in %', foreign_rows, r.tbl; END IF;
    IF own_rows = 0 THEN RAISE EXCEPTION 'tenant A saw none of its own rows in %', r.tbl; END IF;
  END LOOP;
  IF (SELECT count(*) FROM app.tenants) <> 1 THEN RAISE EXCEPTION 'tenant A should see only its tenant row'; END IF;
  IF (SELECT count(*) FROM app.members) <> 3 THEN RAISE EXCEPTION 'tenant A should see exactly its 3 members'; END IF;
  IF (SELECT count(*) FROM app.notes) <> 2 THEN RAISE EXCEPTION 'tenant A should see exactly its 2 notes'; END IF;
  -- Asking for B's rows by id finds nothing: RLS, not the WHERE clause.
  IF EXISTS (SELECT 1 FROM app.projects WHERE id = '00000000-0000-0000-0000-0000000000b5')
     OR EXISTS (SELECT 1 FROM app.notes WHERE id = '00000000-0000-0000-0000-0000000000b6')
     OR EXISTS (SELECT 1 FROM app.members WHERE id = '00000000-0000-0000-0000-0000000000b1')
     OR EXISTS (SELECT 1 FROM app.tenants WHERE id = '00000000-0000-0000-0000-00000000000b') THEN
    RAISE EXCEPTION 'tenant A found a tenant B row by id';
  END IF;
  -- The unbound member is invisible too.
  IF EXISTS (SELECT 1 FROM app.members WHERE id = '00000000-0000-0000-0000-0000000000c1') THEN
    RAISE EXCEPTION 'tenant A saw an unbound member';
  END IF;
END $$;

-- 5. A member id with no tenant sees only that member's own row; a tenant id
-- that does not exist sees nothing.
SELECT set_config('app.tenant_id', '', true) \g /dev/null
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000c1', true) \g /dev/null
DO $$ BEGIN
  IF (SELECT count(*) FROM app.members) <> 1 THEN RAISE EXCEPTION 'unbound member should see only itself'; END IF;
  IF (SELECT count(*) FROM app.projects) + (SELECT count(*) FROM app.notes) + (SELECT count(*) FROM app.tenants) <> 0 THEN
    RAISE EXCEPTION 'unbound member saw tenant data';
  END IF;
END $$;
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-0000000000ff', true) \g /dev/null
SELECT set_config('app.member_id', '', true) \g /dev/null
DO $$
DECLARE
  r record;
  n bigint;
BEGIN
  FOR r IN SELECT * FROM probe_tables LOOP
    EXECUTE format('SELECT count(*) FROM app.%I', r.tbl) INTO n;
    IF n <> 0 THEN RAISE EXCEPTION 'unknown tenant read % rows from %', n, r.tbl; END IF;
  END LOOP;
END $$;

-- 6. Claiming platform without the platform role grants nothing.
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000a', true) \g /dev/null
SELECT set_config('app.platform', 'on', true) \g /dev/null
DO $$ BEGIN
  IF app.is_platform() THEN RAISE EXCEPTION 'runtime role passed is_platform()'; END IF;
  IF (SELECT count(*) FROM app.projects) <> 1 THEN RAISE EXCEPTION 'platform flag widened tenant access'; END IF;
END $$;
SELECT set_config('app.platform', '', true) \g /dev/null
RESET ROLE;

-- 7. Platform role with the flag sees every tenant, in every table; without
-- the flag it sees nothing, even with a tenant bound.
SET LOCAL ROLE rls_probe_platform;
SELECT set_config('app.platform', 'on', true) \g /dev/null
DO $$
DECLARE
  r record;
  n bigint;
BEGIN
  IF NOT app.is_platform() THEN RAISE EXCEPTION 'platform role failed is_platform()'; END IF;
  FOR r IN SELECT * FROM probe_tables LOOP
    -- Scoped to the probe tenants: a dev database holds other rows too.
    EXECUTE format('SELECT count(DISTINCT %I) FROM app.%I WHERE %I IN (%L, %L)',
                   r.scope_col, r.tbl, r.scope_col,
                   '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b') INTO n;
    IF n <> 2 THEN RAISE EXCEPTION 'platform should see both tenants in %, saw %', r.tbl, n; END IF;
  END LOOP;
END $$;
SELECT set_config('app.platform', '', true) \g /dev/null
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000a', true) \g /dev/null
DO $$
DECLARE
  r record;
  n bigint;
BEGIN
  FOR r IN SELECT * FROM probe_tables LOOP
    EXECUTE format('SELECT count(*) FROM app.%I', r.tbl) INTO n;
    IF n <> 0 THEN RAISE EXCEPTION 'platform role without the flag read % rows from %', n, r.tbl; END IF;
  END LOOP;
  -- Nor can it write without the flag.
  BEGIN
    INSERT INTO app.projects (tenant_id, name, created_by)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'Flagless', '00000000-0000-0000-0000-0000000000a1');
    RAISE EXCEPTION 'platform role wrote without the flag';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
SELECT set_config('app.tenant_id', '', true) \g /dev/null
RESET ROLE;

-- 8. The relay reads no tenant table at all, whatever settings it carries.
SET LOCAL ROLE rls_probe_relay;
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000a', true) \g /dev/null
SELECT set_config('app.platform', 'on', true) \g /dev/null
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT * FROM probe_tables LOOP
    BEGIN
      EXECUTE format('SELECT 1 FROM app.%I LIMIT 1', r.tbl);
      RAISE EXCEPTION 'relay read %', r.tbl;
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
  END LOOP;
END $$;
SELECT set_config('app.tenant_id', '', true) \g /dev/null
SELECT set_config('app.platform', '', true) \g /dev/null
RESET ROLE;

-- ===========================================================================
-- Cross-tenant writes: every table, every verb
-- ===========================================================================

-- 9. Tenant A, as its ADMIN (the most privileged tenant caller), cannot
-- insert into, update, or delete from tenant B in any table. Inserts fail
-- loudly; updates and deletes match zero rows because B's rows are invisible.
SET LOCAL ROLE rls_probe_app;
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000a', true) \g /dev/null
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a1', true) \g /dev/null
DO $$
DECLARE
  n integer;
BEGIN
  -- Inserts naming tenant B.
  BEGIN
    INSERT INTO app.projects (tenant_id, name, created_by)
    VALUES ('00000000-0000-0000-0000-00000000000b', 'Planted', '00000000-0000-0000-0000-0000000000a1');
    RAISE EXCEPTION 'cross-tenant project insert succeeded';
  EXCEPTION WHEN insufficient_privilege OR foreign_key_violation THEN NULL;
  END;
  BEGIN
    INSERT INTO app.notes (tenant_id, project_id, author_id, body)
    VALUES ('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-0000000000b5',
            '00000000-0000-0000-0000-0000000000a1', 'Planted');
    RAISE EXCEPTION 'cross-tenant note insert succeeded';
  EXCEPTION WHEN insufficient_privilege OR foreign_key_violation THEN NULL;
  END;
  BEGIN
    INSERT INTO app.audit_log (tenant_id, actor_id, action)
    VALUES ('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-0000000000a1', 'planted');
    RAISE EXCEPTION 'cross-tenant audit insert succeeded';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- Updates of tenant B rows.
  UPDATE app.tenants SET name = 'Hijacked' WHERE id = '00000000-0000-0000-0000-00000000000b';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'tenant A renamed tenant B'; END IF;
  UPDATE app.members SET display_name = 'Hijacked' WHERE id = '00000000-0000-0000-0000-0000000000b1';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'tenant A renamed a tenant B member'; END IF;
  UPDATE app.projects SET name = 'Hijacked' WHERE id = '00000000-0000-0000-0000-0000000000b5';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'tenant A renamed a tenant B project'; END IF;
  UPDATE app.notes SET body = 'Hijacked' WHERE id = '00000000-0000-0000-0000-0000000000b6';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'tenant A edited a tenant B note'; END IF;

  -- Moving its own rows into tenant B.
  BEGIN
    UPDATE app.projects SET tenant_id = '00000000-0000-0000-0000-00000000000b'
    WHERE id = '00000000-0000-0000-0000-0000000000a5';
    RAISE EXCEPTION 'tenant A moved a project into tenant B';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.members SET tenant_id = '00000000-0000-0000-0000-00000000000b'
    WHERE id = '00000000-0000-0000-0000-0000000000a2';
    RAISE EXCEPTION 'tenant A moved a member into tenant B';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- Deletes of tenant B rows.
  DELETE FROM app.projects WHERE id = '00000000-0000-0000-0000-0000000000b5';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'tenant A deleted a tenant B project'; END IF;
  DELETE FROM app.notes WHERE id = '00000000-0000-0000-0000-0000000000b6';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'tenant A deleted a tenant B note'; END IF;
  -- Unscoped deletes touch only tenant A (and are rolled back here).
  BEGIN
    DELETE FROM app.tenants;
    RAISE EXCEPTION 'tenant deleted a tenant row';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    DELETE FROM app.members;
    RAISE EXCEPTION 'tenant deleted members';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
RESET ROLE;

-- 10. A child row cannot point at another tenant's parent, even for a writer
-- RLS does not restrict: the composite foreign keys hold on their own.
SET LOCAL ROLE rls_probe_platform;
SELECT set_config('app.platform', 'on', true) \g /dev/null
DO $$ BEGIN
  BEGIN
    INSERT INTO app.notes (tenant_id, project_id, author_id, body)
    VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000b5',
            '00000000-0000-0000-0000-0000000000a1', 'cross-tenant parent');
    RAISE EXCEPTION 'composite FK allowed a note on another tenant''s project';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
  BEGIN
    INSERT INTO app.notes (tenant_id, project_id, author_id, body)
    VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a5',
            '00000000-0000-0000-0000-0000000000b1', 'cross-tenant author');
    RAISE EXCEPTION 'composite FK allowed a note by another tenant''s member';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
  BEGIN
    INSERT INTO app.projects (tenant_id, name, created_by)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'Foreign creator', '00000000-0000-0000-0000-0000000000b1');
    RAISE EXCEPTION 'composite FK allowed a project created by another tenant''s member';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
END $$;
SELECT set_config('app.platform', '', true) \g /dev/null
RESET ROLE;

-- ===========================================================================
-- Rows a tenant must not write even for itself
-- ===========================================================================

-- 11. Identity bindings belong to the auth path (0003). Even an ADMIN cannot
-- create a member (that would bind someone's subject into the tenant) or
-- rewrite subject, email, tenant, platform role or activation.
SET LOCAL ROLE rls_probe_app;
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000a', true) \g /dev/null
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a1', true) \g /dev/null
DO $$ BEGIN
  BEGIN
    INSERT INTO app.members (tenant_id, subject, email, display_name)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'user_victim', 'victim@example.test', 'Victim');
    RAISE EXCEPTION 'tenant bound an identity by inserting a member';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.members SET subject = 'user_victim' WHERE id = '00000000-0000-0000-0000-0000000000a2';
    RAISE EXCEPTION 'tenant rebound a subject';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.members SET email = 'takeover@example.test' WHERE id = '00000000-0000-0000-0000-0000000000a2';
    RAISE EXCEPTION 'tenant rewrote an email';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.members SET platform_role = 'SUPERADMIN' WHERE id = '00000000-0000-0000-0000-0000000000a1';
    RAISE EXCEPTION 'tenant granted a platform role';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.members SET is_active = false WHERE id = '00000000-0000-0000-0000-0000000000a2';
    RAISE EXCEPTION 'tenant deactivated a member outside the platform path';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    DELETE FROM app.members WHERE id = '00000000-0000-0000-0000-0000000000a2';
    RAISE EXCEPTION 'tenant deleted a member';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;

-- 12. Authority changes need an ADMIN (0003). A MEMBER may edit only their
-- own display name.
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a2', true) \g /dev/null
DO $$ BEGIN
  BEGIN
    UPDATE app.members SET role = 'ADMIN' WHERE id = '00000000-0000-0000-0000-0000000000a2';
    RAISE EXCEPTION 'member promoted itself';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.members SET display_name = 'Renamed by a colleague' WHERE id = '00000000-0000-0000-0000-0000000000a1';
    RAISE EXCEPTION 'member renamed a colleague';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  UPDATE app.members SET display_name = 'Member A Renamed' WHERE id = '00000000-0000-0000-0000-0000000000a2';
  IF NOT FOUND THEN RAISE EXCEPTION 'member could not edit its own display name'; END IF;
END $$;
-- A MANAGER cannot change roles either.
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a3', true) \g /dev/null
DO $$ BEGIN
  BEGIN
    UPDATE app.members SET role = 'MANAGER' WHERE id = '00000000-0000-0000-0000-0000000000a2';
    RAISE EXCEPTION 'manager changed a role';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
-- An ADMIN can, but never leaves the tenant without an ADMIN.
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a1', true) \g /dev/null
DO $$ BEGIN
  UPDATE app.members SET role = 'MANAGER' WHERE id = '00000000-0000-0000-0000-0000000000a2';
  IF NOT FOUND THEN RAISE EXCEPTION 'admin could not change a colleague role'; END IF;
  BEGIN
    UPDATE app.members SET role = 'MEMBER' WHERE id = '00000000-0000-0000-0000-0000000000a1';
    RAISE EXCEPTION 'the last admin demoted itself';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  UPDATE app.members SET role = 'MEMBER' WHERE id = '00000000-0000-0000-0000-0000000000a2';
END $$;

-- 13. The tenant row: an ADMIN or MANAGER renames it; a MEMBER cannot;
-- nobody in the tenant touches plan, suspension or deletion.
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a2', true) \g /dev/null
DO $$ BEGIN
  UPDATE app.tenants SET name = 'Member Rename' WHERE id = '00000000-0000-0000-0000-00000000000a';
  IF FOUND THEN RAISE EXCEPTION 'member renamed the tenant'; END IF;
END $$;
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a3', true) \g /dev/null
DO $$ BEGIN
  UPDATE app.tenants SET name = 'Tenant A Renamed' WHERE id = '00000000-0000-0000-0000-00000000000a';
  IF NOT FOUND THEN RAISE EXCEPTION 'manager could not rename the tenant'; END IF;
END $$;
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a1', true) \g /dev/null
DO $$ BEGIN
  BEGIN
    UPDATE app.tenants SET plan = 'enterprise';
    RAISE EXCEPTION 'tenant upgraded its own plan';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.tenants SET suspended_at = NULL, suspension_reason = NULL;
    RAISE EXCEPTION 'tenant changed its suspension';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.tenants SET slug = 'taken-over';
    RAISE EXCEPTION 'tenant changed its slug';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    INSERT INTO app.tenants (name, slug) VALUES ('Self-made', 'self-made');
    RAISE EXCEPTION 'tenant created a tenant';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;

-- 14. Projects (0003, 0007): created as yourself and active; archived,
-- restored and deleted by a MANAGER or ADMIN; created_by is write-once.
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a2', true) \g /dev/null
DO $$
DECLARE
  n integer;
  pid uuid;
BEGIN
  -- The tenant cannot choose ids: only the granted columns are insertable.
  BEGIN
    INSERT INTO app.projects (id, tenant_id, name, created_by)
    VALUES (gen_random_uuid(), '00000000-0000-0000-0000-00000000000a', 'Chosen id', '00000000-0000-0000-0000-0000000000a2');
    RAISE EXCEPTION 'member chose a project id';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    INSERT INTO app.projects (tenant_id, name, created_by)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'Spoofed', '00000000-0000-0000-0000-0000000000a1');
    RAISE EXCEPTION 'member created a project as a colleague';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    INSERT INTO app.projects (tenant_id, name, created_by, status, archived_at)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'Born archived', '00000000-0000-0000-0000-0000000000a2', 'archived', now());
    RAISE EXCEPTION 'member set status at insert';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  INSERT INTO app.projects (tenant_id, name, created_by)
  VALUES ('00000000-0000-0000-0000-00000000000a', 'Member project', '00000000-0000-0000-0000-0000000000a2')
  RETURNING id INTO pid;
  PERFORM set_config('probe.project14', pid::text, true);
  UPDATE app.projects SET name = 'Member project renamed' WHERE id = pid;
  IF NOT FOUND THEN RAISE EXCEPTION 'member could not rename a project'; END IF;
  BEGIN
    UPDATE app.projects SET status = 'archived', archived_at = now() WHERE id = pid;
    RAISE EXCEPTION 'member archived a project';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.projects SET created_by = '00000000-0000-0000-0000-0000000000a1' WHERE id = pid;
    RAISE EXCEPTION 'member rewrote created_by';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  DELETE FROM app.projects WHERE id = pid;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'member deleted a project'; END IF;
END $$;
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a3', true) \g /dev/null
DO $$
DECLARE
  n integer;
  pid uuid := current_setting('probe.project14')::uuid;
BEGIN
  UPDATE app.projects SET status = 'archived', archived_at = now() WHERE id = pid;
  IF NOT FOUND THEN RAISE EXCEPTION 'manager could not archive a project'; END IF;
  BEGIN
    UPDATE app.projects SET created_by = '00000000-0000-0000-0000-0000000000a3' WHERE id = pid;
    RAISE EXCEPTION 'manager rewrote created_by';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  DELETE FROM app.projects WHERE id = pid;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN RAISE EXCEPTION 'manager could not delete a project'; END IF;
END $$;

-- 15. Notes (0003, 0007): written as yourself on an active project, edited
-- only by their author, deleted by their author or an ADMIN.
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a2', true) \g /dev/null
DO $$
DECLARE
  n integer;
BEGIN
  BEGIN
    INSERT INTO app.notes (tenant_id, project_id, author_id, body)
    VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a5',
            '00000000-0000-0000-0000-0000000000a1', 'Spoofed author');
    RAISE EXCEPTION 'member wrote a note as a colleague';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  INSERT INTO app.notes (tenant_id, project_id, author_id, body)
  VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a5',
          '00000000-0000-0000-0000-0000000000a2', 'Second note by Member A');
  UPDATE app.notes SET body = 'Edited own note' WHERE id = '00000000-0000-0000-0000-0000000000a6';
  IF NOT FOUND THEN RAISE EXCEPTION 'member could not edit its own note'; END IF;
  UPDATE app.notes SET body = 'Edited colleague note' WHERE id = '00000000-0000-0000-0000-0000000000a7';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'member edited a colleague''s note'; END IF;
  BEGIN
    UPDATE app.notes SET author_id = '00000000-0000-0000-0000-0000000000a1' WHERE id = '00000000-0000-0000-0000-0000000000a6';
    RAISE EXCEPTION 'member reassigned a note''s author';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  DELETE FROM app.notes WHERE id = '00000000-0000-0000-0000-0000000000a7';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'member deleted a colleague''s note'; END IF;
END $$;
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a1', true) \g /dev/null
DO $$
DECLARE
  n integer;
BEGIN
  -- Archive the project: its notes become read-only.
  UPDATE app.projects SET status = 'archived', archived_at = now() WHERE id = '00000000-0000-0000-0000-0000000000a5';
  BEGIN
    INSERT INTO app.notes (tenant_id, project_id, author_id, body)
    VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a5',
            '00000000-0000-0000-0000-0000000000a1', 'On an archived project');
    RAISE EXCEPTION 'note written on an archived project';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.notes SET body = 'Edited on archived' WHERE id = '00000000-0000-0000-0000-0000000000a7';
    RAISE EXCEPTION 'note edited on an archived project';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  UPDATE app.projects SET status = 'active', archived_at = NULL WHERE id = '00000000-0000-0000-0000-0000000000a5';
  -- An ADMIN deletes anyone's note.
  DELETE FROM app.notes WHERE id = '00000000-0000-0000-0000-0000000000a6';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN RAISE EXCEPTION 'admin could not delete a member''s note'; END IF;
END $$;
RESET ROLE;

-- ===========================================================================
-- Resolving the caller (0005)
-- ===========================================================================

-- 16. The subject reveals the caller's own member row and nothing else. The
-- data service sets app.subject from a verified session, reads that row to
-- learn its tenant, then binds app.tenant_id and clears app.subject.
SET LOCAL ROLE rls_probe_app;
SELECT set_config('app.tenant_id', '', true) \g /dev/null
SELECT set_config('app.member_id', '', true) \g /dev/null
SELECT set_config('app.subject', 'user_probe_a1', true) \g /dev/null
DO $$ BEGIN
  IF (SELECT count(*) FROM app.members) <> 1 THEN RAISE EXCEPTION 'subject should reveal exactly its own row'; END IF;
  IF (SELECT id FROM app.members) <> '00000000-0000-0000-0000-0000000000a1' THEN
    RAISE EXCEPTION 'subject revealed the wrong member';
  END IF;
  -- The subject alone is not a tenant: no colleagues, no tenant row, no data.
  IF (SELECT count(*) FROM app.tenants) <> 0 THEN RAISE EXCEPTION 'subject exposed a tenant'; END IF;
  IF (SELECT count(*) FROM app.projects) <> 0 THEN RAISE EXCEPTION 'subject exposed tenant rows'; END IF;
END $$;
SELECT set_config('app.subject', 'user_probe_unbound', true) \g /dev/null
DO $$ BEGIN
  IF (SELECT tenant_id FROM app.members) IS NOT NULL OR (SELECT count(*) FROM app.members) <> 1 THEN
    RAISE EXCEPTION 'unbound subject should reveal its own tenantless row';
  END IF;
END $$;
SELECT set_config('app.subject', 'user_probe_nobody', true) \g /dev/null
DO $$ BEGIN
  IF (SELECT count(*) FROM app.members) <> 0 THEN RAISE EXCEPTION 'unknown subject revealed a member'; END IF;
END $$;
SELECT set_config('app.subject', '', true) \g /dev/null
DO $$ BEGIN
  IF (SELECT count(*) FROM app.members) <> 0 THEN RAISE EXCEPTION 'empty subject matched a member'; END IF;
END $$;
-- The binding read is SELECT only. Even on a granted column, the subject
-- alone makes no row updatable.
SELECT set_config('app.subject', 'user_probe_a1', true) \g /dev/null
DO $$
DECLARE
  n integer;
BEGIN
  UPDATE app.members SET display_name = 'Rebound' WHERE subject = 'user_probe_a1';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'subject read allowed a write'; END IF;
END $$;
SELECT set_config('app.subject', '', true) \g /dev/null
RESET ROLE;

-- ===========================================================================
-- Outbox and audit
-- ===========================================================================

-- 17. Events come from the rows (0006): the tenant cannot emit one itself;
-- every write above produced an event with a sequence-drawn version; a change
-- that alters no payload field emits nothing; the relay drains the outbox.
SET LOCAL ROLE rls_probe_app;
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000a', true) \g /dev/null
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a1', true) \g /dev/null
DO $$ BEGIN
  BEGIN
    INSERT INTO app.outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'member', '00000000-0000-0000-0000-0000000000a2',
            'member.upserted', '{"role": "ADMIN"}');
    RAISE EXCEPTION 'tenant forged an outbox event';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM 1 FROM app.outbox_events;
    RAISE EXCEPTION 'tenant read the outbox';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  -- A bare updated_at bump changes no payload field.
  UPDATE app.projects SET updated_at = now() WHERE id = '00000000-0000-0000-0000-0000000000a5';
END $$;
RESET ROLE;
SET LOCAL ROLE rls_probe_relay;
DO $$
DECLARE
  n integer;
  v1 bigint;
  v2 bigint;
BEGIN
  -- Project A: created, archived, restored (check 15). The updated_at bump
  -- just now added nothing.
  SELECT count(*), min(version), max(version) INTO n, v1, v2 FROM app.outbox_events
  WHERE aggregate = 'project' AND aggregate_id = '00000000-0000-0000-0000-0000000000a5';
  IF n <> 3 OR v2 <= v1 THEN RAISE EXCEPTION 'project events wrong: % events, versions % to %', n, v1, v2; END IF;
  IF (SELECT payload->>'status' FROM app.outbox_events
      WHERE aggregate = 'project' AND aggregate_id = '00000000-0000-0000-0000-0000000000a5'
      ORDER BY version DESC LIMIT 1) <> 'active' THEN
    RAISE EXCEPTION 'latest project event does not carry the row as written';
  END IF;
  -- The member role change by the ADMIN (check 12) emitted MANAGER then MEMBER.
  SELECT count(*) INTO n FROM app.outbox_events
  WHERE aggregate = 'member' AND aggregate_id = '00000000-0000-0000-0000-0000000000a2' AND payload->>'role' = 'MANAGER';
  IF n <> 1 THEN RAISE EXCEPTION 'a role change emitted no event'; END IF;
  -- Deleting a note emitted note.deleted, scoped to its tenant.
  IF NOT EXISTS (SELECT 1 FROM app.outbox_events
                 WHERE aggregate = 'note' AND aggregate_id = '00000000-0000-0000-0000-0000000000a6'
                   AND event_type = 'note.deleted' AND tenant_id = '00000000-0000-0000-0000-00000000000a') THEN
    RAISE EXCEPTION 'deleting a note emitted no note.deleted event';
  END IF;
  -- The relay claims and marks events published.
  PERFORM 1 FROM app.outbox_events WHERE published_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED;
  UPDATE app.outbox_events SET published_at = now(), attempts = attempts + 1
  WHERE tenant_id IN ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b');
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n = 0 THEN RAISE EXCEPTION 'relay could not mark events published'; END IF;
END $$;
RESET ROLE;

-- 18. The audit log: a tenant appends as itself, into its own tenant only,
-- and no role (tenant, platform, relay, or the owner through the trigger)
-- can update, delete or truncate it.
SET LOCAL ROLE rls_probe_app;
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000a', true) \g /dev/null
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000a2', true) \g /dev/null
DO $$ BEGIN
  INSERT INTO app.audit_log (tenant_id, actor_id, action)
  VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a2', 'probe.self');
  BEGIN
    INSERT INTO app.audit_log (tenant_id, actor_id, action)
    VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a1', 'probe.forged');
    RAISE EXCEPTION 'tenant appended an audit row as a colleague';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE app.audit_log SET action = 'tampered';
    RAISE EXCEPTION 'tenant updated the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    DELETE FROM app.audit_log;
    RAISE EXCEPTION 'tenant deleted from the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    TRUNCATE app.audit_log;
    RAISE EXCEPTION 'tenant truncated the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
RESET ROLE;
SET LOCAL ROLE rls_probe_platform;
SELECT set_config('app.platform', 'on', true) \g /dev/null
DO $$ BEGIN
  BEGIN
    UPDATE app.audit_log SET action = 'tampered' WHERE action LIKE 'probe.%';
    RAISE EXCEPTION 'platform updated the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    DELETE FROM app.audit_log WHERE action LIKE 'probe.%';
    RAISE EXCEPTION 'platform deleted from the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    TRUNCATE app.audit_log;
    RAISE EXCEPTION 'platform truncated the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
SELECT set_config('app.platform', '', true) \g /dev/null
RESET ROLE;
-- The owner holds every privilege. FORCE RLS already hides every row from it
-- (no policy names it), so an UPDATE matches nothing. Some managed providers
-- give the owner BYPASSRLS, though; lift FORCE here (rolled back with the
-- rest) to stand in for that, and the trigger still refuses.
DO $$
DECLARE
  n integer;
BEGIN
  UPDATE app.audit_log SET action = 'tampered';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'owner updated the audit log under FORCE RLS'; END IF;
  BEGIN
    TRUNCATE app.audit_log;
    RAISE EXCEPTION 'owner truncated the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
SAVEPOINT owner_bypass;
ALTER TABLE app.audit_log NO FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF (SELECT count(*) FROM app.audit_log WHERE action LIKE 'probe.%') = 0 THEN
    RAISE EXCEPTION 'owner without FORCE should see the audit rows';
  END IF;
  BEGIN
    UPDATE app.audit_log SET action = 'tampered' WHERE action LIKE 'probe.%';
    RAISE EXCEPTION 'owner bypassing RLS updated the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    DELETE FROM app.audit_log WHERE action LIKE 'probe.%';
    RAISE EXCEPTION 'owner bypassing RLS deleted from the audit log';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $$;
ROLLBACK TO SAVEPOINT owner_bypass;

-- 19. Tenant B, symmetrically: everything check 4 and 9 proved for A holds
-- from the other side, after all the writes above.
SET LOCAL ROLE rls_probe_app;
SELECT set_config('app.tenant_id', '00000000-0000-0000-0000-00000000000b', true) \g /dev/null
SELECT set_config('app.member_id', '00000000-0000-0000-0000-0000000000b1', true) \g /dev/null
DO $$
DECLARE
  r record;
  foreign_rows bigint;
  n integer;
BEGIN
  FOR r IN SELECT * FROM probe_tables LOOP
    EXECUTE format('SELECT count(*) FILTER (WHERE %1$I <> %2$L) FROM app.%3$I',
                   r.scope_col, '00000000-0000-0000-0000-00000000000b', r.tbl) INTO foreign_rows;
    IF foreign_rows <> 0 THEN RAISE EXCEPTION 'tenant B saw % foreign rows in %', foreign_rows, r.tbl; END IF;
  END LOOP;
  IF (SELECT name FROM app.tenants) <> 'Tenant B' THEN RAISE EXCEPTION 'tenant B row was changed from tenant A'; END IF;
  IF (SELECT body FROM app.notes) <> 'Note by Admin B' THEN RAISE EXCEPTION 'tenant B note was changed from tenant A'; END IF;
  UPDATE app.notes SET body = 'Hijacked' WHERE id = '00000000-0000-0000-0000-0000000000a7';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'tenant B edited a tenant A note'; END IF;
  DELETE FROM app.projects WHERE id = '00000000-0000-0000-0000-0000000000a5';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN RAISE EXCEPTION 'tenant B deleted a tenant A project'; END IF;
END $$;
RESET ROLE;

DO $$ BEGIN RAISE NOTICE 'rls_smoke: all 19 checks passed'; END $$;
ROLLBACK;
