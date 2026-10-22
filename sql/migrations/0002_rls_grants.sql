-- 0002 row-level security, grants, timestamps, append-only enforcement.
--
-- Default: a table with a NOT NULL tenant_id gets one tenant policy for
-- app_user and one platform policy for platform_admin, applied by the loop
-- below. Every other table is listed explicitly afterwards. The final block
-- fails the migration if any table in schema app is left without RLS, so a
-- future table cannot ship open by accident.

-- ---------------------------------------------------------------------------
-- Append-only tables: the runtime may insert and read, never change history.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.reject_mutation() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
  BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
      USING ERRCODE = 'insufficient_privilege';
  END
  $$;

CREATE TRIGGER audit_log_append_only
  BEFORE UPDATE OR DELETE ON app.audit_log
  FOR EACH ROW EXECUTE FUNCTION app.reject_mutation();
-- Row triggers do not fire on TRUNCATE; a statement trigger does.
CREATE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON app.audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION app.reject_mutation();

-- updated_at maintenance for every table that has the column.
DO $touch$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT c.table_name
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
    WHERE c.table_schema = 'app' AND c.column_name = 'updated_at'
  LOOP
    EXECUTE format(
      'CREATE TRIGGER %I BEFORE UPDATE ON app.%I FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at()',
      r.table_name || '_touch_updated_at', r.table_name
    );
  END LOOP;
END
$touch$;

-- ---------------------------------------------------------------------------
-- Generic tenant isolation.
-- ---------------------------------------------------------------------------
DO $tenant$
DECLARE
  r record;
  special text[] := ARRAY[
    -- Handled explicitly below.
    'members', 'audit_log', 'outbox_events'
  ];
BEGIN
  FOR r IN
    SELECT c.relname AS table_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
    WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
      AND a.attnotnull
  LOOP
    CONTINUE WHEN r.table_name = ANY (special);
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', r.table_name);
    EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY', r.table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON app.%I FOR ALL TO app_user
         USING (tenant_id = app.current_tenant_id())
         WITH CHECK (tenant_id = app.current_tenant_id())',
      r.table_name
    );
    EXECUTE format(
      'CREATE POLICY platform_access ON app.%I FOR ALL TO platform_admin
         USING (app.is_platform()) WITH CHECK (app.is_platform())',
      r.table_name
    );
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON app.%I TO app_user', r.table_name);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON app.%I TO platform_admin', r.table_name);
  END LOOP;
END
$tenant$;

-- tenants itself: a tenant sees only its own row.
ALTER TABLE app.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_self ON app.tenants FOR ALL TO app_user
  USING (id = app.current_tenant_id()) WITH CHECK (id = app.current_tenant_id());
CREATE POLICY platform_access ON app.tenants FOR ALL TO platform_admin
  USING (app.is_platform()) WITH CHECK (app.is_platform());
GRANT SELECT, UPDATE ON app.tenants TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.tenants TO platform_admin;

-- ---------------------------------------------------------------------------
-- Explicit policies.
-- ---------------------------------------------------------------------------

-- members: own tenant's colleagues, plus the caller's own row.
ALTER TABLE app.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.members FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app.members FOR ALL TO app_user
  USING (tenant_id = app.current_tenant_id() OR id = app.current_member_id())
  WITH CHECK (tenant_id = app.current_tenant_id());
CREATE POLICY platform_access ON app.members FOR ALL TO platform_admin
  USING (app.is_platform()) WITH CHECK (app.is_platform());
GRANT SELECT, INSERT, UPDATE ON app.members TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.members TO platform_admin;

-- Audit log: the runtime appends and reads its own tenant's rows, as itself.
ALTER TABLE app.audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON app.audit_log FOR SELECT TO app_user
  USING (tenant_id = app.current_tenant_id());
CREATE POLICY tenant_append ON app.audit_log FOR INSERT TO app_user
  WITH CHECK (tenant_id = app.current_tenant_id() AND actor_id = app.current_member_id());
CREATE POLICY platform_read ON app.audit_log FOR SELECT TO platform_admin USING (app.is_platform());
CREATE POLICY platform_append ON app.audit_log FOR INSERT TO platform_admin WITH CHECK (app.is_platform());
GRANT SELECT, INSERT ON app.audit_log TO app_user, platform_admin;

-- Outbox: the runtime appends; only the relay reads and marks published.
ALTER TABLE app.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.outbox_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_append ON app.outbox_events FOR INSERT TO app_user
  WITH CHECK (tenant_id IS NULL OR tenant_id = app.current_tenant_id());
CREATE POLICY platform_append ON app.outbox_events FOR INSERT TO platform_admin
  WITH CHECK (app.is_platform());
CREATE POLICY relay_drain ON app.outbox_events FOR ALL TO outbox_relay USING (true) WITH CHECK (true);
GRANT INSERT ON app.outbox_events TO app_user, platform_admin;
GRANT SELECT, UPDATE ON app.outbox_events TO outbox_relay;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user, platform_admin;
GRANT USAGE ON SEQUENCE app.outbox_events_id_seq TO outbox_relay;

-- ---------------------------------------------------------------------------
-- Guard: every table in schema app must have RLS enabled and forced.
-- ---------------------------------------------------------------------------
DO $guard$
DECLARE
  missing text;
BEGIN
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO missing
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
    AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'tables without forced RLS: %', missing;
  END IF;
END
$guard$;
