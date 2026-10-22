-- 0003 tenant write limits and privilege gates.
--
-- 0002 gave app_user full read/write on every tenant table. RLS keeps a
-- tenant inside its own rows, but some rows a tenant must not be able to
-- write even for itself: billing state, suspension, identity bindings, and
-- anything that grants authority. Those writes belong to platform paths
-- (billing webhooks, the back office, the auth path), which run as
-- platform_admin.
--
-- Rule after this migration: a write that grants or changes authority needs
-- the calling member to be an active ADMIN of the current tenant, on INSERT,
-- UPDATE and DELETE alike. Platform paths (platform_admin with app.platform
-- on) are unaffected. The gates are policies, triggers and constraints, so
-- they keep applying when 0004 revokes everything and later migrations grant
-- write paths back one at a time.

-- The caller's tenant role, read from their own row (RLS lets a member see it).
CREATE OR REPLACE FUNCTION app.caller_role() RETURNS text
  LANGUAGE sql STABLE
  AS $$
    SELECT role FROM app.members
    WHERE id = app.current_member_id()
      AND tenant_id = app.current_tenant_id()
      AND is_active
  $$;

-- ---------------------------------------------------------------------------
-- tenants: plan, suspension and deletion stay platform-controlled.
-- ---------------------------------------------------------------------------
REVOKE UPDATE ON app.tenants FROM app_user;
GRANT UPDATE (name, updated_at) ON app.tenants TO app_user;
CREATE POLICY tenant_manager_update ON app.tenants AS RESTRICTIVE FOR UPDATE TO app_user
  USING (app.caller_role() IN ('ADMIN', 'MANAGER'))
  WITH CHECK (app.caller_role() IN ('ADMIN', 'MANAGER'));

-- ---------------------------------------------------------------------------
-- members: creating a member binds a verified identity-provider subject to a
-- tenant, so it runs only on the auth path (platform_admin, after verifying
-- the session server-side). A tenant could otherwise pre-bind someone else's
-- subject into its own tenant before that person signed up.
-- subject, email, tenant_id, platform_role and is_active are never
-- tenant-writable.
-- ---------------------------------------------------------------------------
REVOKE INSERT, UPDATE ON app.members FROM app_user;
GRANT UPDATE (display_name, role, updated_at) ON app.members TO app_user;

-- A policy cannot see OLD, so a trigger compares the authority columns.
CREATE OR REPLACE FUNCTION app.gate_authority_change() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
  DECLARE
    caller_is_admin boolean;
    changed boolean;
  BEGIN
    IF app.is_platform() OR NOT pg_has_role(current_user, 'app_user', 'MEMBER') THEN
      RETURN NEW;
    END IF;

    caller_is_admin := app.caller_role() IS NOT DISTINCT FROM 'ADMIN';

    -- A non-admin may touch only their own row, and never its authority.
    IF NOT caller_is_admin AND NEW.id IS DISTINCT FROM app.current_member_id() THEN
      RAISE EXCEPTION 'only a tenant ADMIN may change another member'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    changed := (NEW.role, NEW.platform_role, NEW.is_active, NEW.tenant_id, NEW.subject)
               IS DISTINCT FROM (OLD.role, OLD.platform_role, OLD.is_active, OLD.tenant_id, OLD.subject);
    IF changed AND NOT caller_is_admin THEN
      RAISE EXCEPTION 'only a tenant ADMIN may change member authority'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- An admin cannot demote the tenant's last admin (themselves included).
    IF changed AND OLD.role = 'ADMIN' AND NEW.role IS DISTINCT FROM 'ADMIN' AND NOT EXISTS (
         SELECT 1 FROM app.members
         WHERE tenant_id = OLD.tenant_id AND role = 'ADMIN' AND is_active AND id <> OLD.id) THEN
      RAISE EXCEPTION 'a tenant must keep at least one ADMIN'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END
  $$;

CREATE TRIGGER members_gate_authority
  BEFORE UPDATE ON app.members
  FOR EACH ROW EXECUTE FUNCTION app.gate_authority_change();

-- ---------------------------------------------------------------------------
-- projects: anyone creates, as themselves; archiving and deleting are for
-- MANAGER and ADMIN. created_by is set at insert and never rewritten.
-- ---------------------------------------------------------------------------
CREATE POLICY tenant_create_as_self ON app.projects AS RESTRICTIVE FOR INSERT TO app_user
  WITH CHECK (created_by = app.current_member_id() AND status = 'active');
CREATE POLICY tenant_manager_delete ON app.projects AS RESTRICTIVE FOR DELETE TO app_user
  USING (app.caller_role() IN ('ADMIN', 'MANAGER'));

CREATE OR REPLACE FUNCTION app.gate_project_change() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
  BEGIN
    IF app.is_platform() OR NOT pg_has_role(current_user, 'app_user', 'MEMBER') THEN
      RETURN NEW;
    END IF;
    IF NEW.created_by IS DISTINCT FROM OLD.created_by THEN
      RAISE EXCEPTION 'created_by is write-once'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status
       AND app.caller_role() IS DISTINCT FROM 'ADMIN'
       AND app.caller_role() IS DISTINCT FROM 'MANAGER' THEN
      RAISE EXCEPTION 'only a MANAGER or ADMIN may archive or restore a project'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END
  $$;

CREATE TRIGGER projects_gate_change
  BEFORE UPDATE ON app.projects
  FOR EACH ROW EXECUTE FUNCTION app.gate_project_change();

-- ---------------------------------------------------------------------------
-- notes: written as yourself, edited only by their author, deleted by their
-- author or an ADMIN. Notes on an archived project are read-only.
-- ---------------------------------------------------------------------------
CREATE POLICY tenant_write_as_self ON app.notes AS RESTRICTIVE FOR INSERT TO app_user
  WITH CHECK (
    author_id = app.current_member_id()
    AND EXISTS (SELECT 1 FROM app.projects p WHERE p.id = project_id AND p.status = 'active')
  );
CREATE POLICY tenant_edit_own ON app.notes AS RESTRICTIVE FOR UPDATE TO app_user
  USING (author_id = app.current_member_id())
  WITH CHECK (
    author_id = app.current_member_id()
    AND EXISTS (SELECT 1 FROM app.projects p WHERE p.id = project_id AND p.status = 'active')
  );
CREATE POLICY tenant_delete_own_or_admin ON app.notes AS RESTRICTIVE FOR DELETE TO app_user
  USING (author_id = app.current_member_id() OR app.caller_role() = 'ADMIN');
