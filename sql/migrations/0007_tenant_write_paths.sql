-- 0007 tenant write paths, each with its gate (README, "Adding a write path").
--
-- Each grant is the narrowest column list the API needs. The 0003 gates
-- already constrain who may use it; the smoke suite's allowlist (check 1)
-- fails if anything here changes without a matching check.

-- tenants: rename, by ADMIN or MANAGER (0003 tenant_manager_update).
GRANT UPDATE (name, updated_at) ON app.tenants TO app_user;

-- members: a member edits their own display name; an ADMIN changes a
-- colleague's role (0003 gate_authority_change). Never insert: the auth path
-- binds subjects.
GRANT UPDATE (display_name, role, updated_at) ON app.members TO app_user;

-- projects: create as yourself; rename; archive and restore by MANAGER or
-- ADMIN (0003 gate_project_change); delete by MANAGER or ADMIN.
GRANT INSERT (tenant_id, name, created_by) ON app.projects TO app_user;
GRANT UPDATE (name, status, archived_at, updated_at) ON app.projects TO app_user;
GRANT DELETE ON app.projects TO app_user;

-- notes: write as yourself on an active project; edit your own; delete your
-- own, or any as ADMIN (0003 notes policies).
GRANT INSERT (tenant_id, project_id, author_id, body) ON app.notes TO app_user;
GRANT UPDATE (body, updated_at) ON app.notes TO app_user;
GRANT DELETE ON app.notes TO app_user;

-- audit_log: append as yourself (0002 tenant_append); the append-only
-- trigger rejects anything else.
GRANT INSERT (tenant_id, actor_id, action, detail) ON app.audit_log TO app_user;
