-- 0004 the tenant runtime is read-only by default.
--
-- Review rounds on the original system kept finding new ways a tenant could
-- write something it should not, because writes were granted broadly and
-- later migrations clawed them back one by one. The safe baseline is no
-- tenant writes at all.
--
-- The gates from 0003 stay (policies, triggers, constraints). They apply the
-- moment a write is granted. Each write path is added in its own migration as
-- it is built: the narrowest column grant, the gate it needs, and a check in
-- sql/tests/rls_smoke.sql (the allowlist in check 1).
--
-- Revoking a table-level privilege also revokes the matching column
-- privileges, so this clears the column allowlists from 0003 too.

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA app FROM app_user;

DO $guard$
DECLARE
  leftover text;
BEGIN
  SELECT string_agg(DISTINCT format('%s.%s', c.relname, a.privilege_type), ', ') INTO leftover
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_attribute att ON att.attrelid = c.oid AND att.attnum > 0 AND NOT att.attisdropped,
  LATERAL aclexplode(coalesce(att.attacl, c.relacl)) a
  WHERE n.nspname = 'app'
    AND c.relkind IN ('r', 'p')
    AND a.grantee = 'app_user'::regrole
    AND a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE');
  IF leftover IS NOT NULL THEN
    RAISE EXCEPTION 'app_user still holds write privileges: %', leftover;
  END IF;
END
$guard$;
