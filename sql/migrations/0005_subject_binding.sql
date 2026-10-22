-- 0005 the data service finds its caller's member row from a verified subject.
--
-- A request reaches the data service knowing only its identity-provider
-- subject (the JWT `sub`). To bind `app.member_id` and `app.tenant_id` it has
-- to read that subject's own `app.members` row first, and under 0002's policy
-- `app_user` sees no member rows until a tenant is already set.
--
-- This adds one read: with `app.subject` set, `app_user` sees the single
-- member row bound to that subject, and nothing else. It is SELECT only, so
-- it cannot create or move a binding (0003 keeps those on the auth path), and
-- it widens no other table. The data service sets `app.subject` only from a
-- session it verified, clears it once the tenant is bound, and is already
-- trusted to set the tenant itself (README, "Trust boundary"), so this grants
-- a runtime login nothing it could not already reach.

CREATE OR REPLACE FUNCTION app.current_subject() RETURNS text
  LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('app.subject', true), '') $$;

CREATE POLICY self_by_subject ON app.members FOR SELECT TO app_user
  USING (subject IS NOT NULL AND subject = app.current_subject());
