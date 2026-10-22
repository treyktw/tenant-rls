-- 0006 outbox versions come from one sequence, and events come from the rows.
--
-- Versions. A consumer ignores any event whose version is at or below what it
-- already holds for that aggregate, which is what makes relay replays safe. A
-- writer would otherwise have to read the outbox to pick the next version,
-- and only the relay may read it. One global sequence is enough: versions
-- only need to increase per aggregate, and a writer always updates (and so
-- locks) the aggregate's row before inserting its event, so a second writer
-- to the same aggregate waits for the first to commit and then draws a higher
-- number.
--
-- Events come from the rows, not from callers. A consumer applies events as
-- fact. A caller that could insert an outbox row could therefore tell it
-- anything. So each table emits its own events from a trigger, with a payload
-- built from the row as written, and app_user keeps no outbox insert (0004).
-- The trigger function is SECURITY DEFINER so it can append on behalf of any
-- writer (tenant, platform, backfill) without that writer holding the grant.
-- A change that alters no payload field (a bare updated_at bump) emits
-- nothing.

CREATE SEQUENCE app.outbox_version_seq AS bigint;
ALTER TABLE app.outbox_events ALTER COLUMN version SET DEFAULT nextval('app.outbox_version_seq');
GRANT USAGE ON SEQUENCE app.outbox_version_seq TO platform_admin;

CREATE OR REPLACE FUNCTION app.emit_row_event() RETURNS trigger
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, app
  AS $$
  DECLARE
    aggregate text := TG_ARGV[0];
    -- Columns that are bookkeeping, not state.
    ignored text[] := ARRAY['created_at', 'updated_at'];
    old_payload jsonb;
    new_payload jsonb;
    tenant uuid;
  BEGIN
    IF TG_OP = 'DELETE' THEN
      tenant := CASE WHEN TG_TABLE_NAME = 'tenants' THEN OLD.id ELSE (to_jsonb(OLD)->>'tenant_id')::uuid END;
      INSERT INTO app.outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
      VALUES (tenant, aggregate, OLD.id, aggregate || '.deleted', '{}'::jsonb);
      RETURN OLD;
    END IF;

    new_payload := to_jsonb(NEW) - ignored;
    IF TG_OP = 'UPDATE' THEN
      old_payload := to_jsonb(OLD) - ignored;
    END IF;
    IF old_payload IS NOT DISTINCT FROM new_payload THEN
      RETURN NEW;
    END IF;

    tenant := CASE WHEN TG_TABLE_NAME = 'tenants' THEN NEW.id ELSE (new_payload->>'tenant_id')::uuid END;
    INSERT INTO app.outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
    VALUES (tenant, aggregate, NEW.id, aggregate || '.upserted', new_payload);
    RETURN NEW;
  END
  $$;

-- The function runs as the migration owner. FORCE RLS binds the owner too
-- unless it can bypass RLS (a managed provider's owner often can; a plain
-- local one cannot), so the owner gets an append-only policy of its own.
DO $own$
BEGIN
  EXECUTE format(
    'CREATE POLICY definer_emit ON app.outbox_events FOR INSERT TO %I WITH CHECK (true)',
    current_user
  );
END
$own$;

REVOKE ALL ON FUNCTION app.emit_row_event() FROM PUBLIC;

CREATE TRIGGER tenants_emit_event
  AFTER INSERT OR UPDATE OR DELETE ON app.tenants
  FOR EACH ROW EXECUTE FUNCTION app.emit_row_event('tenant');
CREATE TRIGGER members_emit_event
  AFTER INSERT OR UPDATE OR DELETE ON app.members
  FOR EACH ROW EXECUTE FUNCTION app.emit_row_event('member');
CREATE TRIGGER projects_emit_event
  AFTER INSERT OR UPDATE OR DELETE ON app.projects
  FOR EACH ROW EXECUTE FUNCTION app.emit_row_event('project');
CREATE TRIGGER notes_emit_event
  AFTER INSERT OR UPDATE OR DELETE ON app.notes
  FOR EACH ROW EXECUTE FUNCTION app.emit_row_event('note');
