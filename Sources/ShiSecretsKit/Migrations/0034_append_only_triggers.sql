-- Migration 0034 — append-only triggers for secret_audit + seams (Postgres).
--
-- Enforces BR-G-05 at the DB layer: UPDATE and DELETE statements against
-- secret_audit or seams are rejected with RAISE EXCEPTION 'append_only_violation'.
-- Insert-only semantics are what make these two tables the tamper-evident
-- spine of the broker's audit story — any attempt to mutate history fails
-- the transaction and surfaces a clear error string to the caller.
--
-- 2026-05-21: rewritten from SQLite-style triggers
-- (BEGIN..SELECT RAISE(ABORT)..END) to Postgres PL/pgSQL
-- (CREATE FUNCTION + RAISE EXCEPTION + EXECUTE FUNCTION).
-- shikki-db is Postgres; the prior SQLite syntax was a spec gap that
-- silently broke broker bootstrap.

CREATE OR REPLACE FUNCTION append_only_violation_fn() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'append_only_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS secret_audit_no_update ON secret_audit;
CREATE TRIGGER secret_audit_no_update
BEFORE UPDATE ON secret_audit
FOR EACH ROW
EXECUTE FUNCTION append_only_violation_fn();

DROP TRIGGER IF EXISTS secret_audit_no_delete ON secret_audit;
CREATE TRIGGER secret_audit_no_delete
BEFORE DELETE ON secret_audit
FOR EACH ROW
EXECUTE FUNCTION append_only_violation_fn();

DROP TRIGGER IF EXISTS seams_no_update ON seams;
CREATE TRIGGER seams_no_update
BEFORE UPDATE ON seams
FOR EACH ROW
EXECUTE FUNCTION append_only_violation_fn();

DROP TRIGGER IF EXISTS seams_no_delete ON seams;
CREATE TRIGGER seams_no_delete
BEFORE DELETE ON seams
FOR EACH ROW
EXECUTE FUNCTION append_only_violation_fn();
