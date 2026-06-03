-- Migration 0031 — secret_audit table.
--
-- Append-only audit log for every token-validated fetch and every denied
-- request (BR-G-01, BR-G-04). Rows MUST NEVER contain plaintext, ciphertext,
-- or token bytes (BR-G-02, BR-J-05). The UPDATE/DELETE guard triggers live
-- in migration 0034; this migration declares the column shape and CHECK
-- constraints only (BR-J-01, BR-J-04, BR-J-07).

CREATE TABLE secret_audit (
    id               INTEGER PRIMARY KEY,
    ts               TEXT NOT NULL,
    token_jti        TEXT NOT NULL,
    caller_uid       INTEGER,
    caller_transport TEXT NOT NULL CHECK (caller_transport IN ('unix','mcp')),
    secret_name      TEXT NOT NULL,
    op               TEXT NOT NULL CHECK (op IN ('read','rotate')),
    allow            TEXT NOT NULL CHECK (allow IN ('allow','deny')),
    reason           TEXT,
    llm_touched      BOOLEAN NOT NULL
);
