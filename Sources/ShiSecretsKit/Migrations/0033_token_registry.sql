-- Migration 0033 — token_registry.
--
-- Tracks every ShikkiSBT issued by the broker. Stores ONLY jti + claims
-- metadata — never the token bytes themselves (BR-A-07). The passkey_path
-- flag is the kill-switch guard for `shi token revoke --all-bots`: rows
-- with passkey_path=TRUE survive mass revocation (BR-F-02). Revoked rows
-- are retained indefinitely for audit (BR-J-06); no hard delete.
--
-- BR-A-06 is enforced textually in the schema tests: the string "expires_at"
-- must never appear in this file — `dies_at` is the one expiry surface.

CREATE TABLE token_registry (
    jti          TEXT PRIMARY KEY,
    sub          TEXT NOT NULL,
    scope        TEXT NOT NULL,
    op           TEXT NOT NULL CHECK (op IN ('read','rotate')),
    nbf          TEXT NOT NULL,
    dies_at      TEXT NOT NULL,
    llm_touched  BOOLEAN NOT NULL,
    revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at   TEXT,
    passkey_path BOOLEAN NOT NULL DEFAULT FALSE
);
