-- Migration 0035 — debug_bridge_tables (W7 KatagamiDebugBridge broker side)
--
-- Three tables owned by the shi-secrets broker for the KatagamiDebugBridge
-- token lifecycle: active_tokens (live token index), revoked_tokens (permanent
-- revocation list), signing_keys (Ed25519 key set + JWKS state).
--
-- These tables live in the BROKER's embedded Postgres (not the main shikki DB).
-- The main shikki DB hosts katagami_debug_bridge_audit (migration 028).
--
-- Append-only trigger on revoked_tokens mirrors the 0034 pattern.
-- active_tokens is mutable (rows pruned on expiry by broker housekeeping) —
-- not append-only.
-- signing_keys is mutable (status column transitions: active→grace→retired/compromised).
--
-- Operator ballot 2026-05-25:
--   OQ-KDBR-01: YES — codesign check enforced in bridge (not broker)
--   OQ-KDBR-02: SPKI hash CA pin (not leaf) — enforced in bridge TLS
--   OQ-KDBR-03: Tailscale default bind — enforced in bridge
--   OQ-KDBR-04: YES — rate-limit 10 failed /revocation/check per IP in 5min
--                     → in-memory ip_block_cache in broker HTTP layer (not DB)

-- ─── active_tokens ────────────────────────────────────────────────────────────
-- Tracks every live debug-bridge JWT issued by the broker.
-- Rows are pruned by broker housekeeping when expires_at has passed.
-- Pruning uses DELETE (allowed — not append-only).

CREATE TABLE IF NOT EXISTS debug_bridge_active_tokens (
    jti          TEXT        PRIMARY KEY,
    kid          TEXT        NOT NULL,
    sub          TEXT        NOT NULL,   -- operator-id (PocketBase user UUID)
    device_id    TEXT,                   -- SHA-256 of hardware UUID (optional)
    scope        TEXT        NOT NULL,   -- space-separated: read inspect snap rebind
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL    -- max 24h from issued_at
);

CREATE INDEX IF NOT EXISTS idx_db_active_tokens_kid       ON debug_bridge_active_tokens (kid);
CREATE INDEX IF NOT EXISTS idx_db_active_tokens_device_id ON debug_bridge_active_tokens (device_id) WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_db_active_tokens_expires   ON debug_bridge_active_tokens (expires_at);

-- ─── revoked_tokens ───────────────────────────────────────────────────────────
-- Permanent revocation list. Rows are NEVER deleted (append-only enforced below).
-- Broker loads this set into memory on startup (HashSet<jti>).
-- /revocation/check queries this table.

CREATE TABLE IF NOT EXISTS debug_bridge_revoked_tokens (
    jti          TEXT        PRIMARY KEY,
    revoked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_by   TEXT        NOT NULL,  -- 'operator:<sub>' | 'key_compromise:<kid>' | 'mass_revoke'
    reason       TEXT                   -- human-readable (optional)
);

-- Append-only: revocation is permanent — no mutation allowed.
CREATE OR REPLACE FUNCTION debug_bridge_revoked_tokens_no_mutate()
    RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'debug_bridge_revoked_tokens is append-only: % on jti % is forbidden',
        TG_OP,
        COALESCE(OLD.jti, '(null)');
END;
$$;

DROP TRIGGER IF EXISTS debug_bridge_revoked_no_update ON debug_bridge_revoked_tokens;
CREATE TRIGGER debug_bridge_revoked_no_update
    BEFORE UPDATE ON debug_bridge_revoked_tokens
    FOR EACH ROW EXECUTE FUNCTION debug_bridge_revoked_tokens_no_mutate();

DROP TRIGGER IF EXISTS debug_bridge_revoked_no_delete ON debug_bridge_revoked_tokens;
CREATE TRIGGER debug_bridge_revoked_no_delete
    BEFORE DELETE ON debug_bridge_revoked_tokens
    FOR EACH ROW EXECUTE FUNCTION debug_bridge_revoked_tokens_no_mutate();

-- ─── signing_keys ─────────────────────────────────────────────────────────────
-- Ed25519 public key set for JWKS. Private key is in macOS Keychain only —
-- never stored in this table.
--
-- status transitions:
--   active     → grace      (key-rotate: old kid enters 24h grace)
--   active     → compromised (key-compromise: immediate retirement, no grace)
--   grace      → retired     (after grace period expires)
--   compromised → retired    (after emergency key-compromise completes)
--
-- Retired kid rows are KEPT for audit log queries (need public key to verify
-- historical token signatures in audit). Private key is deleted from Keychain
-- after grace period (or immediately on compromise).

CREATE TABLE IF NOT EXISTS debug_bridge_signing_keys (
    kid            TEXT        PRIMARY KEY,                     -- UUID v4
    public_key_hex TEXT        NOT NULL,                        -- hex-encoded Ed25519 public key bytes (32 bytes = 64 hex chars)
    issued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at     TIMESTAMPTZ,                                 -- NULL while active or grace
    status         TEXT        NOT NULL DEFAULT 'active'
                               CHECK (status IN ('active', 'grace', 'retired', 'compromised'))
);

CREATE INDEX IF NOT EXISTS idx_db_signing_keys_status ON debug_bridge_signing_keys (status);
