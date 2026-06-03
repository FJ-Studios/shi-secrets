-- Migration 0032 — seams (Golden Seam Ledger).
--
-- One append-only row per anomaly-driven rotation (BR-G-03, BR-J-02). The
-- rotation_outcome CHECK enforces the three terminal outcomes: the rotation
-- happened, it failed, or it was deliberately bypassed (incident override,
-- see BR-F-04). UPDATE/DELETE are blocked by triggers in migration 0034.

CREATE TABLE seams (
    id               INTEGER PRIMARY KEY,
    ts               TEXT NOT NULL,
    secret_name      TEXT NOT NULL,
    signal           TEXT NOT NULL,
    rotation_outcome TEXT NOT NULL CHECK (rotation_outcome IN ('rotated','failed','bypassed')),
    notes            TEXT
);
