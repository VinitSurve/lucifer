-- Migration 0003: Phase 2 Security Hardening

-- One-time pairing codes for short-lived, single-use device registration
CREATE TABLE IF NOT EXISTS pairing_codes (
    code_hash TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pairing_codes_owner ON pairing_codes(owner_id);

-- Alter processed_updates to support durable state machine: RECEIVED -> PROCESSING -> COMPLETED / FAILED
ALTER TABLE processed_updates ADD COLUMN status TEXT DEFAULT 'COMPLETED';
ALTER TABLE processed_updates ADD COLUMN updated_at INTEGER DEFAULT 0;
ALTER TABLE processed_updates ADD COLUMN error TEXT;
