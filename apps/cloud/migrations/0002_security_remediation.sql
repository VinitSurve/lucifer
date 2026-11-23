-- Migration 0002: Security Remediation

CREATE TABLE IF NOT EXISTS processed_updates (
    update_id INTEGER PRIMARY KEY,
    processed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_processed_updates_time ON processed_updates(processed_at);
