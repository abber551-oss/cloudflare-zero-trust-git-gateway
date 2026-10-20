PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'QUARANTINED', 'REVOKED')),
    fork_name TEXT,
    active_token_id TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS audit_ledger (
    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_path TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    threat_metadata TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_ledger(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_ledger(timestamp DESC);

INSERT OR IGNORE INTO agents (agent_id, namespace, status, risk_score, updated_at)
VALUES 
    ('agent-alpha-01', 'default', 'ACTIVE', 0, '2026-10-19T00:00:00Z'),
    ('agent-rogue-99', 'default', 'ACTIVE', 10, '2026-10-19T00:00:00Z');
