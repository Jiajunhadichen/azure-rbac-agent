-- database/schema.sql
-- SQLite schema for AccessSafe

CREATE TABLE IF NOT EXISTS access_records (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,           -- 'new_request' or 'risk_scan'
    subject TEXT NOT NULL,          -- User or Service Principal name/id
    current_role TEXT,              -- Current role (only for risk_scan source)
    current_scope TEXT,             -- Current scope (only for risk_scan source)
    recommended_role TEXT,          -- Agent recommended role
    recommended_scope TEXT,         -- Agent recommended scope
    production_access INTEGER,      -- 0 or 1
    risk_level TEXT,                -- Low/Medium/High/Critical
    duration_days INTEGER,          -- Recommended validity days
    reason TEXT,                    -- Recommendation reasoning
    approvers TEXT,                 -- Comma-separated list of required approvers
    status TEXT,                    -- Pending/Approved/Rejected/Needs Review
    created_at TEXT,
    updated_at TEXT,
    expires_at TEXT                 -- Expiration timestamp
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,        -- ISO-8601 UTC
    event_type TEXT NOT NULL,       -- Type of event (e.g., ACCESS_REQUEST, AUDIT, REMEDIATION)
    subject TEXT,                   -- Target user or principal name/id
    action TEXT,                    -- Detailed action name/content
    result TEXT,                    -- Result of action (Approved/Rejected/Success/Failed)
    operator TEXT                   -- Person or Agent performing the action
);
