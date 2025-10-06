CREATE TABLE IF NOT EXISTS conviction (
    id TEXT PRIMARY KEY,
    type INTEGER NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT,
    crime_type INTEGER NOT NULL,
    crime_round_id TEXT NOT NULL,
    crime_reason TEXT NOT NULL,
    pardoned BOOLEAN NOT NULL DEFAULT FALSE,
    script TEXT
);

CREATE INDEX IF NOT EXISTS idx_conviction_script ON conviction(script);
CREATE INDEX IF NOT EXISTS idx_conviction_expires_at ON conviction(expires_at);
CREATE INDEX IF NOT EXISTS idx_conviction_pardoned ON conviction(pardoned);
