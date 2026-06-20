package store

import (
	"database/sql"
	"fmt"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    provider        TEXT NOT NULL DEFAULT '',
    providers       TEXT DEFAULT '[]',
    data            TEXT NOT NULL DEFAULT '{}',
    description     TEXT DEFAULT '',
    description_html TEXT DEFAULT '',
    first_seen      TEXT NOT NULL,
    last_updated    TEXT NOT NULL,
    severity        TEXT DEFAULT '',
    score           REAL DEFAULT 0,
    in_kev          INTEGER DEFAULT 0,
    has_poc         INTEGER DEFAULT 0,
    published       TEXT DEFAULT '',
    category        TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cves_severity   ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_score      ON cves(score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_in_kev     ON cves(in_kev);
CREATE INDEX IF NOT EXISTS idx_cves_published  ON cves(published);
CREATE INDEX IF NOT EXISTS idx_cves_has_poc    ON cves(has_poc);
CREATE INDEX IF NOT EXISTS idx_cves_provider   ON cves(provider);
CREATE INDEX IF NOT EXISTS idx_cves_category   ON cves(category);

CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id          TEXT PRIMARY KEY,
    vendor_product  TEXT DEFAULT '',
    vuln_name       TEXT DEFAULT '',
    date_added      TEXT DEFAULT '',
    due_date        TEXT DEFAULT '',
    required_action TEXT DEFAULT '',
    days_left       INTEGER DEFAULT 0,
    last_updated    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_entries(date_added DESC);

CREATE TABLE IF NOT EXISTS source_health (
    source_name     TEXT PRIMARY KEY,
    last_fetched    TEXT NOT NULL,
    status          TEXT DEFAULT 'unknown',
    http_code       INTEGER DEFAULT 0,
    entry_count     INTEGER DEFAULT 0,
    error_message   TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);
`

// InitSchema creates all tables and indexes if they don't exist.
func InitSchema(db *sql.DB) error {
	_, err := db.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	return nil
}
