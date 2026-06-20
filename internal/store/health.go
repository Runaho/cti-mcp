package store

import (
	"database/sql"
	"fmt"
	"time"
)

// SourceHealth tracks the last fetch status of each data source.
type SourceHealth struct {
	SourceName   string `json:"source_name"`
	LastFetched  string `json:"last_fetched"`
	Status       string `json:"status"`
	HTTPCode     int    `json:"http_code"`
	EntryCount   int    `json:"entry_count"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// UpdateSourceHealth records the result of a source fetch.
func UpdateSourceHealth(db *sql.DB, h SourceHealth) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO source_health (source_name, last_fetched, status, http_code, entry_count, error_message)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(source_name) DO UPDATE SET
			last_fetched = excluded.last_fetched,
			status = excluded.status,
			http_code = excluded.http_code,
			entry_count = excluded.entry_count,
			error_message = excluded.error_message
	`, h.SourceName, now, h.Status, h.HTTPCode, h.EntryCount, h.ErrorMessage)
	if err != nil {
		return fmt.Errorf("update source health: %w", err)
	}
	return nil
}

// GetAllSourceHealth returns the health status of all sources.
func GetAllSourceHealth(db *sql.DB) ([]SourceHealth, error) {
	rows, err := db.Query(`SELECT source_name, last_fetched, status, http_code, entry_count, error_message
		FROM source_health ORDER BY source_name`)
	if err != nil {
		return nil, fmt.Errorf("get source health: %w", err)
	}
	defer rows.Close()

	var healths []SourceHealth
	for rows.Next() {
		var h SourceHealth
		if err := rows.Scan(&h.SourceName, &h.LastFetched, &h.Status, &h.HTTPCode,
			&h.EntryCount, &h.ErrorMessage); err != nil {
			return nil, fmt.Errorf("scan source health: %w", err)
		}
		healths = append(healths, h)
	}
	return healths, rows.Err()
}

// SettingGet retrieves a setting value by key. Returns empty string if not found.
func SettingGet(db *sql.DB, key string) (string, error) {
	var val string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

// SettingSet sets a setting value.
func SettingSet(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
