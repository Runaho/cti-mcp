package store

import (
	"database/sql"
	"fmt"
	"time"
)

// KEVEntry represents a CISA KEV catalog entry.
type KEVEntry struct {
	CVEID          string `json:"cve_id"`
	VendorProduct  string `json:"vendor_product"`
	VulnName       string `json:"vuln_name"`
	DateAdded      string `json:"date_added"`
	DueDate        string `json:"due_date"`
	RequiredAction string `json:"required_action"`
	DaysLeft       int    `json:"days_left"`
	LastUpdated    string `json:"last_updated"`
}

// UpsertKEV inserts or updates a KEV entry.
func UpsertKEV(db *sql.DB, k KEVEntry) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO kev_entries (cve_id, vendor_product, vuln_name, date_added, due_date,
			required_action, days_left, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			vendor_product = excluded.vendor_product,
			vuln_name = excluded.vuln_name,
			date_added = excluded.date_added,
			due_date = excluded.due_date,
			required_action = excluded.required_action,
			days_left = excluded.days_left,
			last_updated = excluded.last_updated
	`, k.CVEID, k.VendorProduct, k.VulnName, k.DateAdded, k.DueDate,
		k.RequiredAction, k.DaysLeft, now)
	if err != nil {
		return fmt.Errorf("upsert kev %s: %w", k.CVEID, err)
	}
	return nil
}

// QueryKEV returns KEV entries from the last recentDays, limited to `limit` results.
func QueryKEV(db *sql.DB, recentDays int, limit int) ([]KEVEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	q := `SELECT cve_id, vendor_product, vuln_name, date_added, due_date,
			required_action, days_left, last_updated
		FROM kev_entries`
	args := []any{}

	if recentDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -recentDays).Format("2006-01-02")
		q += " WHERE date_added >= ?"
		args = append(args, cutoff)
	}
	q += " ORDER BY date_added DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query kev: %w", err)
	}
	defer rows.Close()

	var entries []KEVEntry
	for rows.Next() {
		var k KEVEntry
		if err := rows.Scan(&k.CVEID, &k.VendorProduct, &k.VulnName, &k.DateAdded,
			&k.DueDate, &k.RequiredAction, &k.DaysLeft, &k.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan kev: %w", err)
		}
		entries = append(entries, k)
	}
	return entries, rows.Err()
}

// KEVIDs returns a set of all CVE IDs currently in the KEV catalog.
func KEVIDs(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query("SELECT cve_id FROM kev_entries")
	if err != nil {
		return nil, fmt.Errorf("query kev ids: %w", err)
	}
	defer rows.Close()

	ids := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids[id] = true
	}
	return ids, rows.Err()
}

// KEVCount returns the total number of KEV entries.
func KEVCount(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM kev_entries").Scan(&count)
	return count, err
}
