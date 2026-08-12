package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// CVEData is the flexible JSON blob stored in the `data` column.
type CVEData struct {
	Title          string   `json:"title,omitempty"`
	CVSSVector     string   `json:"cvss_vector,omitempty"`
	VulnRange      string   `json:"vuln_range,omitempty"`
	PatchedVer     string   `json:"patched_ver,omitempty"`
	CWE            []string `json:"cwe,omitempty"`
	CWENames       []string `json:"cwe_names,omitempty"`
	Ecosystem      string   `json:"ecosystem,omitempty"`
	Product        string   `json:"product,omitempty"`
	References     []string `json:"references,omitempty"`
	ExploitRefs    []string `json:"exploit_refs,omitempty"`
	PoCLinks       []string `json:"poc_links,omitempty"`
	EPSSPct        float64  `json:"epss_pct,omitempty"`
	EPSSPctile     float64  `json:"epss_percentile,omitempty"`
	GHSAURL        string   `json:"ghsa_url,omitempty"`
	NVDURL         string   `json:"nvd_url,omitempty"`
	Priority       string   `json:"priority,omitempty"`
	RequiredAction string   `json:"required_action,omitempty"`
}

// CVE is the full row representation used by query results.
type CVE struct {
	CVEID           string  `json:"cve_id"`
	Provider        string  `json:"provider"`
	Providers       []string `json:"providers"`
	Data            CVEData `json:"details"`
	Description     string  `json:"description"`
	DescriptionHTML string  `json:"description_html,omitempty"`
	FirstSeen       string  `json:"first_seen"`
	LastUpdated     string  `json:"last_updated"`
	Severity        string  `json:"severity"`
	Score           float64 `json:"score"`
	InKEV           bool    `json:"in_kev"`
	HasPoC          bool    `json:"has_poc"`
	Published       string  `json:"published"`
	Category        string  `json:"category"`
}

// UpsertCVE inserts or updates a CVE entry. Merges providers list and
// never downgrades in_kev/has_poc flags.
func UpsertCVE(db *sql.DB, c CVE) error {
	dataJSON, err := json.Marshal(c.Data)
	if err != nil {
		return fmt.Errorf("marshal cve data: %w", err)
	}
	providersJSON, err := json.Marshal(c.Providers)
	if err != nil {
		return fmt.Errorf("marshal providers: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if c.FirstSeen == "" {
		c.FirstSeen = now
	}
	if c.LastUpdated == "" {
		c.LastUpdated = now
	}

	inKEV := 0
	if c.InKEV {
		inKEV = 1
	}
	hasPoC := 0
	if c.HasPoC {
		hasPoC = 1
	}

	_, err = db.Exec(`
		INSERT INTO cves (cve_id, provider, providers, data, description, description_html,
			first_seen, last_updated, severity, score, in_kev, has_poc, published, category)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			provider = excluded.provider,
			providers = excluded.providers,
			data = excluded.data,
			description = excluded.description,
			description_html = excluded.description_html,
			last_updated = excluded.last_updated,
			severity = excluded.severity,
			score = MAX(score, excluded.score),
			in_kev = MAX(in_kev, excluded.in_kev),
			has_poc = MAX(has_poc, excluded.has_poc),
			published = CASE WHEN excluded.published != '' THEN excluded.published ELSE published END,
			category = excluded.category
	`, c.CVEID, c.Provider, string(providersJSON), string(dataJSON), c.Description, c.DescriptionHTML,
		c.FirstSeen, c.LastUpdated, c.Severity, c.Score, inKEV, hasPoC, c.Published, c.Category)

	if err != nil {
		return fmt.Errorf("upsert cve %s: %w", c.CVEID, err)
	}
	return nil
}

// QueryCVEs filters CVEs by severity, time window, and returns at most `limit` results.
// If severity is empty, returns all. If sinceHours is 0, no time filter.
func QueryCVEs(db *sql.DB, severity string, sinceHours int, limit int) ([]CVE, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	q := `SELECT cve_id, provider, providers, data, description, description_html,
			first_seen, last_updated, severity, score, in_kev, has_poc, published, category
		FROM cves`
	args := []any{}
	conditions := []string{}

	if severity != "" && severity != "ALL" {
		conditions = append(conditions, "severity = ?")
		args = append(args, severity)
	}
	if sinceHours > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(sinceHours) * time.Hour).Format(time.RFC3339)
		conditions = append(conditions, "published >= ?")
		args = append(args, cutoff)
	}

	if len(conditions) > 0 {
		q += " WHERE " + joinAnd(conditions)
	}
	q += " ORDER BY score DESC, last_updated DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query cves: %w", err)
	}
	defer rows.Close()

	return scanCVEs(rows)
}

// GetCVE retrieves a single CVE by ID.
func GetCVE(db *sql.DB, cveID string) (*CVE, error) {
	row := db.QueryRow(`SELECT cve_id, provider, providers, data, description, description_html,
			first_seen, last_updated, severity, score, in_kev, has_poc, published, category
		FROM cves WHERE cve_id = ?`, cveID)

	c, err := scanCVE(row)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// SearchCVEs performs a LIKE search across description, cve_id, and the data JSON blob.
func SearchCVEs(db *sql.DB, keyword, product, cwe string, limit int) ([]CVE, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	q := `SELECT cve_id, provider, providers, data, description, description_html,
			first_seen, last_updated, severity, score, in_kev, has_poc, published, category
		FROM cves`
	args := []any{}
	conditions := []string{}

	if keyword != "" {
		conditions = append(conditions, "(description LIKE ? OR cve_id LIKE ? OR data LIKE ?)")
		pattern := "%" + keyword + "%"
		args = append(args, pattern, pattern, pattern)
	}
	if product != "" {
		conditions = append(conditions, "data LIKE ?")
		args = append(args, "%\"product\":\""+product+"\"%")
	}
	if cwe != "" {
		conditions = append(conditions, "data LIKE ?")
		args = append(args, "%"+cwe+"%")
	}

	if len(conditions) > 0 {
		q += " WHERE " + joinAnd(conditions)
	}
	q += " ORDER BY score DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("search cves: %w", err)
	}
	defer rows.Close()

	return scanCVEs(rows)
}

// QueryExploitedCVEs returns CVEs that are in KEV or have PoC, sorted by score.
// If sinceHours > 0, filters to CVEs published within that time window.
func QueryExploitedCVEs(db *sql.DB, limit int, sinceHours int) ([]CVE, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	// Parens required: (in_kev OR has_poc) AND published >= cutoff.
	// Without parens, AND binds tighter than OR and the time filter is
	// only applied to has_poc rows, letting stale in_kev rows slip through.
	q := `SELECT cve_id, provider, providers, data, description, description_html,
		first_seen, last_updated, severity, score, in_kev, has_poc, published, category
		FROM cves WHERE (in_kev = 1 OR has_poc = 1)`
	args := []any{}

	if sinceHours > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(sinceHours) * time.Hour).Format(time.RFC3339)
		q += " AND published >= ?"
		args = append(args, cutoff)
	}

	q += " ORDER BY score DESC, last_updated DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query exploited cves: %w", err)
	}
	defer rows.Close()

	return scanCVEs(rows)
}

// CVEExists checks if a CVE is in the database and returns its last_updated timestamp.
func CVEExists(db *sql.DB, cveID string) (exists bool, lastUpdated string, err error) {
	err = db.QueryRow("SELECT last_updated FROM cves WHERE cve_id = ?", cveID).Scan(&lastUpdated)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("check cve exists: %w", err)
	}
	return true, lastUpdated, nil
}

// CVECount returns the total number of CVEs in the database.
func CVECount(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM cves").Scan(&count)
	return count, err
}

// --- helpers ---

func joinAnd(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " AND "
		}
		result += p
	}
	return result
}

func scanCVEs(rows *sql.Rows) ([]CVE, error) {
	var cves []CVE
	for rows.Next() {
		c, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		cves = append(cves, *c)
	}
	return cves, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanCVE(s scanner) (*CVE, error) {
	return scanRow(s)
}

func scanRow(s scanner) (*CVE, error) {
	var c CVE
	var providersJSON, dataJSON string
	var inKEV, hasPoC int

	err := s.Scan(
		&c.CVEID, &c.Provider, &providersJSON, &dataJSON,
		&c.Description, &c.DescriptionHTML,
		&c.FirstSeen, &c.LastUpdated,
		&c.Severity, &c.Score, &inKEV, &hasPoC,
		&c.Published, &c.Category,
	)
	if err != nil {
		return nil, err
	}

	c.InKEV = inKEV == 1
	c.HasPoC = hasPoC == 1

	_ = json.Unmarshal([]byte(providersJSON), &c.Providers)
	if c.Providers == nil {
		c.Providers = []string{}
	}
	_ = json.Unmarshal([]byte(dataJSON), &c.Data)

	return &c, nil
}
