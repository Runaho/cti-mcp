package store

import (
	"testing"
	"time"
)

// TestQueryExploitedCVEs_Regression covers the parenthesisation fix in
// QueryExploitedCVEs. Before the fix, the SQL was:
//
//	WHERE in_kev = 1 OR has_poc = 1 AND published >= ?
//
// Because AND binds tighter than OR in SQL, the time filter only applied
// to has_poc rows; in_kev rows passed through unfiltered, regardless of
// how old they were. The fix wraps the OR clause in parentheses:
//
//	WHERE (in_kev = 1 OR has_poc = 1) AND published >= ?
func TestQueryExploitedCVEs_Regression(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := InitSchema(s.DB()); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	recent := now.Add(-1 * time.Hour).Format(time.RFC3339)
	old := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)

	// Four synthetic CVEs spanning the four (in_kev, has_poc, age) cells.
	cves := []CVE{
		{
			CVEID:     "CVE-2026-0001",
			Provider:  "nvd",
			Severity:  "CRITICAL",
			Score:     9.8,
			InKEV:     true,
			HasPoC:    false,
			Published: old,
		},
		{
			CVEID:     "CVE-2026-0002",
			Provider:  "nvd",
			Severity:  "HIGH",
			Score:     8.5,
			InKEV:     true,
			HasPoC:    false,
			Published: recent,
		},
		{
			CVEID:     "CVE-2026-0003",
			Provider:  "nvd",
			Severity:  "MEDIUM",
			Score:     6.5,
			InKEV:     false,
			HasPoC:    true,
			Published: old,
		},
		{
			CVEID:     "CVE-2026-0004",
			Provider:  "nvd",
			Severity:  "HIGH",
			Score:     7.5,
			InKEV:     false,
			HasPoC:    true,
			Published: recent,
		},
	}
	for _, c := range cves {
		if err := UpsertCVE(s.DB(), c); err != nil {
			t.Fatalf("upsert %s: %v", c.CVEID, err)
		}
	}

	// Helper: collect the set of CVEIDs returned by a query for assertions.
	ids := func(rows []CVE) map[string]bool {
		out := make(map[string]bool, len(rows))
		for _, r := range rows {
			out[r.CVEID] = true
		}
		return out
	}

	t.Run("72h window returns only the two recent rows", func(t *testing.T) {
		// 100 limit, 72h window -> only CVE-0002 (KEV, recent) and
		// CVE-0004 (PoC, recent) should be returned. Pre-fix, CVE-0001
		// (KEV, old) would also leak through.
		got, err := QueryExploitedCVEs(s.DB(), 100, 72)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{"CVE-2026-0002": true, "CVE-2026-0004": true}
		gotSet := ids(got)
		if len(got) != 2 {
			t.Fatalf("expected 2 recent exploited CVEs, got %d: %v", len(got), gotSet)
		}
		for id := range want {
			if !gotSet[id] {
				t.Errorf("expected %s in result, missing", id)
			}
		}
		if gotSet["CVE-2026-0001"] {
			t.Errorf("CVE-2026-0001 (KEV, old) must NOT be returned for a 72h window")
		}
		if gotSet["CVE-2026-0003"] {
			t.Errorf("CVE-2026-0003 (PoC, old) must NOT be returned for a 72h window")
		}
	})

	t.Run("0h window returns all four exploited CVEs", func(t *testing.T) {
		// sinceHours == 0 disables the time filter, so all 4 must come back.
		got, err := QueryExploitedCVEs(s.DB(), 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 4 {
			t.Fatalf("expected 4 exploited CVEs (no time filter), got %d", len(got))
		}
	})

	t.Run("limit=0 clamps to default 50", func(t *testing.T) {
		// limit <= 0 should fall back to the default 50. With only four rows
		// in the DB we can't directly observe the clamp count, but we can
		// confirm the query still returns rows and doesn't error.
		got, err := QueryExploitedCVEs(s.DB(), 0, 72)
		if err != nil {
			t.Fatal(err)
		}
		// 72h window: same expectation as the first subtest.
		if len(got) != 2 {
			t.Errorf("expected 2 rows with default limit, got %d", len(got))
		}
	})

	t.Run("limit>500 clamps to 500", func(t *testing.T) {
		// Upper bound: limit > 500 must clamp to 500. With only 4 rows in
		// the DB we can't directly observe the clamp either, but the query
		// must succeed and return rows.
		got, err := QueryExploitedCVEs(s.DB(), 1000, 72)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Errorf("expected 2 rows with limit=1000 (clamped), got %d", len(got))
		}
	})

	t.Run("ignores rows that are neither in_kev nor has_poc", func(t *testing.T) {
		// Sanity: an entry with neither flag must never appear, regardless
		// of how fresh it is.
		boring := CVE{
			CVEID:     "CVE-2026-9999",
			Provider:  "nvd",
			Severity:  "LOW",
			Score:     3.1,
			InKEV:     false,
			HasPoC:    false,
			Published: recent,
		}
		if err := UpsertCVE(s.DB(), boring); err != nil {
			t.Fatal(err)
		}
		got, err := QueryExploitedCVEs(s.DB(), 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got {
			if r.CVEID == "CVE-2026-9999" {
				t.Errorf("non-exploited CVE leaked into exploited result: %s", r.CVEID)
			}
		}
	})
}
