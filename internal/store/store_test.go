package store

import (
	"testing"
)

func TestInitSchema(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := InitSchema(s.DB()); err != nil {
		t.Fatal(err)
	}

	// Verify all tables exist
	tables := []string{"cves", "kev_entries", "source_health", "settings"}
	for _, table := range tables {
		var name string
		err := s.DB().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}

	// Verify indexes
	indexes := []string{
		"idx_cves_severity", "idx_cves_score", "idx_cves_in_kev",
		"idx_cves_published", "idx_cves_has_poc", "idx_cves_provider",
		"idx_cves_category", "idx_kev_date_added",
	}
	for _, idx := range indexes {
		var name string
		err := s.DB().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx,
		).Scan(&name)
		if err != nil {
			t.Errorf("index %s not found: %v", idx, err)
		}
	}
}

func TestUpsertAndQueryCVE(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := InitSchema(s.DB()); err != nil {
		t.Fatal(err)
	}

	cve := CVE{
		CVEID:       "CVE-2026-12345",
		Provider:    "nvd",
		Providers:   []string{"nvd", "ghadv"},
		Description: "Heap buffer overflow in libxml2",
		Severity:    "CRITICAL",
		Score:       9.8,
		InKEV:       true,
		HasPoC:      true,
		Published:   "2026-06-20T14:30:00Z",
		Category:    "Server/Infra",
		Data: CVEData{
			Title:      "Heap buffer overflow in libxml2",
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:        []string{"CWE-787"},
			Product:    "pip/libxml2",
			NVDURL:     "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
		},
	}

	if err := UpsertCVE(s.DB(), cve); err != nil {
		t.Fatal(err)
	}

	// Query it back
	got, err := GetCVE(s.DB(), "CVE-2026-12345")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("CVE not found after insert")
	}
	if got.CVEID != "CVE-2026-12345" {
		t.Errorf("cve_id mismatch: got %s", got.CVEID)
	}
	if !got.InKEV {
		t.Error("in_kev should be true")
	}
	if !got.HasPoC {
		t.Error("has_poc should be true")
	}
	if got.Score != 9.8 {
		t.Errorf("score mismatch: got %f", got.Score)
	}
	if len(got.Providers) != 2 {
		t.Errorf("providers length: got %d, want 2", len(got.Providers))
	}
	if got.Data.Title != "Heap buffer overflow in libxml2" {
		t.Errorf("data.title: got %s", got.Data.Title)
	}

	// Test upsert (update existing)
	cve2 := cve
	cve2.Score = 10.0
	cve2.Description = "Updated description"
	if err := UpsertCVE(s.DB(), cve2); err != nil {
		t.Fatal(err)
	}
	got2, _ := GetCVE(s.DB(), "CVE-2026-12345")
	if got2.Score != 10.0 {
		t.Errorf("updated score: got %f, want 10.0", got2.Score)
	}
	if got2.Description != "Updated description" {
		t.Errorf("updated description: got %s", got2.Description)
	}
}

func TestUpsertAndQueryKEV(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := InitSchema(s.DB()); err != nil {
		t.Fatal(err)
	}

	kev := KEVEntry{
		CVEID:          "CVE-2026-12345",
		VendorProduct:  "xmlsoft_libxml2",
		VulnName:       "libxml2 Heap Buffer Overflow",
		DateAdded:      "2026-06-19",
		DueDate:        "2026-07-10",
		RequiredAction: "Apply patch from vendor.",
		DaysLeft:       19,
	}

	if err := UpsertKEV(s.DB(), kev); err != nil {
		t.Fatal(err)
	}

	entries, err := QueryKEV(s.DB(), 30, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 KEV entry, got %d", len(entries))
	}
	if entries[0].CVEID != "CVE-2026-12345" {
		t.Errorf("kev cve_id: got %s", entries[0].CVEID)
	}

	ids, err := KEVIDs(s.DB())
	if err != nil {
		t.Fatal(err)
	}
	if !ids["CVE-2026-12345"] {
		t.Error("KEV ID set missing CVE-2026-12345")
	}
}

func TestSourceHealth(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	InitSchema(s.DB())

	if err := UpdateSourceHealth(s.DB(), SourceHealth{
		SourceName: "cisa_kev",
		Status:     "ok",
		HTTPCode:   200,
		EntryCount: 1200,
	}); err != nil {
		t.Fatal(err)
	}

	healths, err := GetAllSourceHealth(s.DB())
	if err != nil {
		t.Fatal(err)
	}
	if len(healths) != 1 {
		t.Fatalf("expected 1 source health, got %d", len(healths))
	}
	if healths[0].SourceName != "cisa_kev" {
		t.Errorf("source name: got %s", healths[0].SourceName)
	}
}

func TestSettings(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	InitSchema(s.DB())

	SettingSet(s.DB(), "retention_days", "90")
	val, err := SettingGet(s.DB(), "retention_days")
	if err != nil {
		t.Fatal(err)
	}
	if val != "90" {
		t.Errorf("setting value: got %s, want 90", val)
	}

	// Test update
	SettingSet(s.DB(), "retention_days", "180")
	val2, _ := SettingGet(s.DB(), "retention_days")
	if val2 != "180" {
		t.Errorf("updated setting: got %s, want 180", val2)
	}

	// Test missing key
	val3, _ := SettingGet(s.DB(), "nonexistent")
	if val3 != "" {
		t.Errorf("missing key should return empty, got %s", val3)
	}
}

func TestSearchCVEs(t *testing.T) {
	s, _ := NewStore(":memory:")
	defer s.Close()
	InitSchema(s.DB())

	// Insert test data
	cves := []CVE{
		{CVEID: "CVE-2026-11111", Provider: "nvd", Severity: "CRITICAL", Score: 9.8,
			Description: "RCE in nginx", Published: "2026-06-20T00:00:00Z",
			Data: CVEData{Product: "nginx", CWE: []string{"CWE-78"}}},
		{CVEID: "CVE-2026-22222", Provider: "ghadv", Severity: "HIGH", Score: 7.5,
			Description: "XSS in react", Published: "2026-06-21T00:00:00Z",
			Data: CVEData{Product: "npm/react", CWE: []string{"CWE-79"}}},
	}
	for _, c := range cves {
		UpsertCVE(s.DB(), c)
	}

	// Search by keyword
	results, err := SearchCVEs(s.DB(), "nginx", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("keyword search: expected 1, got %d", len(results))
	}
	if results[0].CVEID != "CVE-2026-11111" {
		t.Errorf("wrong result: got %s", results[0].CVEID)
	}

	// Search by CWE
	results2, _ := SearchCVEs(s.DB(), "", "", "CWE-79", 10)
	if len(results2) != 1 {
		t.Fatalf("CWE search: expected 1, got %d", len(results2))
	}
}
