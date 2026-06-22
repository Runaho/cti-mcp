package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestOSVFetch(t *testing.T) {
	src := &OSV{}
	result, err := src.Fetch(context.Background())
	if err != nil {
		t.Skipf("OSV fetch failed (network?): %v", err)
	}

	// OSV always returns a result (even if empty) — no error on empty
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	t.Logf("OSV: %d CVEs across all ecosystems", len(result.CVEs))

	if len(result.CVEs) == 0 {
		t.Skip("OSV returned 0 CVEs — possibly no recent vulnerabilities in 24h window")
	}

	// Verify first CVE has required fields
	c := result.CVEs[0]
	if c.CVEID == "" {
		t.Error("OSV CVE missing CVE ID")
	}
	if !startsWith(c.CVEID, "CVE-") {
		t.Errorf("CVE ID %q does not start with \"CVE-\"", c.CVEID)
	}
	if c.Provider != "osv" {
		t.Errorf("provider = %q, want \"osv\"", c.Provider)
	}
	if c.Published == "" {
		t.Error("OSV CVE missing published date")
	}
	if c.Data.NVDURL == "" {
		t.Error("OSV CVE missing NVDURL")
	}

	// Verify ecosystem field is populated and lowercase
	validEcosystems := map[string]bool{
		"go": true, "pypi": true, "npm": true, "maven": true,
	}
	foundEcosystem := false
	for _, cve := range result.CVEs {
		if cve.Data.Ecosystem == "" {
			t.Errorf("CVE %s missing ecosystem", cve.CVEID)
			continue
		}
		if !validEcosystems[cve.Data.Ecosystem] {
			t.Errorf("CVE %s ecosystem = %q, not in expected set", cve.CVEID, cve.Data.Ecosystem)
		}
		foundEcosystem = true
	}
	if !foundEcosystem {
		t.Error("no CVEs with populated ecosystem field")
	}

	t.Logf("Sample: CVE=%s Eco=%s Published=%s",
		c.CVEID, c.Data.Ecosystem, c.Published)
}

func TestOSVName(t *testing.T) {
	src := &OSV{}
	if src.Name() != "osv" {
		t.Errorf("Name() = %q, want \"osv\"", src.Name())
	}
}

// ---------------------------------------------------------------------------
// Mock-based deterministic tests for queryEcosystem
// ---------------------------------------------------------------------------

// withMockClient and mockTransport are defined in nvd_test.go (same package).

func TestOSVQueryEcosystem_Normal(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify POST body
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["ecosystem"] != "Go" {
			t.Errorf("body ecosystem = %q, want Go", body["ecosystem"])
		}

		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{
				{
					"id":      "GO-2024-0001",
					"aliases": []string{"CVE-2024-AAAA", "GHSA-xxxx-xxxx-xxxx"},
					"summary": "Denial of service via crafted input in package foo",
					"published": "2024-06-15T12:00:00Z",
					"references": []map[string]any{
						{"url": "https://pkg.go.dev/vuln/GO-2024-0001"},
						{"url": "https://github.com/foo/bar/commit/abc"},
					},
				},
			},
		})
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "2024-06-14/2024-06-15")
	if err != nil {
		t.Fatalf("queryEcosystem error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1", len(cves))
	}

	c := cves[0]
	if c.CVEID != "CVE-2024-AAAA" {
		t.Errorf("CVEID = %q, want CVE-2024-AAAA (from alias)", c.CVEID)
	}
	if c.Provider != "osv" {
		t.Errorf("Provider = %q, want osv", c.Provider)
	}
	if c.Data.Ecosystem != "go" {
		t.Errorf("Ecosystem = %q, want go (lowercased)", c.Data.Ecosystem)
	}
	if c.Published != "2024-06-15T12:00:00Z" {
		t.Errorf("Published = %q", c.Published)
	}
	if c.Description != "Denial of service via crafted input in package foo" {
		t.Errorf("Description mismatch")
	}
	if len(c.Data.References) != 2 {
		t.Errorf("References = %d, want 2", len(c.Data.References))
	}
	// NVD URL generated from CVE ID
	wantURL := "https://nvd.nist.gov/vuln/detail/CVE-2024-AAAA"
	if c.Data.NVDURL != wantURL {
		t.Errorf("NVDURL = %q, want %q", c.Data.NVDURL, wantURL)
	}
	// OSV hardcodes score=7.0, severity=HIGH
	if c.Score != 7.0 {
		t.Errorf("Score = %.1f, want 7.0", c.Score)
	}
	if c.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", c.Severity)
	}
}

func TestOSVQueryEcosystem_MultipleVulns(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{
				{
					"id":      "GO-2024-001",
					"aliases": []string{"CVE-2024-0001"},
					"summary": "First",
					"published": "2024-01-01T00:00:00Z",
				},
				{
					"id":      "GO-2024-002",
					"aliases": []string{"CVE-2024-0002"},
					"summary": "Second",
					"published": "2024-01-02T00:00:00Z",
				},
				{
					"id":      "PYSEC-2024-003",
					"aliases": []string{"CVE-2024-0003"},
					"summary": "Third",
					"published": "2024-01-03T00:00:00Z",
				},
			},
		})
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 3 {
		t.Fatalf("got %d CVEs, want 3", len(cves))
	}
	for _, c := range cves {
		if c.CVEID == "" {
			t.Error("empty CVE ID")
		}
	}
}

func TestOSVQueryEcosystem_NoCVEAliasSkipped(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{
				{
					// Only GHSA alias, no CVE
					"id":      "GHSA-aaaa-bbbb-cccc",
					"aliases": []string{"GHSA-aaaa-bbbb-cccc"},
					"summary": "Should be skipped (no CVE alias)",
					"published": "2024-01-01T00:00:00Z",
				},
				{
					// No aliases at all
					"id":      "PYSEC-2024-NOCVE",
					"aliases": []string{},
					"summary": "Should also be skipped (empty aliases)",
					"published": "2024-01-02T00:00:00Z",
				},
				{
					// This one has a CVE alias
					"id":      "GO-2024-VALID",
					"aliases": []string{"GHSA-dddd-eeee-ffff", "CVE-2024-VALID"},
					"summary": "Should be kept",
					"published": "2024-01-03T00:00:00Z",
				},
			},
		})
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1 (non-CVE skipped)", len(cves))
	}
	if cves[0].CVEID != "CVE-2024-VALID" {
		t.Errorf("CVEID = %q, want CVE-2024-VALID", cves[0].CVEID)
	}
}

func TestOSVQueryEcosystem_DescriptionFallback(t *testing.T) {
	longDetails := strings.Repeat("x", 500)
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{
				{
					// Summary empty, details long → should truncate details to 300
					"id":      "GO-2024-LONG",
					"aliases": []string{"CVE-2024-LONG"},
					"summary": "",
					"details": longDetails,
					"published": "2024-01-01T00:00:00Z",
				},
			},
		})
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1", len(cves))
	}
	// Description should be truncated to 300 chars
	if len(cves[0].Description) > 300 {
		t.Errorf("Description len = %d, want <= 300 (truncated from 500)", len(cves[0].Description))
	}
	if len(cves[0].Description) != 300 {
		t.Errorf("Description len = %d, want exactly 300", len(cves[0].Description))
	}
}

func TestOSVQueryEcosystem_RefTruncation(t *testing.T) {
	refs := make([]map[string]any, 12)
	for i := range refs {
		refs[i] = map[string]any{"url": fmt.Sprintf("https://example.com/ref/%d", i)}
	}
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{
				{
					"id":      "GO-2024-REFS",
					"aliases": []string{"CVE-2024-REFS"},
					"summary": "Test",
					"published": "2024-01-01T00:00:00Z",
					"references": refs,
				},
			},
		})
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves[0].Data.References) > 8 {
		t.Errorf("References = %d items, want <= 8", len(cves[0].Data.References))
	}
	if len(cves[0].Data.References) != 8 {
		t.Errorf("References = %d items, want exactly 8 (truncated from 12)", len(cves[0].Data.References))
	}
}

func TestOSVQueryEcosystem_EmptyResponse(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{},
		})
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 0 {
		t.Errorf("got %d CVEs, want 0 for empty response", len(cves))
	}
}

func TestOSVQueryEcosystem_HTTPError(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
	if len(cves) != 0 {
		t.Errorf("got %d CVEs, want 0 for error", len(cves))
	}
}

func TestOSVQueryEcosystem_MalformedJSON(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})

	src := &OSV{}
	_, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestOSVQueryEcosystem_EcosystemLowercase(t *testing.T) {
	tests := []struct {
		name       string
		ecosystem  string
		wantLower  string
	}{
		{"go", "Go", "go"},
		{"pypi", "PyPI", "pypi"},
		{"npm", "npm", "npm"},
		{"maven", "Maven", "maven"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"vulns": []map[string]any{
						{
							"id":      "TEST-" + tt.name,
							"aliases": []string{"CVE-2024-" + tt.name},
							"summary": "Test",
							"published": "2024-01-01T00:00:00Z",
						},
					},
				})
			})

			src := &OSV{}
			cves, err := src.queryEcosystem(context.Background(), tt.ecosystem, "range")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(cves) != 1 {
				t.Fatalf("got %d CVEs, want 1", len(cves))
			}
			if cves[0].Data.Ecosystem != tt.wantLower {
				t.Errorf("Ecosystem = %q, want %q", cves[0].Data.Ecosystem, tt.wantLower)
			}
		})
	}
}

func TestOSVQueryEcosystem_MultipleAliases(t *testing.T) {
	// Multiple CVE aliases — first one should be picked
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{
				{
					"id":      "GO-2024-MULTI",
					"aliases": []string{"GHSA-xxxx", "CVE-2024-FIRST", "CVE-2024-SECOND"},
					"summary": "Test",
					"published": "2024-01-01T00:00:00Z",
				},
			},
		})
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cves[0].CVEID != "CVE-2024-FIRST" {
		t.Errorf("CVEID = %q, want CVE-2024-FIRST (first CVE alias)", cves[0].CVEID)
	}
}

func TestOSVQueryEcosystem_EmptySummaryAndDetails(t *testing.T) {
	// Both summary and details empty → description should be empty, not crash
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{
				{
					"id":      "GO-2024-EMPTY",
					"aliases": []string{"CVE-2024-EMPTY"},
					"summary": "",
					"details": "",
					"published": "2024-01-01T00:00:00Z",
				},
			},
		})
	})

	src := &OSV{}
	cves, err := src.queryEcosystem(context.Background(), "Go", "range")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1", len(cves))
	}
	if cves[0].Description != "" {
		t.Errorf("Description = %q, want empty", cves[0].Description)
	}
}

// startsWith is a tiny local helper to avoid importing strings just for one check.
func startsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
