package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseNVDMetrics(t *testing.T) {
	tests := []struct {
		name           string
		json           string
		wantScore      float64
		wantSeverity   string
		wantVector     string
	}{
		{
			name:         "cvss4_highest_priority",
			json:         `{"cvssMetricV40":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/AV:N/AC:L"}}],"cvssMetricV31":[{"cvssData":{"baseScore":8.1,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L"}}]}`,
			wantScore:    9.8,
			wantSeverity: "CRITICAL",
			wantVector:   "CVSS:4.0/AV:N/AC:L",
		},
		{
			name:         "cvss31_only",
			json:         `{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L"}}]}`,
			wantScore:    7.5,
			wantSeverity: "HIGH",
			wantVector:   "CVSS:3.1/AV:N/AC:L",
		},
		{
			name:         "cvss30_fallback",
			json:         `{"cvssMetricV30":[{"cvssData":{"baseScore":6.5,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.0/AV:N"}}]}`,
			wantScore:    6.5,
			wantSeverity: "MEDIUM",
			wantVector:   "CVSS:3.0/AV:N",
		},
		{
			name:         "cvss2_legacy",
			json:         `{"cvssMetricV2":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM","vectorString":"AV:N/AC:L"}}]}`,
			wantScore:    5.0,
			wantSeverity: "MEDIUM",
			wantVector:   "AV:N/AC:L",
		},
		{
			name:         "empty_metrics_defaults_high",
			json:         `{}`,
			wantScore:    0,
			wantSeverity: "HIGH",
			wantVector:   "",
		},
		{
			name:         "invalid_json_defaults_high",
			json:         `not json`,
			wantScore:    0,
			wantSeverity: "HIGH",
			wantVector:   "",
		},
		{
			name: "multiple_same_version_picks_highest",
			json: `{"cvssMetricV31":[
				{"cvssData":{"baseScore":5.3,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/A"}},
				{"cvssData":{"baseScore":8.8,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/B"}}
			]}`,
			wantScore:    8.8,
			wantSeverity: "HIGH",
			wantVector:   "CVSS:3.1/B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, severity, vector := parseNVDMetrics(json.RawMessage(tt.json))
			if score != tt.wantScore {
				t.Errorf("score = %.1f, want %.1f", score, tt.wantScore)
			}
			if severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", severity, tt.wantSeverity)
			}
			if vector != tt.wantVector {
				t.Errorf("vector = %q, want %q", vector, tt.wantVector)
			}
		})
	}
}

func TestFirstLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"multiline", "First line\nSecond line\nThird", "First line"},
		{"short", "Short description", "Short description"},
		{"truncates_long", string(make([]byte, 300)), ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill the long byte slice with 'a' for a deterministic test
			if tt.name == "truncates_long" {
				tt.in = string(make([]byte, 300))
				for i := range tt.in {
					tt.in = tt.in[:i] + "a" + tt.in[i+1:]
				}
				got := firstLine(tt.in)
				if len(got) > 200 {
					t.Errorf("firstLine returned %d chars, want <= 200", len(got))
				}
				return
			}
			got := firstLine(tt.in)
			if got != tt.want {
				t.Errorf("firstLine(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestNVDFetch(t *testing.T) {
	src := &NVD{}
	result, err := src.Fetch(context.Background())
	if err != nil {
		t.Skipf("NVD fetch failed (likely 503, expected): %v", err)
	}

	if len(result.CVEs) == 0 {
		t.Fatal("expected NVD CVEs, got 0")
	}
	t.Logf("NVD: %d CVEs fetched", len(result.CVEs))

	// Verify first CVE has required fields
	c := result.CVEs[0]
	if c.CVEID == "" {
		t.Error("NVD CVE missing CVE ID")
	}
	if c.Provider != "nvd" {
		t.Errorf("provider = %q, want \"nvd\"", c.Provider)
	}
	if c.Severity == "" {
		t.Error("NVD CVE missing severity")
	}
	if c.Published == "" {
		t.Error("NVD CVE missing published date")
	}
	// NVD URLs should always be populated
	if c.Data.NVDURL == "" {
		t.Error("NVD CVE missing NVDURL")
	}

	// All CVEs should have a valid severity (no server-side filter anymore)
	for _, cve := range result.CVEs {
		if cve.Severity == "" {
			t.Errorf("CVE %s missing severity", cve.CVEID)
		}
	}

	t.Logf("Sample: CVE=%s Severity=%s Score=%.1f Published=%s",
		c.CVEID, c.Severity, c.Score, c.Published)
}

func TestNVDName(t *testing.T) {
	src := &NVD{}
	if src.Name() != "nvd" {
		t.Errorf("Name() = %q, want \"nvd\"", src.Name())
	}
}

// ---------------------------------------------------------------------------
// Mock-based deterministic tests for fetchEndpoint
// ---------------------------------------------------------------------------

// mockTransport intercepts all HTTP requests regardless of URL, letting us
// test fetchEndpoint without hitting the real NVD API. URLs in the source
// code are hardcoded, so we replace the transport rather than the base URL.
type mockTransport struct {
	handler http.HandlerFunc
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.handler(rec, req)
	return rec.Result(), nil
}

// withMockClient swaps the package-level HTTPClient with a mock that routes
// every request through handler. Original client is restored on cleanup.
func withMockClient(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	orig := HTTPClient
	HTTPClient = &http.Client{Transport: &mockTransport{handler: handler}}
	t.Cleanup(func() { HTTPClient = orig })
}

func TestNVDFetchEndpoint_Normal(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify query params are present
		q := r.URL.Query()
		if q.Get("cvssV3Severity") != "CRITICAL" {
			t.Errorf("query cvssV3Severity = %q, want CRITICAL", q.Get("cvssV3Severity"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{
					"cve": map[string]any{
						"id":       "CVE-2024-12345",
						"published": "2024-06-01T10:00:00.000Z",
						"descriptions": []map[string]any{
							{"lang": "en", "value": "A critical SQL injection vulnerability in the admin panel."},
						},
						"metrics": map[string]any{
							"cvssMetricV31": []map[string]any{
								{"cvssData": map[string]any{
									"baseScore":    9.8,
									"baseSeverity": "CRITICAL",
									"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								}},
							},
						},
						"weaknesses": []map[string]any{
							{"description": []map[string]any{
								{"value": "CWE-89"},
							}},
						},
						"references": []map[string]any{
							{"url": "https://example.com/advisory"},
							{"url": "https://github.com/foo/bar/issues/1"},
						},
					},
				},
			},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "CRITICAL", "cvssV3Severity",
		"2024-06-01T00:00:00.000Z", "2024-06-02T00:00:00.000Z")
	if err != nil {
		t.Fatalf("fetchEndpoint error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1", len(cves))
	}

	c := cves[0]
	if c.CVEID != "CVE-2024-12345" {
		t.Errorf("CVEID = %q, want CVE-2024-12345", c.CVEID)
	}
	if c.Provider != "nvd" {
		t.Errorf("Provider = %q, want nvd", c.Provider)
	}
	if c.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", c.Severity)
	}
	if c.Score != 9.8 {
		t.Errorf("Score = %.1f, want 9.8", c.Score)
	}
	if c.Published != "2024-06-01T10:00:00.000Z" {
		t.Errorf("Published = %q", c.Published)
	}
	if c.Description != "A critical SQL injection vulnerability in the admin panel." {
		t.Errorf("Description mismatch")
	}
	// HasPoC should be true because of github.com reference
	if !c.HasPoC {
		t.Error("HasPoC = false, want true (github.com ref present)")
	}
	// CWE
	if len(c.Data.CWE) != 1 || c.Data.CWE[0] != "CWE-89" {
		t.Errorf("CWE = %v, want [CWE-89]", c.Data.CWE)
	}
	// CVSS vector
	if c.Data.CVSSVector == "" {
		t.Error("CVSSVector empty")
	}
	// NVD URL generated
	wantURL := "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
	if c.Data.NVDURL != wantURL {
		t.Errorf("NVDURL = %q, want %q", c.Data.NVDURL, wantURL)
	}
	// Title = firstLine(desc)
	if c.Data.Title != "A critical SQL injection vulnerability in the admin panel." {
		t.Errorf("Title = %q", c.Data.Title)
	}
}

func TestNVDFetchEndpoint_MultipleCVEs(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cve": map[string]any{
					"id":       "CVE-2024-0001",
					"published": "2024-01-01T00:00:00Z",
					"descriptions": []map[string]any{
						{"lang": "en", "value": "First vuln"},
					},
					"metrics": map[string]any{
						"cvssMetricV31": []map[string]any{
							{"cvssData": map[string]any{"baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/X"}},
						},
					},
				}},
				{"cve": map[string]any{
					"id":       "CVE-2024-0002",
					"published": "2024-01-02T00:00:00Z",
					"descriptions": []map[string]any{
						{"lang": "en", "value": "Second vuln"},
					},
					"metrics": map[string]any{
						"cvssMetricV31": []map[string]any{
							{"cvssData": map[string]any{"baseScore": 9.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/Y"}},
						},
					},
				}},
				{"cve": map[string]any{
					"id":       "CVE-2024-0003",
					"published": "2024-01-03T00:00:00Z",
					"descriptions": []map[string]any{
						{"lang": "en", "value": "Third vuln"},
					},
					"metrics": map[string]any{
						"cvssMetricV31": []map[string]any{
							{"cvssData": map[string]any{"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/Z"}},
						},
					},
				}},
			},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "HIGH", "cvssV3Severity", "", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 3 {
		t.Fatalf("got %d CVEs, want 3", len(cves))
	}
	// All should have unique IDs
	ids := map[string]bool{}
	for _, c := range cves {
		ids[c.CVEID] = true
	}
	if len(ids) != 3 {
		t.Errorf("expected 3 unique IDs, got %d: %v", len(ids), ids)
	}
}

func TestNVDFetchEndpoint_CWETruncation(t *testing.T) {
	// 8 CWE entries → should truncate to max 5
	cweList := make([]map[string]any, 8)
	for i := range cweList {
		cweList[i] = map[string]any{
			"description": []map[string]any{{"value": fmt.Sprintf("CWE-%d", 100+i)}},
		}
	}
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cve": map[string]any{
					"id":          "CVE-2024-CWE",
					"published":   "2024-01-01T00:00:00Z",
					"descriptions": []map[string]any{{"lang": "en", "value": "Test"}},
					"metrics":     map[string]any{},
					"weaknesses":  cweList,
				}},
			},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "HIGH", "cvssV3Severity", "", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1", len(cves))
	}
	if len(cves[0].Data.CWE) > 5 {
		t.Errorf("CWE list = %d items, want <= 5", len(cves[0].Data.CWE))
	}
	if len(cves[0].Data.CWE) != 5 {
		t.Errorf("CWE list = %d items, want exactly 5 (truncated from 8)", len(cves[0].Data.CWE))
	}
}

func TestNVDFetchEndpoint_ExploitRefDetection(t *testing.T) {
	tests := []struct {
		name      string
		refURL    string
		wantExploit bool
	}{
		{"github_ref", "https://github.com/foo/bar/poc", true},
		{"exploit_keyword", "https://example.com/exploit.html", true},
		{"poc_keyword", "https://example.com/poc.txt", true},
		{"packetstorm", "https://packetstormsecurity.com/files/exploit", true},
		{"benign_ref", "https://example.com/blog/post", false},
		{"advisory_ref", "https://nvd.nist.gov/vuln/detail/CVE-2024-X", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{
					"vulnerabilities": []map[string]any{
						{"cve": map[string]any{
							"id":          "CVE-2024-EXP",
							"published":   "2024-01-01T00:00:00Z",
							"descriptions": []map[string]any{{"lang": "en", "value": "Test"}},
							"metrics":     map[string]any{},
							"references":  []map[string]any{{"url": tt.refURL}},
						}},
					},
				})
			})

			src := &NVD{}
			cves, err := src.fetchEndpoint(context.Background(), "HIGH", "cvssV3Severity", "", "")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if cves[0].HasPoC != tt.wantExploit {
				t.Errorf("HasPoC = %v, want %v for ref %q", cves[0].HasPoC, tt.wantExploit, tt.refURL)
			}
			if tt.wantExploit && len(cves[0].Data.ExploitRefs) == 0 {
				t.Errorf("ExploitRefs empty but HasPoC should be true")
			}
		})
	}
}

func TestNVDFetchEndpoint_RefTruncation(t *testing.T) {
	// 12 references → should truncate to max 8
	refs := make([]map[string]any, 12)
	for i := range refs {
		refs[i] = map[string]any{"url": fmt.Sprintf("https://example.com/ref/%d", i)}
	}
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cve": map[string]any{
					"id":          "CVE-2024-REFS",
					"published":   "2024-01-01T00:00:00Z",
					"descriptions": []map[string]any{{"lang": "en", "value": "Test"}},
					"metrics":     map[string]any{},
					"references":  refs,
				}},
			},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "HIGH", "cvssV3Severity", "", "")
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

func TestNVDFetchEndpoint_EmptyVulns(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "CRITICAL", "cvssV3Severity", "", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 0 {
		t.Errorf("got %d CVEs, want 0 for empty vulns", len(cves))
	}
}

func TestNVDFetchEndpoint_HTTP503(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "CRITICAL", "cvssV3Severity", "", "")
	if err == nil {
		t.Fatal("expected error for HTTP 503, got nil")
	}
	if len(cves) != 0 {
		t.Errorf("got %d CVEs, want 0 for 503", len(cves))
	}
}

func TestNVDFetchEndpoint_MalformedJSON(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json at all`))
	})

	src := &NVD{}
	_, err := src.fetchEndpoint(context.Background(), "CRITICAL", "cvssV3Severity", "", "")
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestNVDFetchEndpoint_NoEnglishDesc(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cve": map[string]any{
					"id":       "CVE-2024-NODESC",
					"published": "2024-01-01T00:00:00Z",
					"descriptions": []map[string]any{
						{"lang": "fr", "value": "Vulnérabilité en français"},
						{"lang": "de", "value": "Schwachstelle auf Deutsch"},
					},
					"metrics": map[string]any{},
				}},
			},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "HIGH", "cvssV3Severity", "", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1", len(cves))
	}
	// No English description → desc should be empty
	if cves[0].Description != "" {
		t.Errorf("Description = %q, want empty (no en desc)", cves[0].Description)
	}
}

func TestNVDFetchEndpoint_EmptyIDSkipped(t *testing.T) {
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cve": map[string]any{
					"id":       "",
					"published": "2024-01-01T00:00:00Z",
					"descriptions": []map[string]any{{"lang": "en", "value": "Should be skipped"}},
					"metrics":  map[string]any{},
				}},
				{"cve": map[string]any{
					"id":       "CVE-2024-VALID",
					"published": "2024-01-02T00:00:00Z",
					"descriptions": []map[string]any{{"lang": "en", "value": "Should be kept"}},
					"metrics":  map[string]any{},
				}},
			},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "HIGH", "cvssV3Severity", "", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1 (empty ID skipped)", len(cves))
	}
	if cves[0].CVEID != "CVE-2024-VALID" {
		t.Errorf("CVEID = %q, want CVE-2024-VALID", cves[0].CVEID)
	}
}

func TestNVDFetchEndpoint_CVSS4Priority(t *testing.T) {
	// Both CVSS 4.0 and 3.1 present — should pick highest score
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cve": map[string]any{
					"id":       "CVE-2024-CVSS4",
					"published": "2024-01-01T00:00:00Z",
					"descriptions": []map[string]any{{"lang": "en", "value": "Test"}},
					"metrics": map[string]any{
						"cvssMetricV40": []map[string]any{
							{"cvssData": map[string]any{"baseScore": 9.9, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/A"}},
						},
						"cvssMetricV31": []map[string]any{
							{"cvssData": map[string]any{"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/B"}},
						},
					},
				}},
			},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "CRITICAL", "cvssV4Severity", "", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cves[0].Score != 9.9 {
		t.Errorf("Score = %.1f, want 9.9 (highest)", cves[0].Score)
	}
	if cves[0].Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", cves[0].Severity)
	}
	if cves[0].Data.CVSSVector != "CVSS:4.0/A" {
		t.Errorf("CVSSVector = %q, want CVSS:4.0/A", cves[0].Data.CVSSVector)
	}
}

func TestNVDFetchEndpoint_NonEnglishFiltered(t *testing.T) {
	// Multiple descriptions — English one should be picked
	withMockClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []map[string]any{
				{"cve": map[string]any{
					"id":       "CVE-2024-LANG",
					"published": "2024-01-01T00:00:00Z",
					"descriptions": []map[string]any{
						{"lang": "es", "value": "Vulnerabilidad en español"},
						{"lang": "en", "value": "English description wins"},
						{"lang": "ja", "value": "日本語の説明"},
					},
					"metrics": map[string]any{},
				}},
			},
		})
	})

	src := &NVD{}
	cves, err := src.fetchEndpoint(context.Background(), "HIGH", "cvssV3Severity", "", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cves[0].Description != "English description wins" {
		t.Errorf("Description = %q, want English version", cves[0].Description)
	}
}
