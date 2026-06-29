package report

import (
	"strings"
	"testing"
)

func TestRenderMarkdown_HeaderAndStats(t *testing.T) {
	r := &CTIReport{
		Meta: Meta{
			GeneratedAt: "2026-06-29T12:00:00Z",
			WindowHours: 24,
			P1:          3,
			P2:          5,
			P3:          7,
			TotalUnique: 15,
			Sources:     "nvd 5000 + kev 1300",
		},
	}
	out, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	wantStrings := []string{
		"# CTI Threat Report",
		"Generated: 2026-06-29T12:00:00Z",
		"Window: 24 hours",
		"Sources: nvd 5000 + kev 1300",
		"## Stats",
		"- P1 CRITICAL: 3",
		"- P2 HIGH: 5",
		"- P3 STANDARD: 7",
	}
	for _, w := range wantStrings {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in markdown output", w)
		}
	}
}

func TestRenderMarkdown_EmptySectionsOmitted(t *testing.T) {
	r := &CTIReport{
		Meta: Meta{GeneratedAt: "2026-06-29T12:00:00Z", WindowHours: 24},
	}
	out, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "## KEV Recent") {
		t.Error("KEV section must be omitted when KEVRecent is empty")
	}
	if strings.Contains(out, "## Sectors") {
		t.Error("Sectors section must be omitted when Sectors is empty")
	}
}

func TestRenderMarkdown_KEVAndSectors(t *testing.T) {
	r := &CTIReport{
		Meta: Meta{
			GeneratedAt: "2026-06-29T12:00:00Z",
			WindowHours: 24,
		},
		KEVRecent: []KEV{
			{
				CVEID:          "CVE-2026-1001",
				VendorProduct:  "demo | with-pipe",
				DateAdded:      "2026-06-28",
				RequiredAction: "Apply vendor patch",
			},
		},
		Sectors: []Sector{
			{
				Name: "Web Vulnerabilities",
				CVEs: []CVE{
					{
						ID:       "CVE-2026-2002",
						Title:    strings.Repeat("long-title-", 30),
						Severity: "HIGH",
						GHSAURL:  "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
						NVDURL:   "https://nvd.nist.gov/vuln/detail/CVE-2026-2002",
					},
				},
			},
		},
	}
	out, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "## KEV Recent (1 entries)") {
		t.Error("expected KEV Recent header with count")
	}
	// Pipe character in vendor must be escaped so the row stays a single
	// Markdown table row.
	if !strings.Contains(out, `demo \| with-pipe`) {
		t.Error("expected pipe in vendor string to be escaped")
	}
	if !strings.Contains(out, "Apply vendor patch") {
		t.Error("expected KEV required_action text")
	}
	if !strings.Contains(out, "## Sectors") {
		t.Error("expected Sectors header")
	}
	if !strings.Contains(out, "### Web Vulnerabilities") {
		t.Error("expected per-sector heading")
	}
	if !strings.Contains(out, "[more](https://github.com/advisories/GHSA-xxxx-yyyy-zzzz)") {
		t.Error("expected GHSA URL link in markdown format")
	}
	if !strings.Contains(out, "HIGH") {
		t.Error("expected severity text")
	}
	// Title should be trimmed to <= 80 runes + "..."
	if strings.Contains(out, strings.Repeat("long-title-", 30)) {
		t.Error("title longer than 80 chars must be trimmed")
	}
}

func TestRenderMarkdown_SectorFallbackURL(t *testing.T) {
	r := &CTIReport{
		Meta: Meta{GeneratedAt: "2026-06-29T12:00:00Z", WindowHours: 24},
		Sectors: []Sector{
			{
				Name: "Other",
				CVEs: []CVE{
					{
						ID:       "CVE-2026-3003",
						Severity: "MEDIUM",
						// No GHSA or NVD URL -> fallback to https://nvd.nist.gov/vuln/detail/CVE-2026-3003
					},
				},
			},
		},
	}
	out, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "https://nvd.nist.gov/vuln/detail/CVE-2026-3003") {
		t.Error("expected NVD fallback URL when GHSA URL is missing")
	}
}

func TestRenderMarkdown_KEVRequiredActionPipeEscaped(t *testing.T) {
	r := &CTIReport{
		Meta: Meta{GeneratedAt: "2026-06-29T12:00:00Z", WindowHours: 24},
		KEVRecent: []KEV{
			{
				CVEID:          "CVE-2026-4004",
				VendorProduct:  "demo/vendor",
				DateAdded:      "2026-06-28",
				RequiredAction: "Apply | restart service | verify",
			},
		},
	}
	out, err := RenderMarkdown(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `Apply \| restart service \| verify`) {
		t.Error("expected pipe characters in RequiredAction to be escaped")
	}
	if strings.Contains(out, "Apply | restart service | verify") {
		t.Error("un-escaped pipe in RequiredAction would break the markdown row")
	}
}

func TestRenderMarkdown_NilReport(t *testing.T) {
	if _, err := RenderMarkdown(nil); err == nil {
		t.Error("expected error when CTIReport is nil")
	}
}
