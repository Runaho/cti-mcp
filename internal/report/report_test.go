package report

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Runaho/cti-mcp/internal/sources"
	"github.com/Runaho/cti-mcp/internal/store"
)

// TestRenderWithRealData is an integration test that fetches the live CISA
// KEV catalog from the network. It is skipped under `go test -short` so the
// unit suite (including TestRenderWithSyntheticData below) stays
// deterministic and offline.
func TestRenderWithRealData(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires network access to CISA KEV")
	}

	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := store.InitSchema(s.DB()); err != nil {
		t.Fatal(err)
	}

	// Fetch real KEV data to populate
	kev := &sources.CISAKEV{}
	result, err := kev.Fetch(context.Background())
	if err != nil {
		t.Skipf("network error: %v", err)
	}

	// Insert some CVEs
	for i, cve := range result.CVEs {
		if i >= 20 {
			break
		}
		store.UpsertCVE(s.DB(), cve)
	}
	for i, kev := range result.KEVEntries {
		if i >= 20 {
			break
		}
		store.UpsertKEV(s.DB(), kev)
	}

	// 1 year window: effectively no time filter, ensures the test stays
	// stable as the live KEV catalog ages.
	html, err := GenerateHTML(s, 8760)
	if err != nil {
		t.Fatal(err)
	}

	if len(html) == 0 {
		t.Fatal("report HTML is empty")
	}

	// Write to temp file for inspection
	tmpFile := "/tmp/cti_mcp_test_report.html"
	if err := os.WriteFile(tmpFile, []byte(html), 0644); err != nil {
		t.Fatal(err)
	}

	t.Logf("Report generated: %d bytes -> %s", len(html), tmpFile)

	if !strings.Contains(html, "<html") {
		t.Error("missing <html tag")
	}
	if !strings.Contains(html, "CVE-") {
		t.Error("no CVE IDs in report")
	}
}

// TestRenderWithSyntheticData covers the HTML render path with no network
// dependency. It is the offline counterpart of TestRenderWithRealData and
// runs under `go test -short`.
func TestRenderWithSyntheticData(t *testing.T) {
	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := store.InitSchema(s.DB()); err != nil {
		t.Fatal(err)
	}

	cves := []store.CVE{
		{
			CVEID:     "CVE-2026-9001",
			Provider:  "nvd",
			Severity:  "CRITICAL",
			Score:     9.8,
			InKEV:     true,
			HasPoC:    true,
			Published: time.Now().UTC().Format(time.RFC3339),
		},
		{
			CVEID:     "CVE-2026-9002",
			Provider:  "nvd",
			Severity:  "HIGH",
			Score:     8.1,
			InKEV:     false,
			HasPoC:    false,
			Published: time.Now().UTC().Format(time.RFC3339),
		},
	}
	for _, c := range cves {
		if err := store.UpsertCVE(s.DB(), c); err != nil {
			t.Fatalf("upsert %s: %v", c.CVEID, err)
		}
	}

	kev := store.KEVEntry{
		CVEID:         "CVE-2026-9001",
		VendorProduct: "demo/example",
		VulnName:      "Demo SQL injection",
		DateAdded:     time.Now().UTC().Format("2006-01-02"),
		RequiredAction: "Apply vendor patch",
	}
	if err := store.UpsertKEV(s.DB(), kev); err != nil {
		t.Fatalf("upsert kev: %v", err)
	}

	html, err := GenerateHTML(s, 8760)
	if err != nil {
		t.Fatal(err)
	}
	if len(html) == 0 {
		t.Fatal("report HTML is empty")
	}
	if !strings.Contains(html, "<html") {
		t.Error("missing <html tag")
	}
	if !strings.Contains(html, "CVE-2026-9001") {
		t.Error("expected synthetic CVE-2026-9001 in report")
	}
}

func TestMd2htmlXSS(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"script tag", `<script>alert(1)</script>`},
		{"img onerror", `<img src=x onerror=alert(1)>`},
		{"svg onload", `<svg onload=alert(1)>`},
		{"javascript URL", `[click](javascript:alert(1))`},
		{"inline event", `<a href="x" onclick="alert(1)">click</a>`},
		{"escaped quotes", `<input value="\" onmouseover=\"alert(1)">`},
		{"markdown with XSS", `**bold** <script>alert(1)</script> text`},
		{"code block XSS", "```html\n<script>alert(1)</script>\n```"},
		{"inline code XSS", "`<script>alert(1)</script>`"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := md2html(tt.input)
			lower := strings.ToLower(output)

			// The key check: no unescaped HTML tags should survive.
			// html.EscapeString converts < to &lt; and > to &gt;,
			// so any <tag> in the input becomes &lt;tag&gt; — safe text.
			// We check for literal < followed by known dangerous tag names.
			dangerousTags := []string{"<script", "<img", "<svg", "<iframe", "<object", "<embed"}
			for _, tag := range dangerousTags {
				if strings.Contains(lower, tag) {
					t.Errorf("XSS: unescaped %s tag found in output for input %q\nOutput: %s", tag, tt.input, output)
				}
			}

			// Check no javascript: protocol in an actual href attribute
			// (not in escaped text). Only matters if we have a real <a tag.
			if strings.Contains(lower, `href="javascript:`) {
				t.Errorf("XSS: javascript: protocol in href for input %q\nOutput: %s", tt.input, output)
			}

			// Check that our own generated <a> tags (from urlRe) don't
			// contain javascript: protocol
			if strings.Contains(lower, `<a href="javascript:`) {
				t.Errorf("XSS: generated <a> tag with javascript: protocol for input %q\nOutput: %s", tt.input, output)
			}
		})
	}
}
