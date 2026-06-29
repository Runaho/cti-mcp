package report

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Runaho/cti-mcp/internal/sources"
	"github.com/Runaho/cti-mcp/internal/store"
)

func TestRenderWithRealData(t *testing.T) {
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

	// Generate report
	html, err := GenerateHTML(s, 8760) // 1 year = no effective filter for test data
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

	t.Logf("Report generated: %d bytes → %s", len(html), tmpFile)

	// Basic structure checks
	if !strings.Contains(html, "<html") {
		t.Error("missing <html tag")
	}
	if !strings.Contains(html, "CVE-") {
		t.Error("no CVE IDs in report")
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
