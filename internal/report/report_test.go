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
	html, err := GenerateHTML(s, 24)
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
