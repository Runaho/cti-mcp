package sources

import (
	"context"
	"testing"
)

func TestCISAKEVFetch(t *testing.T) {
	src := &CISAKEV{}
	result, err := src.Fetch(context.Background())
	if err != nil {
		t.Skipf("KEV fetch failed (network?): %v", err)
	}

	if len(result.CVEs) == 0 {
		t.Fatal("expected KEV CVEs, got 0")
	}
	t.Logf("KEV: %d CVEs, %d KEV entries", len(result.CVEs), len(result.KEVEntries))

	// Verify first entry
	if len(result.KEVEntries) > 0 {
		e := result.KEVEntries[0]
		if e.CVEID == "" {
			t.Error("KEV entry missing CVE ID")
		}
		if e.VendorProduct == "" {
			t.Error("KEV entry missing vendor/product")
		}
		t.Logf("Sample: CVE=%s Product=%s DateAdded=%s", e.CVEID, e.VendorProduct, e.DateAdded)
	}

	// Verify a CVE entry has InKEV=true
	foundKEV := false
	for _, c := range result.CVEs {
		if c.InKEV {
			foundKEV = true
			break
		}
	}
	if !foundKEV {
		t.Error("no CVE entries with InKEV=true")
	}
}
