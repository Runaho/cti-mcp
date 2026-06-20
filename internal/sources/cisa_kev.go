package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Runaho/cti-mcp/internal/store"
)

// CISAKEV fetches the CISA Known Exploited Vulnerabilities catalog.
type CISAKEV struct{}

func (s *CISAKEV) Name() string    { return "cisa_kev" }
func (s *CISAKEV) TTL() time.Duration { return time.Hour }

type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID          string `json:"cveID"`
		VendorProduct  string `json:"product"`
		VulnName       string `json:"vulnerabilityName"`
		DateAdded      string `json:"dateAdded"`
		DueDate        string `json:"dueDate"`
		RequiredAction string `json:"requiredAction"`
	} `json:"vulnerabilities"`
}

func (s *CISAKEV) Fetch(ctx context.Context) (*FetchResult, error) {
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kev request: %w", err)
	}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev fetch: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("kev read: %w", err)
	}

	var catalog kevCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("kev parse: %w", err)
	}

	now := time.Now()
	entries := make([]store.KEVEntry, 0, len(catalog.Vulnerabilities))
	kevIDs := make(map[string]bool)

	for _, v := range catalog.Vulnerabilities {
		if v.CVEID == "" {
			continue
		}
		daysLeft := 0
		if v.DueDate != "" {
			if due, err := time.Parse("2006-01-02", v.DueDate); err == nil {
				daysLeft = int(due.Sub(now).Hours() / 24)
			}
		}
		entries = append(entries, store.KEVEntry{
			CVEID:          v.CVEID,
			VendorProduct:  v.VendorProduct,
			VulnName:       v.VulnName,
			DateAdded:      v.DateAdded,
			DueDate:        v.DueDate,
			RequiredAction: v.RequiredAction,
			DaysLeft:       daysLeft,
		})
		kevIDs[v.CVEID] = true
	}

	// Also create CVE entries marking them as in_kev
	cves := make([]store.CVE, 0, len(entries))
	for _, e := range entries {
		cves = append(cves, store.CVE{
			CVEID:    e.CVEID,
			Provider: "kev",
			Providers: []string{"kev"},
			Severity: "HIGH",
			InKEV:    true,
			Published: e.DateAdded,
			Description: e.VulnName,
			Data: store.CVEData{
				Title:          e.VulnName,
				Product:        e.VendorProduct,
				RequiredAction: e.RequiredAction,
				NVDURL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", e.CVEID),
			},
		})
	}

	return &FetchResult{
		CVEs:       cves,
		KEVEntries: entries,
	}, nil
}
