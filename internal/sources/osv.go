package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Runaho/cti-mcp/internal/store"
)

// OSV fetches vulnerability data from OSV.dev for multiple ecosystems.
type OSV struct{}

func (s *OSV) Name() string       { return "osv" }
func (s *OSV) TTL() time.Duration { return time.Hour }

type osvResponse struct {
	Vulns []struct {
		ID        string   `json:"id"`
		Aliases   []string `json:"aliases"`
		Summary   string   `json:"summary"`
		Details   string   `json:"details"`
		Published string   `json:"published"`
		Severity  []struct {
			Score string `json:"score"`
		} `json:"severity"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"vulns"`
}

func (s *OSV) Fetch(ctx context.Context) (*FetchResult, error) {
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour).Format(time.RFC3339)
	end := now.Format(time.RFC3339)
	timeRange := fmt.Sprintf("%s/%s", start, end)

	ecosystems := []string{"Go", "PyPI", "npm", "Maven"}
	var allCVEs []store.CVE

	for _, eco := range ecosystems {
		cves, err := s.queryEcosystem(ctx, eco, timeRange)
		if err != nil {
			continue
		}
		allCVEs = append(allCVEs, cves...)
	}

	return &FetchResult{CVEs: allCVEs}, nil
}

func (s *OSV) queryEcosystem(ctx context.Context, ecosystem, timeRange string) ([]store.CVE, error) {
	payload, _ := json.Marshal(map[string]string{
		"ecosystem": ecosystem,
		"published": timeRange,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.osv.dev/v1/query", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result osvResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var cves []store.CVE
	for _, vuln := range result.Vulns {
		var cveID string
		for _, alias := range vuln.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				cveID = alias
				break
			}
		}
		if cveID == "" {
			continue
		}

		desc := vuln.Summary
		if desc == "" && vuln.Details != "" {
			if len(vuln.Details) > 300 {
				desc = vuln.Details[:300]
			} else {
				desc = vuln.Details
			}
		}

		score := 7.0
		severity := "HIGH"
		if score >= 9.0 {
			severity = "CRITICAL"
		}

		var refs []string
		for _, r := range vuln.References {
			refs = append(refs, r.URL)
		}
		if len(refs) > 8 {
			refs = refs[:8]
		}

		cves = append(cves, store.CVE{
			CVEID:       cveID,
			Provider:    "osv",
			Providers:   []string{"osv"},
			Severity:    severity,
			Score:       score,
			Description: desc,
			Published:   vuln.Published,
			Data: store.CVEData{
				Title:      firstLine(desc),
				Ecosystem:  strings.ToLower(ecosystem),
				References: refs,
				NVDURL:     fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID),
			},
		})
	}

	return cves, nil
}
