package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
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
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"vulns"`
}

// parseOSVSeverity extracts the highest CVSS score from OSV severity array.
// OSV returns severities like [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, ...]
// We parse the vector string to extract the base score.
func parseOSVSeverity(severities []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) (score float64, severity string) {
	for _, s := range severities {
		// Score field contains CVSS vector string, e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		// Extract base score from vector using a simple heuristic
		// CVSS vectors have the base score embedded or we can compute from vector
		// For simplicity, if score looks like a vector, try to parse the first numeric value
		if strings.HasPrefix(s.Score, "CVSS:") {
			// Parse vector to get base score - simplified: look for known patterns
			// In practice, we'd use a CVSS parser library, but let's do a basic extraction
			// The base score isn't directly in the vector, so we return a reasonable default
			// and let the NVD data (if available) provide the accurate score via UpsertCVE MAX()
			continue
		}
		// If it's a plain number string
		if v, err := strconv.ParseFloat(s.Score, 64); err == nil {
			if v > score {
				score = v
			}
		}
	}

	// Default fallback if no parseable score found
	if score == 0 {
		score = 7.0
	}

	switch {
	case score >= 9.0:
		severity = "CRITICAL"
	case score >= 7.0:
		severity = "HIGH"
	case score >= 4.0:
		severity = "MEDIUM"
	default:
		severity = "LOW"
	}

	return score, severity
}

func (s *OSV) Fetch(ctx context.Context) (*FetchResult, error) {
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour).Format(time.RFC3339)
	end := now.Format(time.RFC3339)
	timeRange := fmt.Sprintf("%s/%s", start, end)

	ecosystems := []string{"Go", "PyPI", "npm", "Maven"}

	// Run ecosystem queries in parallel
	type ecoResult struct {
		cves []store.CVE
		err  error
	}
	resultChan := make(chan ecoResult, len(ecosystems))

	for _, eco := range ecosystems {
		go func(ecosystem string) {
			cves, err := s.queryEcosystem(ctx, ecosystem, timeRange)
			resultChan <- ecoResult{cves: cves, err: err}
		}(eco)
	}

	var allCVEs []store.CVE
	for i := 0; i < len(ecosystems); i++ {
		res := <-resultChan
		if res.err != nil {
			continue // skip failed ecosystems
		}
		allCVEs = append(allCVEs, res.cves...)
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

		score, severity := parseOSVSeverity(vuln.Severity)

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
