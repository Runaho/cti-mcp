package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Runaho/cti-mcp/internal/store"
)

// NVD fetches CVE data from the NVD API 2.0. NVD is notoriously unreliable
// (frequent 503s), so failures are expected and handled gracefully.
type NVD struct{}

func (s *NVD) Name() string       { return "nvd" }
func (s *NVD) TTL() time.Duration { return time.Hour }

// fetchSequentially fetches all recent CVEs in a single request (no severity
// filter) and filters client-side. NVD's severity filter params are unreliable
// (cvssV3Severity=CRITICAL returns 503/404 randomly, cvssV4Severity same).
// A plain date-range query is the only stable endpoint.
func (s *NVD) fetchSequentially(ctx context.Context, start, end string) ([]store.CVE, error) {
	return s.fetchEndpoint(ctx, "", "", start, end)
}

func (s *NVD) Fetch(ctx context.Context) (*FetchResult, error) {
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour).Format(time.RFC3339)
	end := now.Format(time.RFC3339)

	cves, err := s.fetchSequentially(ctx, start, end)
	if err != nil {
		return &FetchResult{}, err
	}

	if len(cves) == 0 {
		return &FetchResult{}, fmt.Errorf("nvd: no CVEs in 24h window")
	}

	return &FetchResult{CVEs: cves}, nil
}

func (s *NVD) fetchEndpoint(ctx context.Context, severity, stype, start, end string) ([]store.CVE, error) {
	var url string
	if severity != "" && stype != "" {
		url = fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?%s=%s&pubStartDate=%s&pubEndDate=%s&resultsPerPage=2000",
			stype, severity, start, end)
	} else {
		// No severity filter — fetch all CVEs in date range, filter client-side.
		// This is the only stable NVD endpoint; severity filters 503/404 randomly.
		url = fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=%s&pubEndDate=%s&resultsPerPage=2000",
			start, end)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if key := nvdAPIKey(); key != "" {
		req.Header.Set("apiKey", key)
	}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse metrics manually since the structure varies
	var raw struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics    json.RawMessage `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("nvd parse: %w", err)
	}

	var cves []store.CVE
	for _, v := range raw.Vulnerabilities {
		cve := v.CVE
		if cve.ID == "" {
			continue
		}

		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		score, severity, vector := parseNVDMetrics(cve.Metrics)

		var cweList []string
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if d.Value != "" {
					cweList = append(cweList, d.Value)
				}
			}
		}

		var refs []string
		var exploitRefs []string
		for _, r := range cve.References {
			refs = append(refs, r.URL)
			lower := strings.ToLower(r.URL)
			if strings.Contains(lower, "exploit") || strings.Contains(lower, "poc") ||
				strings.Contains(lower, "github.com") || strings.Contains(lower, "packetstorm") {
				exploitRefs = append(exploitRefs, r.URL)
			}
		}

		if len(cweList) > 5 {
			cweList = cweList[:5]
		}
		if len(refs) > 8 {
			refs = refs[:8]
		}

		cves = append(cves, store.CVE{
			CVEID:       cve.ID,
			Provider:    "nvd",
			Providers:   []string{"nvd"},
			Severity:    severity,
			Score:       score,
			Description: desc,
			Published:   cve.Published,
			HasPoC:      len(exploitRefs) > 0,
			Data: store.CVEData{
				Title:       firstLine(desc),
				CVSSVector:  vector,
				CWE:         cweList,
				References:  refs,
				ExploitRefs: exploitRefs,
				NVDURL:      fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID),
			},
		})
	}

	return cves, nil
}

func parseNVDMetrics(raw json.RawMessage) (score float64, severity, vector string) {
	var metrics map[string][]struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
			VectorString string  `json:"vectorString"`
		} `json:"cvssData"`
	}
	if err := json.Unmarshal(raw, &metrics); err != nil {
		return 0, "HIGH", ""
	}

	for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		for _, m := range metrics[key] {
			if m.CVSSData.BaseScore > score {
				score = m.CVSSData.BaseScore
				severity = strings.ToUpper(m.CVSSData.BaseSeverity)
				vector = m.CVSSData.VectorString
			}
		}
	}

	if severity == "" {
		severity = "HIGH"
	}
	return
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx > 0 {
		return s[:idx]
	}
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}

func nvdAPIKey() string {
	return os.Getenv("NVD_API_KEY")
}
