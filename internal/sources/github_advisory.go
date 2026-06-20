package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Runaho/cti-mcp/internal/store"
)

// GitHubAdvisory fetches CRITICAL and HIGH advisories from the GitHub Security Advisory API.
type GitHubAdvisory struct{}

func (s *GitHubAdvisory) Name() string    { return "github_advisory" }
func (s *GitHubAdvisory) TTL() time.Duration { return 30 * time.Minute }

type ghAdvisory struct {
	GHSAID    string  `json:"ghsa_id"`
	CVEID     *string `json:"cve_id"`
	Summary   string  `json:"summary"`
	Description string `json:"description"`
	Severity  string  `json:"severity"`
	Score     *float64 `json:"cvss_score"`
	CVSS      *struct {
		Score       *float64 `json:"score"`
		VectorString string   `json:"vector_string"`
		Severity     string   `json:"severity"`
	} `json:"cvss"`
	CWEs []struct {
		CWEID string `json:"cwe_id"`
		Name  string `json:"name"`
	} `json:"cwes"`
	EPSS *struct {
		Percentage float64 `json:"percentage"`
		Percentile float64 `json:"percentile"`
	} `json:"epss"`
	References []string `json:"references"`
	HTMLURL    string   `json:"html_url"`
	PublishedAt string  `json:"published_at"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    any    `json:"first_patched_version"`
	} `json:"vulnerabilities"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	Aliases []string `json:"aliases"`
}

func (s *GitHubAdvisory) Fetch(ctx context.Context) (*FetchResult, error) {
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	var allCVEs []store.CVE

	for _, severity := range []string{"critical", "high"} {
		cves, err := s.fetchSeverity(ctx, severity, since)
		if err != nil {
			return nil, fmt.Errorf("gh advisory %s: %w", severity, err)
		}
		allCVEs = append(allCVEs, cves...)
	}

	return &FetchResult{CVEs: allCVEs}, nil
}

func (s *GitHubAdvisory) fetchSeverity(ctx context.Context, severity, since string) ([]store.CVE, error) {
	url := fmt.Sprintf("https://api.github.com/advisories?type=reviewed&severity=%s&per_page=50&published_since=%s", severity, since)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token := GitHubToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gh advisory fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gh advisory HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var advisories []ghAdvisory
	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil, fmt.Errorf("gh advisory parse: %w", err)
	}

	var cves []store.CVE
	for _, adv := range advisories {
		cveIDs := s.extractCVEIDs(adv)
		if len(cveIDs) == 0 {
			continue
		}

		data := s.parseAdvisoryData(adv)
		sev := strings.ToUpper(adv.Severity)
		if sev == "" {
			sev = "HIGH"
		}
		score := 7.0
		if sev == "CRITICAL" {
			score = 10.0
		}
		if adv.CVSS != nil && adv.CVSS.Score != nil {
			score = *adv.CVSS.Score
		}
		if adv.Score != nil {
			score = *adv.Score
		}

		for _, cveID := range cveIDs {
			cves = append(cves, store.CVE{
				CVEID:       cveID,
				Provider:    "ghadv",
				Providers:   []string{"ghadv"},
				Severity:    sev,
				Score:       score,
				Description: adv.Description,
				Published:   adv.PublishedAt,
				Category:    data.Ecosystem,
				Data:        data,
				HasPoC:      len(data.ExploitRefs) > 0 || len(data.PoCLinks) > 0,
			})
		}
	}

	return cves, nil
}

func (s *GitHubAdvisory) extractCVEIDs(adv ghAdvisory) []string {
	seen := make(map[string]bool)
	var ids []string

	if adv.CVEID != nil && strings.HasPrefix(*adv.CVEID, "CVE-") {
		ids = append(ids, *adv.CVEID)
		seen[*adv.CVEID] = true
	}
	for _, ident := range adv.Identifiers {
		if ident.Type == "CVE" && strings.HasPrefix(ident.Value, "CVE-") && !seen[ident.Value] {
			ids = append(ids, ident.Value)
			seen[ident.Value] = true
		}
	}
	for _, alias := range adv.Aliases {
		if strings.HasPrefix(alias, "CVE-") && !seen[alias] {
			ids = append(ids, alias)
			seen[alias] = true
		}
	}

	return ids
}

func (s *GitHubAdvisory) parseAdvisoryData(adv ghAdvisory) store.CVEData {
	data := store.CVEData{
		Title:      adv.Summary,
		GHSAURL:    adv.HTMLURL,
		References: adv.References,
	}

	if adv.CVSS != nil {
		data.CVSSVector = adv.CVSS.VectorString
	}
	if adv.EPSS != nil {
		data.EPSSPct = adv.EPSS.Percentage
		data.EPSSPctile = adv.EPSS.Percentile
	}

	// Extract exploit/PoC refs
	for _, ref := range adv.References {
		lower := strings.ToLower(ref)
		if strings.Contains(lower, "exploit") || strings.Contains(lower, "poc") ||
			strings.Contains(lower, "packetstorm") || strings.Contains(lower, "securiteam") ||
			strings.Contains(lower, "zerodayinitiative") {
			data.ExploitRefs = append(data.ExploitRefs, ref)
		}
		if strings.Contains(lower, "github.com") &&
			(strings.Contains(lower, "poc") || strings.Contains(lower, "exploit") ||
				strings.Contains(lower, "security/advisories")) {
			data.PoCLinks = append(data.PoCLinks, ref)
		}
	}

	// CWE
	for _, c := range adv.CWEs {
		if c.CWEID != "" {
			data.CWE = append(data.CWE, c.CWEID)
		}
		if c.Name != "" {
			data.CWENames = append(data.CWENames, c.Name)
		}
	}

	// Package info
	if len(adv.Vulnerabilities) > 0 {
		v := adv.Vulnerabilities[0]
		if v.Package.Ecosystem != "" || v.Package.Name != "" {
			data.Product = fmt.Sprintf("%s/%s", v.Package.Ecosystem, v.Package.Name)
			data.Ecosystem = strings.ToLower(v.Package.Ecosystem)
		}
		data.VulnRange = v.VulnerableVersionRange
		if v.FirstPatchedVersion != nil {
			data.PatchedVer = fmt.Sprintf("%v", v.FirstPatchedVersion)
		}
	}

	// NVD URL
	for _, cveID := range s.extractCVEIDs(adv) {
		data.NVDURL = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
		break
	}

	return data
}
