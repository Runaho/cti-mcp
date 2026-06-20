package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Runaho/cti-mcp/internal/store"
)

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// GitHubPoC searches GitHub for CVE exploit and PoC repositories.
type GitHubPoC struct{}

func (s *GitHubPoC) Name() string    { return "github_poc" }
func (s *GitHubPoC) TTL() time.Duration { return 2 * time.Hour }

type ghSearchResult struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		FullName    string `json:"full_name"`
		Description string `json:"description"`
		HTMLURL     string `json:"html_url"`
		Stars       int    `json:"stargazers_count"`
		PushedAt    string `json:"pushed_at"`
	} `json:"items"`
}

func (s *GitHubPoC) Fetch(ctx context.Context) (*FetchResult, error) {
	dateSince := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	var allCVEs []store.CVE

	// Search 1: CVE exploit repos
	exploitCVEs, err := s.searchRepos(ctx, fmt.Sprintf(
		"CVE 2026 exploit pushed:>%s", dateSince), "updated", "exploit")
	if err != nil {
		return nil, fmt.Errorf("gh poc exploit search: %w", err)
	}
	allCVEs = append(allCVEs, exploitCVEs...)

	// Search 2: CVE PoC repos
	pocCVEs, err := s.searchRepos(ctx, fmt.Sprintf(
		"CVE 2026 PoC pushed:>%s", dateSince), "stars", "PoC")
	if err != nil {
		return nil, fmt.Errorf("gh poc search: %w", err)
	}
	allCVEs = append(allCVEs, pocCVEs...)

	return &FetchResult{CVEs: allCVEs}, nil
}

func (s *GitHubPoC) searchRepos(ctx context.Context, query, sortBy, label string) ([]store.CVE, error) {
	url := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=%s&order=desc&per_page=30",
		query, sortBy)

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
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gh search HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result ghSearchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var cves []store.CVE
	for _, repo := range result.Items {
		cveIDs := cveRe.FindAllString(repo.FullName+" "+repo.Description, -1)
		seen := make(map[string]bool)
		for _, cid := range cveIDs {
			if seen[cid] {
				continue
			}
			seen[cid] = true
			desc := fmt.Sprintf("%s: %s", repo.FullName, truncate(repo.Description, 200))
			cves = append(cves, store.CVE{
				CVEID:       cid,
				Provider:    fmt.Sprintf("gh-%s", label),
				Providers:   []string{fmt.Sprintf("gh-%s", label)},
				Severity:    "CRITICAL",
				Score:       9.0,
				Description: desc,
				Published:   repo.PushedAt,
				HasPoC:      true,
				Data: store.CVEData{
					Title:       repo.FullName,
					PoCLinks:    []string{repo.HTMLURL},
					ExploitRefs: []string{repo.HTMLURL},
					References:  []string{repo.HTMLURL},
					NVDURL:      fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cid),
				},
			})
		}

		// Standalone PoC repos (no CVE ID but high stars)
		if len(cveIDs) == 0 && repo.Stars >= 5 && label == "PoC" {
			repoID := "GH-" + strings.ReplaceAll(repo.FullName, "/", "-")
			cves = append(cves, store.CVE{
				CVEID:       repoID,
				Provider:    fmt.Sprintf("gh-%s", label),
				Providers:   []string{fmt.Sprintf("gh-%s", label)},
				Severity:    "HIGH",
				Score:       7.5,
				Description: fmt.Sprintf("%s: %s", repo.FullName, truncate(repo.Description, 200)),
				Published:   repo.PushedAt,
				HasPoC:      true,
				Data: store.CVEData{
					Title:       repo.FullName,
					PoCLinks:    []string{repo.HTMLURL},
					ExploitRefs: []string{repo.HTMLURL},
					References:  []string{repo.HTMLURL},
				},
			})
		}
	}

	return cves, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
