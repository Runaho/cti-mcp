package sources

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/Runaho/cti-mcp/internal/store"
)

// Source represents a data source that fetches CVE or KEV data.
type Source interface {
	Name() string
	TTL() time.Duration
	Fetch(ctx context.Context) (*FetchResult, error)
}

// FetchResult holds the result of a source fetch.
type FetchResult struct {
	CVEs     []store.CVE
	KEVEntries []store.KEVEntry
}

// HTTPClient is a shared HTTP client with generous timeouts.
// NVD API 2.0 can take 30+ seconds per request without an API key.
var HTTPClient = &http.Client{
	Timeout: 45 * time.Second,
}

// GitHubToken returns the GitHub API token from the environment, if set.
func GitHubToken() string {
	return os.Getenv("GITHUB_TOKEN")
}
