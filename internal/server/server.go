package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/Runaho/cti-mcp/internal/cache"
	"github.com/Runaho/cti-mcp/internal/store"
	"github.com/Runaho/cti-mcp/internal/tools"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const instructions = `CTI MCP Server — Cyber Threat Intelligence

This server provides real-time CVE and threat intelligence data from multiple sources (CISA KEV, GitHub Advisory, NVD, OSV.dev, GitHub PoC repos).

IMPORTANT — Pre-flight Check:
Before calling refresh_sources, generate_report, or any data-heavy operation, call get_status first.
This returns token configuration, source health, and a "warnings" array.
If "warnings" is empty, everything is configured and ready.
If "warnings" is non-empty, review them and use your judgment: you may proceed anyway
(sources without API keys still work, just slower), or you may ask the user to provide
missing keys for better results. The decision is yours.

Available tools:
- get_status: Check server health, token/API key config, source availability, and warnings. Call this FIRST.
- get_recent_cves: Get recent CVEs within a time window, filtered by severity
- get_kev_entries: Get CISA KEV (Known Exploited Vulnerabilities) catalog entries
- get_cve_details: Get full details for a specific CVE by ID (fetches on-demand if missing)
- search_vulnerabilities: Search CVEs by keyword, product name, or CWE ID
- get_exploited: Get CVEs that are actively exploited (in KEV) and/or have PoC code
- generate_report: Generate a full HTML threat intelligence report
- refresh_sources: Force refresh data from all or specific sources

Environment Variables:
- NVD_API_KEY: NVD API key (recommended). Without it, NVD fetches are rate-limited to 5 req/30s and frequently fail. Request at https://nvd.nist.gov/developers/request-an-api-key
- GITHUB_TOKEN: GitHub personal access token. Without it, GitHub sources are limited to 60 req/h instead of 5000/h.
- CTI_MCP_DB_PATH: Custom SQLite database path (optional, defaults to embedded location).

Data is cached in SQLite with background refresh. First call after startup may be slow while the cache populates.`

type Server struct {
	store   *store.Store
	logger  *slog.Logger
	tools   *tools.Manager
	cache   *cache.Manager
	version string
}

func NewServer(s *store.Store, logger *slog.Logger, version string) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	cm := cache.NewManager(s, logger)
	return &Server{
		store:   s,
		logger:  logger,
		tools:   tools.NewManager(s, logger, cm),
		cache:   cm,
		version: version,
	}
}

func (srv *Server) Run(ctx context.Context) error {
	srv.logger.Info("starting CTI MCP server", "version", srv.version)

	// Start background cache refresh
	srv.cache.Start(ctx)
	defer srv.cache.Stop()

	mcpServer := mcp.NewServer(
		&mcp.Implementation{
			Name:    "cti-mcp",
			Version: srv.version,
		},
		&mcp.ServerOptions{
			Instructions: instructions,
			Logger:       srv.logger,
		},
	)

	srv.tools.RegisterAll(mcpServer)

	srv.logger.Info("server ready, waiting for connections on stdio")
	if err := mcpServer.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server run: %w", err)
	}
	return nil
}
