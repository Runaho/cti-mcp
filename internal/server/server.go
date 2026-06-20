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

Available tools:
- get_recent_cves: Get recent CVEs within a time window, filtered by severity
- get_kev_entries: Get CISA KEV (Known Exploited Vulnerabilities) catalog entries
- get_cve_details: Get full details for a specific CVE by ID (fetches on-demand if missing)
- search_vulnerabilities: Search CVEs by keyword, product name, or CWE ID
- get_exploited: Get CVEs that are actively exploited (in KEV) and/or have PoC code
- generate_report: Generate a full HTML threat intelligence report
- get_status: Check server health, cache status, token configuration, and source availability
- refresh_sources: Force refresh data from all or specific sources

Data is cached in SQLite with background refresh. First call after startup may be slow while the cache populates.

If GITHUB_TOKEN is not set, GitHub API calls are rate-limited to 60/hour. Use get_status to check configuration.`

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
