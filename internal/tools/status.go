package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Runaho/cti-mcp/internal/store"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (m *Manager) registerStatus(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_status",
		Description: "Check server health, cache status, token configuration, and data source availability. Use this to diagnose issues or check if the server is ready.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		status := m.buildStatus()
		jsonBytes, _ := json.MarshalIndent(status, "", "  ")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
		}, nil, nil
	})
}

func (m *Manager) buildStatus() map[string]any {
	db := m.store.DB()

	cveCount, _ := store.CVECount(db)
	kevCount, _ := store.KEVCount(db)
	healths, _ := store.GetAllSourceHealth(db)

	sources := make(map[string]any)
	for _, h := range healths {
		lastFetch := h.LastFetched
		if lastFetch != "" {
			if t, err := time.Parse(time.RFC3339, lastFetch); err == nil {
				lastFetch = fmt.Sprintf("%s (%dm ago)", h.LastFetched, int(time.Since(t).Minutes()))
			}
		}
		sources[h.SourceName] = map[string]any{
			"status":       h.Status,
			"http_code":    h.HTTPCode,
			"entry_count":  h.EntryCount,
			"last_fetched": lastFetch,
			"error":        h.ErrorMessage,
		}
	}

	tokenStatus := "missing (rate limited to 60 req/h, set GITHUB_TOKEN for 5000 req/h)"
	if os.Getenv("GITHUB_TOKEN") != "" {
		tokenStatus = "set"
	}

	return map[string]any{
		"github_token": tokenStatus,
		"cache": map[string]any{
			"cves_count":  cveCount,
			"kev_count":   kevCount,
			"db_path":     os.Getenv("CTI_MCP_DB_PATH"),
			"populated":   cveCount > 0,
		},
		"sources": sources,
	}
}
