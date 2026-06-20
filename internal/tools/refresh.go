package tools

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RefreshInput struct {
	Source *string `json:"source,omitempty" jsonschema:"specific source to refresh (cisa_kev, github_advisory, github_poc, nvd, osv). If omitted, refreshes all sources."`
}

func (m *Manager) registerRefresh(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "refresh_sources",
		Description: "Force refresh data from all or specific sources. Use this when the cache is stale or to populate the database after first install. Returns the status of each source fetch.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in RefreshInput) (*mcp.CallToolResult, any, error) {
		if in.Source != nil && *in.Source != "" {
			err := m.cache.RefreshSource(ctx, *in.Source)
			status := "ok"
			errMsg := ""
			if err != nil {
				status = "failed"
				errMsg = err.Error()
			}
			jsonBytes, _ := json.MarshalIndent(map[string]any{
				"source": *in.Source,
				"status": status,
				"error":  errMsg,
			}, "", "  ")
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
			}, nil, nil
		}

		// Refresh all
		results := m.cache.RefreshAll(ctx)
		sourceResults := make(map[string]any)
		for name, err := range results {
			if err != nil {
				sourceResults[name] = map[string]string{"status": "failed", "error": err.Error()}
			} else {
				sourceResults[name] = map[string]string{"status": "ok"}
			}
		}

		jsonBytes, _ := json.MarshalIndent(map[string]any{
			"sources": sourceResults,
		}, "", "  ")

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
		}, nil, nil
	})
}
