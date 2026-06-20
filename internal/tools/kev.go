package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Runaho/cti-mcp/internal/store"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type KEVInput struct {
	RecentDays *int `json:"recent_days,omitempty" jsonschema:"filter to entries added in the last N days (default 30, 0 for all)"`
	Limit      *int `json:"limit,omitempty" jsonschema:"max results (default 50)"`
}

type ExploitedInput struct {
	Limit *int `json:"limit,omitempty" jsonschema:"max results (default 20, max 100)"`
}

func (m *Manager) registerKEV(s *mcp.Server) {
	// get_kev_entries
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_kev_entries",
		Description: "Get CISA KEV (Known Exploited Vulnerabilities) catalog entries. These are vulnerabilities that are being actively exploited in the wild. Includes vendor/product, due dates for patching, and required actions.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in KEVInput) (*mcp.CallToolResult, any, error) {
		recentDays := 30
		if in.RecentDays != nil {
			recentDays = *in.RecentDays
		}
		limit := 50
		if in.Limit != nil {
			limit = *in.Limit
		}

		entries, err := store.QueryKEV(m.store.DB(), recentDays, limit)
		if err != nil {
			return nil, nil, fmt.Errorf("query kev: %w", err)
		}

		jsonBytes, _ := json.MarshalIndent(map[string]any{
			"total":    len(entries),
			"entries":  entries,
		}, "", "  ")

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
		}, nil, nil
	})

	// get_exploited
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_exploited",
		Description: "Get the highest-risk CVEs: those that are actively exploited (in CISA KEV catalog) and/or have public PoC exploit code. Sorted by CVSS score descending.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ExploitedInput) (*mcp.CallToolResult, any, error) {
		limit := 20
		if in.Limit != nil {
			limit = *in.Limit
			if limit > 100 {
				limit = 100
			}
		}

		cves, err := store.QueryExploitedCVEs(m.store.DB(), limit)
		if err != nil {
			return nil, nil, err
		}

		jsonBytes, _ := json.MarshalIndent(map[string]any{
			"total": len(cves),
			"cves":  cves,
		}, "", "  ")

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
		}, nil, nil
	})
}
