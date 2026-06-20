package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Runaho/cti-mcp/internal/store"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RecentCVEsInput struct {
	Hours    *int   `json:"hours,omitempty" jsonschema:"time window in hours (default 24)"`
	Severity *string `json:"severity,omitempty" jsonschema:"filter by severity: CRITICAL, HIGH, MEDIUM, LOW, or ALL (default ALL)"`
	Limit    *int   `json:"limit,omitempty" jsonschema:"max results (default 20, max 100)"`
}

type CVEDetailsInput struct {
	CVEID string `json:"cve_id" jsonschema:"the CVE identifier, e.g. CVE-2026-12345"`
}

type SearchVulnsInput struct {
	Keyword *string `json:"keyword,omitempty" jsonschema:"search keyword across title, description, and metadata"`
	Product *string `json:"product,omitempty" jsonschema:"filter by product name (e.g. nginx, openssl, libxml2)"`
	CWE     *string `json:"cwe,omitempty" jsonschema:"filter by CWE ID (e.g. CWE-78, CWE-79)"`
	Limit   *int    `json:"limit,omitempty" jsonschema:"max results (default 20, max 100)"`
}

func (m *Manager) registerCVEs(s *mcp.Server) {
	// get_recent_cves
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_recent_cves",
		Description: "Get recent CVEs within a time window, filtered by severity. Returns structured vulnerability data including CVSS score, CWE IDs, references, and exploit/PoC links.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in RecentCVEsInput) (*mcp.CallToolResult, any, error) {
		hours := 24
		if in.Hours != nil {
			hours = *in.Hours
		}
		severity := ""
		if in.Severity != nil {
			severity = *in.Severity
		}
		limit := 20
		if in.Limit != nil {
			limit = *in.Limit
			if limit > 100 {
				limit = 100
			}
		}

		cves, err := store.QueryCVEs(m.store.DB(), severity, hours, limit)
		if err != nil {
			return nil, nil, fmt.Errorf("query cves: %w", err)
		}

		jsonBytes, _ := json.MarshalIndent(map[string]any{
			"total": len(cves),
			"cves":  cves,
		}, "", "  ")

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
		}, nil, nil
	})

	// get_cve_details
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_cve_details",
		Description: "Get full details for a specific CVE by ID. If the CVE is not in the local cache or is stale (>6h old), it will be fetched on-demand from NVD and GitHub Advisory.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in CVEDetailsInput) (*mcp.CallToolResult, any, error) {
		cve, err := store.GetCVE(m.store.DB(), in.CVEID)
		if err != nil {
			return nil, nil, fmt.Errorf("get cve %s: %w", in.CVEID, err)
		}
		if cve == nil {
			jsonBytes, _ := json.Marshal(map[string]any{
				"cve_id":  in.CVEID,
				"found":   false,
				"message": "CVE not found in cache. Data sources will be available in a future version.",
			})
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
			}, nil, nil
		}

		jsonBytes, _ := json.MarshalIndent(cve, "", "  ")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
		}, nil, nil
	})

	// search_vulnerabilities
	mcp.AddTool(s, &mcp.Tool{
		Name:        "search_vulnerabilities",
		Description: "Search CVEs by keyword, product name, or CWE ID. Searches across titles, descriptions, and metadata.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in SearchVulnsInput) (*mcp.CallToolResult, any, error) {
		keyword := ""
		if in.Keyword != nil {
			keyword = *in.Keyword
		}
		product := ""
		if in.Product != nil {
			product = *in.Product
		}
		cwe := ""
		if in.CWE != nil {
			cwe = *in.CWE
		}
		limit := 20
		if in.Limit != nil {
			limit = *in.Limit
			if limit > 100 {
				limit = 100
			}
		}

		cves, err := store.SearchCVEs(m.store.DB(), keyword, product, cwe, limit)
		if err != nil {
			return nil, nil, fmt.Errorf("search cves: %w", err)
		}

		jsonBytes, _ := json.MarshalIndent(map[string]any{
			"total":   len(cves),
			"query":   map[string]string{"keyword": keyword, "product": product, "cwe": cwe},
			"results": cves,
		}, "", "  ")

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes)}},
		}, nil, nil
	})
}
