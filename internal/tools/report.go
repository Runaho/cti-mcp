package tools

import (
	"context"

	"github.com/Runaho/cti-mcp/internal/report"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ReportInput struct {
	Hours  *int    `json:"hours,omitempty" jsonschema:"time window in hours (default 24)"`
	Format *string `json:"format,omitempty" jsonschema:"output format: html or markdown (default html)"`
}

func (m *Manager) registerReport(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "generate_report",
		Description: "Generate a full HTML threat intelligence report with sectors, filters, KEV entries, and CVE details. Returns self-contained HTML suitable for viewing in a browser or saving to a file.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ReportInput) (*mcp.CallToolResult, any, error) {
		hours := 24
		if in.Hours != nil {
			hours = *in.Hours
		}

		html, err := report.GenerateHTML(m.store, hours)
		if err != nil {
			return nil, nil, err
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: html}},
		}, nil, nil
	})
}
