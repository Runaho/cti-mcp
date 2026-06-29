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
		Description: "Generate a full threat intelligence report. Returns either a self-contained HTML report (default, suitable for viewing in a browser or saving to a file) or a plain Markdown summary (suitable for chat delivery or text preview).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ReportInput) (*mcp.CallToolResult, any, error) {
		hours := 24
		if in.Hours != nil {
			hours = *in.Hours
		}

		format := "html"
		if in.Format != nil && *in.Format != "" {
			format = *in.Format
		}

		switch format {
		case "markdown", "md":
			md, err := report.GenerateMarkdown(m.store, hours)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: md}},
			}, nil, nil
		default:
			html, err := report.GenerateHTML(m.store, hours)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: html}},
			}, nil, nil
		}
	})
}
