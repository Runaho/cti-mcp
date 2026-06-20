package server

import (
	"context"
	"testing"

	"github.com/Runaho/cti-mcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestServerToolsList(t *testing.T) {
	s, err := store.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := store.InitSchema(s.DB()); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(s, nil, "test")
	mcpServer := mcp.NewServer(
		&mcp.Implementation{Name: "cti-mcp", Version: "test"},
		&mcp.ServerOptions{Instructions: "test"},
	)
	srv.tools.RegisterAll(mcpServer)

	ctx := context.Background()
	t1, t2 := mcp.NewInMemoryTransports()

	if _, err := mcpServer.Connect(ctx, t1, nil); err != nil {
		t.Fatal(err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	// Collect all tools
	toolNames := []string{}
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		toolNames = append(toolNames, tool.Name)
	}

	expected := map[string]bool{
		"get_status":             true,
		"get_recent_cves":        true,
		"get_cve_details":        true,
		"search_vulnerabilities": true,
		"get_kev_entries":        true,
		"get_exploited":          true,
		"refresh_sources":        true,
		"generate_report":        true,
	}

	if len(toolNames) == 0 {
		t.Fatal("no tools registered")
	}

	for _, name := range toolNames {
		if !expected[name] {
			t.Errorf("unexpected tool: %s", name)
		}
		delete(expected, name)
	}

	if len(expected) > 0 {
		t.Errorf("missing tools: %v", expected)
	}

	t.Logf("Registered %d tools: %v", len(toolNames), toolNames)
}

func TestServerInstructions(t *testing.T) {
	if instructions == "" {
		t.Error("instructions should not be empty")
	}
	t.Logf("Instructions length: %d chars", len(instructions))
}
