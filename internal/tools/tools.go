package tools

import (
	"log/slog"

	"github.com/Runaho/cti-mcp/internal/cache"
	"github.com/Runaho/cti-mcp/internal/store"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Manager holds shared state for all tool handlers.
type Manager struct {
	store  *store.Store
	logger *slog.Logger
	cache  *cache.Manager
}

func NewManager(s *store.Store, logger *slog.Logger, cm *cache.Manager) *Manager {
	return &Manager{
		store:  s,
		logger: logger,
		cache:  cm,
	}
}

// RegisterAll registers every MCP tool on the given server.
func (m *Manager) RegisterAll(s *mcp.Server) {
	m.registerStatus(s)
	m.registerCVEs(s)
	m.registerKEV(s)
	m.registerRefresh(s)
	m.registerReport(s)
}
