package cache

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Runaho/cti-mcp/internal/sources"
	"github.com/Runaho/cti-mcp/internal/store"
)

// Manager coordinates background data refresh from multiple sources.
type Manager struct {
	store   *store.Store
	sources []sources.Source
	logger  *slog.Logger
	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.RWMutex
	running map[string]bool // source name → currently fetching
}

// NewManager creates a cache manager with the given store and sources.
func NewManager(s *store.Store, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		store:   s,
		logger:  logger,
		stopCh:  make(chan struct{}),
		running: make(map[string]bool),
		sources: []sources.Source{
			&sources.CISAKEV{},
			&sources.GitHubAdvisory{},
			&sources.GitHubPoC{},
			&sources.NVD{},
			&sources.OSV{},
		},
	}
}

// Start launches background refresh goroutines for all sources.
// The first refresh runs immediately; subsequent ones follow each source's TTL.
func (m *Manager) Start(ctx context.Context) {
	m.logger.Info("cache manager starting", "sources", len(m.sources))

	// Initial population (async — don't block server startup)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.RefreshAll(ctx)
	}()

	// Background refresh loops
	for _, src := range m.sources {
		m.wg.Add(1)
		go func(s sources.Source) {
			defer m.wg.Done()
			m.refreshLoop(ctx, s)
		}(src)
	}

	// Daily retention prune
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.retentionLoop(ctx)
	}()
}

// Stop signals all goroutines to stop and waits for them to finish.
func (m *Manager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

// RefreshAll fetches from all sources and upserts results into the store.
func (m *Manager) RefreshAll(ctx context.Context) map[string]error {
	results := make(map[string]error)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, src := range m.sources {
		wg.Add(1)
		go func(s sources.Source) {
			defer wg.Done()
			err := m.refreshSource(ctx, s)
			mu.Lock()
			results[s.Name()] = err
			mu.Unlock()
		}(src)
	}
	wg.Wait()
	return results
}

// RefreshSource fetches from a single source by name.
func (m *Manager) RefreshSource(ctx context.Context, name string) error {
	for _, src := range m.sources {
		if src.Name() == name {
			return m.refreshSource(ctx, src)
		}
	}
	return fmt.Errorf("unknown source: %s", name)
}

func (m *Manager) refreshSource(ctx context.Context, src sources.Source) error {
	// Skip if already running — but report it honestly, not as success
	m.mu.Lock()
	if m.running[src.Name()] {
		m.mu.Unlock()
		m.logger.Debug("source already fetching, skipping", "source", src.Name())
		return fmt.Errorf("source %s is already fetching, skipping", src.Name())
	}
	m.running[src.Name()] = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.running, src.Name())
		m.mu.Unlock()
	}()

	m.logger.Info("fetching source", "source", src.Name())
	start := time.Now()

	result, err := src.Fetch(ctx)
	if err != nil {
		_ = store.UpdateSourceHealth(m.store.DB(), store.SourceHealth{
			SourceName:   src.Name(),
			Status:       "failed",
			ErrorMessage: err.Error(),
		})
		m.logger.Warn("source fetch failed", "source", src.Name(), "error", err)
		return err
	}

	// Upsert CVEs
	cveCount := 0
	for _, cve := range result.CVEs {
		if err := store.UpsertCVE(m.store.DB(), cve); err != nil {
			m.logger.Debug("cve upsert failed", "cve", cve.CVEID, "error", err)
			continue
		}
		cveCount++
	}

	// Upsert KEV entries
	kevCount := 0
	for _, kev := range result.KEVEntries {
		if err := store.UpsertKEV(m.store.DB(), kev); err != nil {
			m.logger.Debug("kev upsert failed", "cve", kev.CVEID, "error", err)
			continue
		}
		kevCount++
	}

	_ = store.UpdateSourceHealth(m.store.DB(), store.SourceHealth{
		SourceName: src.Name(),
		Status:     "ok",
		EntryCount: cveCount,
	})

	m.logger.Info("source fetched",
		"source", src.Name(),
		"cves", cveCount,
		"kev_entries", kevCount,
		"duration", time.Since(start).Round(time.Millisecond))

	return nil
}

func (m *Manager) refreshLoop(ctx context.Context, src sources.Source) {
	ticker := time.NewTicker(src.TTL())
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refreshSource(ctx, src)
		}
	}
}

func (m *Manager) retentionLoop(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run once on startup
	m.pruneOldEntries()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.pruneOldEntries()
		}
	}
}

func (m *Manager) pruneOldEntries() {
	// Delete entries older than 90 days that aren't CRITICAL/HIGH
	result, err := m.store.DB().Exec(`
		DELETE FROM cves
		WHERE last_updated < datetime('now', '-90 days')
		AND severity NOT IN ('CRITICAL', 'HIGH')
	`)
	if err != nil {
		m.logger.Warn("retention prune failed", "error", err)
		return
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		m.logger.Info("retention prune", "deleted", rows)
	}

	// Delete entries older than 365 days (all severities)
	result2, _ := m.store.DB().Exec(`DELETE FROM cves WHERE last_updated < datetime('now', '-365 days')`)
	if rows, _ := result2.RowsAffected(); rows > 0 {
		m.logger.Info("retention prune (365d)", "deleted", rows)
	}
}
