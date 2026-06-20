package store

import (
	"database/sql"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database connection.
type Store struct {
	db *sql.DB
}

// NewStore opens (or creates) the SQLite database at the given path.
// Enables WAL mode for concurrent read/write access.
func NewStore(dbPath string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", url.PathEscape(dbPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	return &Store{db: db}, nil
}

// DB returns the underlying *sql.DB for direct access.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
