package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
)

func getTestPool(t *testing.T) *Pool {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := NewPool(context.Background(), dsn)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
	})
	return pool
}

func truncateTables(t *testing.T, pool *Pool, tables ...string) {
	t.Helper()
	if len(tables) == 0 {
		return
	}
	query := "TRUNCATE " + strings.Join(tables, ", ") + " CASCADE"
	if _, err := pool.Exec(context.Background(), query); err != nil {
		t.Fatalf("failed to truncate tables: %v", err)
	}
}
