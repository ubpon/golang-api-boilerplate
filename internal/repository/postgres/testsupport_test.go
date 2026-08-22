package postgres_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ubpon/golang-api-boilerplate/internal/repository/postgres"
)

func newIntegrationStore(t *testing.T) *postgres.Store {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}

	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("boilerplate_test"),
		tcpostgres.WithUsername("boilerplate"),
		tcpostgres.WithPassword("boilerplate"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		t.Skipf("could not start a postgres container (is a container runtime available?): %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	require.Eventually(t, func() bool {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return db.PingContext(pingCtx) == nil
	}, 30*time.Second, 250*time.Millisecond)

	applyMigrations(t, db)
	return postgres.NewStore(db, 5*time.Second)
}

func applyMigrations(t *testing.T, db *sql.DB) {
	t.Helper()

	dir := filepath.Join("..", "..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	require.NotEmpty(t, files)

	for _, name := range files {
		body, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		_, err = db.Exec(string(body))
		require.NoError(t, err, "migration %s failed", name)
	}
}

func hash(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}
