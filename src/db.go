package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const (
	poolMaxConns       = 10 // Headroom below db-broker's ROLE_CONNECTION_LIMIT=15
	poolMinConns       = 1
	poolMaxIdleTime    = 5 * time.Minute
	brokerHTTPTimeout  = 10 * time.Second
	brokerMaxRespBytes = 64 << 10
	brokerMaxAttempts  = 5
)

type brokerDBResponse struct {
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	URL      string `json:"url"`
}

type sqlMigration struct {
	version int
	file    string
}

var allMigrations = []sqlMigration{
	{version: 1, file: "migrations/001_init.sql"},
}

// ResolveDatabaseURL follows the cubus.sh db-broker client contract:
// DB_BROKER_URL takes precedence when set; DATABASE_URL is used for standalone local dev.
// Never logs or returns secrets inside error messages.
func ResolveDatabaseURL(ctx context.Context, cfg Config, client *http.Client) (string, error) {
	if cfg.DBBrokerURL == "" {
		if cfg.DatabaseURL == "" {
			return "", errors.New("set DB_BROKER_URL or DATABASE_URL")
		}
		return cfg.DatabaseURL, nil
	}
	return fetchFromBroker(ctx, cfg.DBBrokerURL, client, nil)
}

func fetchFromBroker(ctx context.Context, brokerURL string, client *http.Client, sleepFn func(time.Duration)) (string, error) {
	if client == nil {
		var tr *http.Transport
		if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
			tr = base.Clone()
		} else {
			tr = &http.Transport{}
		}
		// Never inherit HTTP_PROXY/HTTPS_PROXY for internal db-broker traffic.
		tr.Proxy = nil
		client = &http.Client{
			Timeout:   brokerHTTPTimeout,
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if sleepFn == nil {
		sleepFn = time.Sleep
	}

	var lastErr error
	for attempt := range brokerMaxAttempts {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, brokerURL, strings.NewReader("{}"))
		if err != nil {
			return "", errors.New("failed to build db-broker request")
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = errors.New("db-broker request failed")
			if ctx.Err() != nil || attempt == brokerMaxAttempts-1 {
				break
			}
			sleepWithContext(ctx, sleepFn, brokerBackoff(attempt, 0))
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, brokerMaxRespBytes))
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK && readErr == nil {
			var parsed brokerDBResponse
			if err := json.Unmarshal(body, &parsed); err != nil {
				return "", errors.New("failed to decode db-broker response")
			}
			if strings.TrimSpace(parsed.URL) == "" {
				return "", errors.New("db-broker response missing url")
			}
			return parsed.URL, nil
		}

		// Fail fast on non-retryable client/policy errors.
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusRequestEntityTooLarge:
			return "", fmt.Errorf("db-broker rejected request with status %d", resp.StatusCode)
		}

		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		lastErr = fmt.Errorf("db-broker returned status %d", resp.StatusCode)
		if ctx.Err() != nil || attempt == brokerMaxAttempts-1 {
			break
		}
		sleepWithContext(ctx, sleepFn, brokerBackoff(attempt, retryAfter))
	}
	return "", lastErr
}

func parseRetryAfter(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return 0
	}
	if secs > 10 {
		secs = 10
	}
	return time.Duration(secs) * time.Second
}

func brokerBackoff(attempt int, retryAfter time.Duration) time.Duration {
	base := time.Duration(500<<attempt) * time.Millisecond
	if retryAfter > base {
		base = retryAfter
	}
	if base > 10*time.Second {
		base = 10 * time.Second
	}
	jitter := time.Duration(rand.IntN(250)) * time.Millisecond
	return base + jitter
}

func sleepWithContext(ctx context.Context, sleepFn func(time.Duration), d time.Duration) {
	if ctx.Err() != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		sleepFn(d)
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// OpenPool opens and verifies a bounded pgxpool connection pool.
// Error messages never include the DSN or password.
func OpenPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("failed to parse postgres DSN")
	}
	poolCfg.MaxConns = poolMaxConns
	poolCfg.MinConns = poolMinConns
	poolCfg.MaxConnIdleTime = poolMaxIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, errors.New("failed to create postgres connection pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("failed to ping postgres database")
	}
	return pool, nil
}

// Migrate applies embedded SQL migrations inside a transaction-scoped advisory lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('audown_migrations', 0))`); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, m := range allMigrations {
		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %d: %w", m.version, err)
		}
		if applied {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile(m.file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", m.file, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", m.version, m.file, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}
