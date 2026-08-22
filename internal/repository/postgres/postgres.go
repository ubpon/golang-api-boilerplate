package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	// Registers the "pgx" driver with database/sql; this package exposes no
	// identifiers of its own.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
	"github.com/ubpon/golang-api-boilerplate/internal/repository"
)

const uniqueViolation = "23505"

type Options struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	QueryTimeout    time.Duration
}

type Store struct {
	db      *sql.DB
	timeout time.Duration

	users    *UserRepo
	refresh  *RefreshTokenRepo
	resets   *OneTimeTokenRepo
	verifies *OneTimeTokenRepo
}

func Open(ctx context.Context, opts Options) (*Store, error) {
	db, err := sql.Open("pgx", opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	db.SetMaxOpenConns(opts.MaxOpenConns)
	db.SetMaxIdleConns(opts.MaxIdleConns)
	db.SetConnMaxLifetime(opts.ConnMaxLifetime)
	db.SetConnMaxIdleTime(opts.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		// The handle is unusable, so a close error adds nothing to the reported failure.
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	timeout := opts.QueryTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	s := &Store{db: db, timeout: timeout}
	s.users = &UserRepo{db: db, timeout: timeout}
	s.refresh = &RefreshTokenRepo{db: db, timeout: timeout}
	s.resets = &OneTimeTokenRepo{db: db, timeout: timeout, label: "password reset token", queries: passwordResetQueries}
	s.verifies = &OneTimeTokenRepo{db: db, timeout: timeout, label: "email verification token", queries: emailVerificationQueries}
	return s, nil
}

func NewStore(db *sql.DB, timeout time.Duration) *Store {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Store{
		db:       db,
		timeout:  timeout,
		users:    &UserRepo{db: db, timeout: timeout},
		refresh:  &RefreshTokenRepo{db: db, timeout: timeout},
		resets:   &OneTimeTokenRepo{db: db, timeout: timeout, label: "password reset token", queries: passwordResetQueries},
		verifies: &OneTimeTokenRepo{db: db, timeout: timeout, label: "email verification token", queries: emailVerificationQueries},
	}
}

func (s *Store) Users() repository.UserRepository                       { return s.users }
func (s *Store) RefreshTokens() repository.RefreshTokenRepository       { return s.refresh }
func (s *Store) PasswordResetTokens() repository.OneTimeTokenRepository { return s.resets }
func (s *Store) EmailVerificationTokens() repository.OneTimeTokenRepository {
	return s.verifies
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.db.PingContext(ctx)
}

func (s *Store) Close() error { return s.db.Close() }

func translate(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return domain.ErrConflict
	}
	return err
}
