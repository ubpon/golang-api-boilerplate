package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
	"github.com/ubpon/golang-api-boilerplate/internal/repository"
)

const userColumns = `id, email::text, display_email, password_hash, name,
	email_verified_at, failed_login_attempts, locked_until, created_at, updated_at`

type UserRepo struct {
	db      *sql.DB
	timeout time.Duration
}

func (r *UserRepo) Create(ctx context.Context, params repository.CreateUserParams) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		INSERT INTO users (email, display_email, password_hash, name)
		VALUES ($1, $2, $3, $4)
		RETURNING ` + userColumns

	row := r.db.QueryRowContext(ctx, query, params.Email, params.DisplayEmail, params.PasswordHash, params.Name)
	user, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: create user: %w", translate(err))
	}
	return user, nil
}

func (r *UserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	user, err := scanUser(r.db.QueryRowContext(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("postgres: get user by id: %w", translate(err))
	}
	return user, nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `SELECT ` + userColumns + ` FROM users WHERE email = $1`
	user, err := scanUser(r.db.QueryRowContext(ctx, query, domain.NormalizeEmail(email)))
	if err != nil {
		return nil, fmt.Errorf("postgres: get user by email: %w", translate(err))
	}
	return user, nil
}

func (r *UserRepo) UpdateName(ctx context.Context, id, name string) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE users SET name = $2, updated_at = now()
		WHERE id = $1
		RETURNING ` + userColumns

	user, err := scanUser(r.db.QueryRowContext(ctx, query, id, name))
	if err != nil {
		return nil, fmt.Errorf("postgres: update user name: %w", translate(err))
	}
	return user, nil
}

func (r *UserRepo) UpdatePasswordHash(ctx context.Context, id, passwordHash string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE users
		SET password_hash = $2, failed_login_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`

	return r.exec(ctx, "update password hash", query, id, passwordHash)
}

func (r *UserRepo) MarkEmailVerified(ctx context.Context, id string, at time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE users
		SET email_verified_at = COALESCE(email_verified_at, $2), updated_at = now()
		WHERE id = $1`

	return r.exec(ctx, "mark email verified", query, id, at.UTC())
}

func (r *UserRepo) RecordFailedLogin(ctx context.Context, id string, at time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1, updated_at = $2
		WHERE id = $1
		RETURNING failed_login_attempts`

	var attempts int
	if err := r.db.QueryRowContext(ctx, query, id, at.UTC()).Scan(&attempts); err != nil {
		return 0, fmt.Errorf("postgres: record failed login: %w", translate(err))
	}
	return attempts, nil
}

func (r *UserRepo) ApplyLock(ctx context.Context, id string, until time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `UPDATE users SET locked_until = $2, updated_at = now() WHERE id = $1`
	return r.exec(ctx, "apply account lock", query, id, until.UTC())
}

func (r *UserRepo) ResetFailedLogins(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE users
		SET failed_login_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1 AND (failed_login_attempts <> 0 OR locked_until IS NOT NULL)`

	res, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("postgres: reset failed logins: %w", translate(err))
	}
	// A zero-row result means the counters were already clean, which is not an error.
	_, _ = res.RowsAffected()
	return nil
}

func (r *UserRepo) exec(ctx context.Context, op, query string, args ...any) error {
	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("postgres: %s: %w", op, translate(err))
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: %s: rows affected: %w", op, err)
	}
	if affected == 0 {
		return fmt.Errorf("postgres: %s: %w", op, domain.ErrNotFound)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*domain.User, error) {
	var (
		u               domain.User
		name            sql.NullString
		emailVerifiedAt sql.NullTime
		lockedUntil     sql.NullTime
	)
	err := row.Scan(
		&u.ID, &u.Email, &u.DisplayEmail, &u.PasswordHash, &name,
		&emailVerifiedAt, &u.FailedLoginAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.Name = name.String
	if emailVerifiedAt.Valid {
		t := emailVerifiedAt.Time.UTC()
		u.EmailVerifiedAt = &t
	}
	if lockedUntil.Valid {
		t := lockedUntil.Time.UTC()
		u.LockedUntil = &t
	}
	return &u, nil
}
