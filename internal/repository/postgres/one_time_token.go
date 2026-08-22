package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/repository"
)

type oneTimeQueries struct {
	insert        string
	consume       string
	invalidate    string
	deleteExpired string
}

var passwordResetQueries = oneTimeQueries{
	insert: `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
	         VALUES ($1, $2, $3) RETURNING id`,
	consume: `UPDATE password_reset_tokens SET used_at = $2
	          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
	          RETURNING user_id`,
	invalidate: `UPDATE password_reset_tokens SET used_at = $2
	             WHERE user_id = $1 AND used_at IS NULL`,
	deleteExpired: `DELETE FROM password_reset_tokens WHERE expires_at < $1`,
}

var emailVerificationQueries = oneTimeQueries{
	insert: `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
	         VALUES ($1, $2, $3) RETURNING id`,
	consume: `UPDATE email_verification_tokens SET used_at = $2
	          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
	          RETURNING user_id`,
	invalidate: `UPDATE email_verification_tokens SET used_at = $2
	             WHERE user_id = $1 AND used_at IS NULL`,
	deleteExpired: `DELETE FROM email_verification_tokens WHERE expires_at < $1`,
}

type OneTimeTokenRepo struct {
	db      *sql.DB
	timeout time.Duration
	label   string
	queries oneTimeQueries
}

func (r *OneTimeTokenRepo) Create(ctx context.Context, params repository.CreateOneTimeTokenParams) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var id string
	err := r.db.QueryRowContext(ctx, r.queries.insert, params.UserID, params.TokenHash, params.ExpiresAt.UTC()).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("postgres: create %s: %w", r.label, translate(err))
	}
	return id, nil
}

func (r *OneTimeTokenRepo) ConsumeByHash(ctx context.Context, tokenHash []byte, at time.Time) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var userID string
	err := r.db.QueryRowContext(ctx, r.queries.consume, tokenHash, at.UTC()).Scan(&userID)
	if err != nil {
		return "", fmt.Errorf("postgres: consume %s: %w", r.label, translate(err))
	}
	return userID, nil
}

func (r *OneTimeTokenRepo) InvalidateForUser(ctx context.Context, userID string, at time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.execCount(ctx, "invalidate", r.queries.invalidate, userID, at.UTC())
}

func (r *OneTimeTokenRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.execCount(ctx, "delete expired", r.queries.deleteExpired, before.UTC())
}

func (r *OneTimeTokenRepo) execCount(ctx context.Context, op, query string, args ...any) (int64, error) {
	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("postgres: %s %s: %w", op, r.label, translate(err))
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("postgres: %s %s: rows affected: %w", op, r.label, err)
	}
	return affected, nil
}
