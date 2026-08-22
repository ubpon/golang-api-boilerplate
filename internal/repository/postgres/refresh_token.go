package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
	"github.com/ubpon/golang-api-boilerplate/internal/repository"
)

const refreshColumns = `id, user_id, token_hash, family_id, expires_at, used_at, revoked_at,
	user_agent, host(ip), created_at`

type RefreshTokenRepo struct {
	db      *sql.DB
	timeout time.Duration
}

func (r *RefreshTokenRepo) Create(ctx context.Context, params repository.CreateRefreshTokenParams) (*domain.RefreshToken, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::inet)
		RETURNING ` + refreshColumns

	row := r.db.QueryRowContext(ctx, query,
		params.UserID, params.TokenHash, params.FamilyID, params.ExpiresAt.UTC(), params.UserAgent, params.IP)

	token, err := scanRefreshToken(row)
	if err != nil {
		return nil, fmt.Errorf("postgres: create refresh token: %w", translate(err))
	}
	return token, nil
}

func (r *RefreshTokenRepo) GetByHash(ctx context.Context, tokenHash []byte) (*domain.RefreshToken, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `SELECT ` + refreshColumns + ` FROM refresh_tokens WHERE token_hash = $1`
	token, err := scanRefreshToken(r.db.QueryRowContext(ctx, query, tokenHash))
	if err != nil {
		return nil, fmt.Errorf("postgres: get refresh token: %w", translate(err))
	}
	return token, nil
}

func (r *RefreshTokenRepo) ConsumeByHash(ctx context.Context, tokenHash []byte, at time.Time) (*domain.RefreshToken, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE refresh_tokens
		SET used_at = $2
		WHERE token_hash = $1
		  AND used_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > $2
		RETURNING ` + refreshColumns

	token, err := scanRefreshToken(r.db.QueryRowContext(ctx, query, tokenHash, at.UTC()))
	if err != nil {
		return nil, fmt.Errorf("postgres: consume refresh token: %w", translate(err))
	}
	return token, nil
}

func (r *RefreshTokenRepo) RevokeFamily(ctx context.Context, familyID string, at time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE refresh_tokens SET revoked_at = $2
		WHERE family_id = $1 AND revoked_at IS NULL`

	return r.execCount(ctx, "revoke refresh token family", query, familyID, at.UTC())
}

func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string, at time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE refresh_tokens SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL`

	return r.execCount(ctx, "revoke all refresh tokens", query, userID, at.UTC())
}

func (r *RefreshTokenRepo) RevokeAllForUserExceptFamily(ctx context.Context, userID, familyID string, at time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE refresh_tokens SET revoked_at = $3
		WHERE user_id = $1 AND family_id <> $2 AND revoked_at IS NULL`

	return r.execCount(ctx, "revoke other refresh tokens", query, userID, familyID, at.UTC())
}

func (r *RefreshTokenRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `DELETE FROM refresh_tokens WHERE expires_at < $1`
	return r.execCount(ctx, "delete expired refresh tokens", query, before.UTC())
}

func (r *RefreshTokenRepo) execCount(ctx context.Context, op, query string, args ...any) (int64, error) {
	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("postgres: %s: %w", op, translate(err))
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("postgres: %s: rows affected: %w", op, err)
	}
	return affected, nil
}

func scanRefreshToken(row rowScanner) (*domain.RefreshToken, error) {
	var (
		t         domain.RefreshToken
		usedAt    sql.NullTime
		revokedAt sql.NullTime
		ip        sql.NullString
	)
	err := row.Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.FamilyID, &t.ExpiresAt,
		&usedAt, &revokedAt, &t.UserAgent, &ip, &t.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if usedAt.Valid {
		v := usedAt.Time.UTC()
		t.UsedAt = &v
	}
	if revokedAt.Valid {
		v := revokedAt.Time.UTC()
		t.RevokedAt = &v
	}
	t.IP = ip.String
	t.ExpiresAt = t.ExpiresAt.UTC()
	t.CreatedAt = t.CreatedAt.UTC()
	return &t, nil
}
