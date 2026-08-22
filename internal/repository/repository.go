package repository

import (
	"context"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
)

type CreateUserParams struct {
	Email        string
	DisplayEmail string
	PasswordHash string
	Name         string
}

type UserRepository interface {
	Create(ctx context.Context, params CreateUserParams) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateName(ctx context.Context, id, name string) (*domain.User, error)
	UpdatePasswordHash(ctx context.Context, id, passwordHash string) error
	MarkEmailVerified(ctx context.Context, id string, at time.Time) error
	RecordFailedLogin(ctx context.Context, id string, at time.Time) (int, error)
	ApplyLock(ctx context.Context, id string, until time.Time) error
	ResetFailedLogins(ctx context.Context, id string) error
}

type CreateRefreshTokenParams struct {
	UserID    string
	TokenHash []byte
	FamilyID  string
	ExpiresAt time.Time
	UserAgent string
	IP        string
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, params CreateRefreshTokenParams) (*domain.RefreshToken, error)
	GetByHash(ctx context.Context, tokenHash []byte) (*domain.RefreshToken, error)
	ConsumeByHash(ctx context.Context, tokenHash []byte, at time.Time) (*domain.RefreshToken, error)
	RevokeFamily(ctx context.Context, familyID string, at time.Time) (int64, error)
	RevokeAllForUser(ctx context.Context, userID string, at time.Time) (int64, error)
	RevokeAllForUserExceptFamily(ctx context.Context, userID, familyID string, at time.Time) (int64, error)
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

type CreateOneTimeTokenParams struct {
	UserID    string
	TokenHash []byte
	ExpiresAt time.Time
}

type OneTimeTokenRepository interface {
	Create(ctx context.Context, params CreateOneTimeTokenParams) (string, error)
	ConsumeByHash(ctx context.Context, tokenHash []byte, at time.Time) (string, error)
	InvalidateForUser(ctx context.Context, userID string, at time.Time) (int64, error)
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

type Store interface {
	Users() UserRepository
	RefreshTokens() RefreshTokenRepository
	PasswordResetTokens() OneTimeTokenRepository
	EmailVerificationTokens() OneTimeTokenRepository
	Ping(ctx context.Context) error
	Close() error
}
