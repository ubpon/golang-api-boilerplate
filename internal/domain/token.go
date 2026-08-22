package domain

import "time"

type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash []byte
	FamilyID  string
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	UserAgent string
	IP        string
	CreatedAt time.Time
}

func (t *RefreshToken) IsActive(now time.Time) bool {
	return t.UsedAt == nil && t.RevokedAt == nil && t.ExpiresAt.After(now)
}

type PasswordResetToken struct {
	ID        string
	UserID    string
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type EmailVerificationToken struct {
	ID        string
	UserID    string
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
