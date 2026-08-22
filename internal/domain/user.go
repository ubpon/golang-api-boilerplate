package domain

import (
	"strings"
	"time"
)

type User struct {
	ID                  string
	Email               string
	DisplayEmail        string
	PasswordHash        string
	Name                string
	EmailVerifiedAt     *time.Time
	FailedLoginAttempts int
	LockedUntil         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (u *User) IsEmailVerified() bool {
	return u.EmailVerifiedAt != nil
}

func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func EmailLocalPart(email string) string {
	normalized := NormalizeEmail(email)
	at := strings.LastIndex(normalized, "@")
	if at <= 0 {
		return normalized
	}
	return normalized[:at]
}
