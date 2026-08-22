package domain

import "errors"

var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("conflict")
	ErrInvalidCredential = errors.New("invalid credentials")
	ErrInvalidToken      = errors.New("invalid token")
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenUsed         = errors.New("token already used")
	ErrTokenRevoked      = errors.New("token revoked")
	ErrAccountLocked     = errors.New("account locked")
	ErrEmailNotVerified  = errors.New("email not verified")
	ErrWeakPassword      = errors.New("password does not meet policy")
	ErrPasswordReuse     = errors.New("password matches the current password")
)
