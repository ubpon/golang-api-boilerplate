package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/mailer"
	"github.com/ubpon/golang-api-boilerplate/internal/repository"
	"github.com/ubpon/golang-api-boilerplate/internal/security"
	"github.com/ubpon/golang-api-boilerplate/internal/validation"
)

var (
	ErrInvalidCredentials = errors.New("service: invalid credentials")
	ErrAccountLocked      = errors.New("service: account locked")
	ErrEmailNotVerified   = errors.New("service: email not verified")
	ErrInvalidToken       = errors.New("service: token is invalid, expired or already used")
	ErrWeakPassword       = errors.New("service: password rejected by policy")
	ErrPasswordUnchanged  = errors.New("service: new password matches the current password")
	ErrUserNotFound       = errors.New("service: user not found")
)

type Clock func() time.Time

type LockoutPolicy struct {
	Threshold   int
	BaseWindow  time.Duration
	MaxWindow   time.Duration
	BackoffStep int
}

type TTLs struct {
	Access  time.Duration
	Refresh time.Duration
	Reset   time.Duration
	Verify  time.Duration
}

type AuthDeps struct {
	Users              repository.UserRepository
	RefreshTokens      repository.RefreshTokenRepository
	ResetTokens        repository.OneTimeTokenRepository
	VerificationTokens repository.OneTimeTokenRepository
	Hasher             *security.PasswordHasher
	Tokens             *security.TokenIssuer
	Mailer             mailer.Mailer
	Composer           *mailer.Composer
	Policy             validation.PasswordPolicy
	Lockout            LockoutPolicy
	TTL                TTLs
	Logger             *slog.Logger
	Clock              Clock
	RequireVerified    bool
}

type AuthService struct {
	deps AuthDeps
	now  Clock
}

func NewAuthService(deps AuthDeps) (*AuthService, error) {
	switch {
	case deps.Users == nil, deps.RefreshTokens == nil, deps.ResetTokens == nil, deps.VerificationTokens == nil:
		return nil, errors.New("service: all repositories are required")
	case deps.Hasher == nil || deps.Tokens == nil:
		return nil, errors.New("service: hasher and token issuer are required")
	case deps.Mailer == nil || deps.Composer == nil:
		return nil, errors.New("service: mailer and composer are required")
	case deps.Logger == nil:
		return nil, errors.New("service: logger is required")
	}
	clock := deps.Clock
	if clock == nil {
		clock = time.Now
	}
	return &AuthService{deps: deps, now: clock}, nil
}

type SessionMetadata struct {
	UserAgent string
	IP        string
}

type Session struct {
	User             *domain.User
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	CSRFToken        string
	FamilyID         string
}

type RegisterInput struct {
	Email    string
	Password string
	Name     string
}

func (s *AuthService) Register(ctx context.Context, in RegisterInput) error {
	normalized := domain.NormalizeEmail(in.Email)
	if issue := s.deps.Policy.Validate("password", in.Password, normalized); issue != nil {
		return fmt.Errorf("%w: %s", ErrWeakPassword, issue.Message)
	}

	hash, err := s.deps.Hasher.Hash(in.Password)
	if err != nil {
		return fmt.Errorf("service: hash password: %w", err)
	}

	user, err := s.deps.Users.Create(ctx, repository.CreateUserParams{
		Email:        normalized,
		DisplayEmail: in.Email,
		PasswordHash: hash,
		Name:         in.Name,
	})
	switch {
	case err == nil:
		return s.issueVerificationEmail(ctx, user)
	case errors.Is(err, domain.ErrConflict):
		return s.handleDuplicateRegistration(ctx, normalized)
	default:
		return fmt.Errorf("service: create user: %w", err)
	}
}

func (s *AuthService) handleDuplicateRegistration(ctx context.Context, normalized string) error {
	existing, err := s.deps.Users.GetByEmail(ctx, normalized)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("service: load existing user: %w", err)
	}
	if existing.IsEmailVerified() {
		s.deps.Logger.InfoContext(ctx, "registration attempted for an existing verified account")
		return nil
	}
	return s.issueVerificationEmail(ctx, existing)
}

func (s *AuthService) issueVerificationEmail(ctx context.Context, user *domain.User) error {
	token, err := security.NewOpaqueToken()
	if err != nil {
		return fmt.Errorf("service: generate verification token: %w", err)
	}
	if _, err := s.deps.VerificationTokens.InvalidateForUser(ctx, user.ID, s.now()); err != nil {
		return fmt.Errorf("service: invalidate verification tokens: %w", err)
	}
	if _, err := s.deps.VerificationTokens.Create(ctx, repository.CreateOneTimeTokenParams{
		UserID:    user.ID,
		TokenHash: token.Hash,
		ExpiresAt: s.now().Add(s.deps.TTL.Verify),
	}); err != nil {
		return fmt.Errorf("service: store verification token: %w", err)
	}

	msg, err := s.deps.Composer.VerifyEmail(user.DisplayEmail, user.Name, token.Plaintext, humanizeTTL(s.deps.TTL.Verify))
	if err != nil {
		return fmt.Errorf("service: compose verification email: %w", err)
	}
	if err := s.deps.Mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("service: queue verification email: %w", err)
	}
	return nil
}

type LoginInput struct {
	Email    string
	Password string
	Metadata SessionMetadata
}

func (s *AuthService) Login(ctx context.Context, in LoginInput) (*Session, error) {
	normalized := domain.NormalizeEmail(in.Email)
	now := s.now()

	user, err := s.deps.Users.GetByEmail(ctx, normalized)
	if err != nil {
		if !errors.Is(err, domain.ErrNotFound) {
			return nil, fmt.Errorf("service: load user: %w", err)
		}
		s.deps.Hasher.VerifyDummy(in.Password)
		logging.Security(ctx, logging.EventLoginFailed, "reason", "unknown_account")
		return nil, ErrInvalidCredentials
	}

	matches, err := s.deps.Hasher.Verify(in.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("service: verify password: %w", err)
	}
	if !matches {
		if err := s.registerFailedLogin(ctx, user, now); err != nil {
			return nil, err
		}
		logging.Security(ctx, logging.EventLoginFailed, "reason", "bad_password", "user_id", user.ID)
		return nil, ErrInvalidCredentials
	}

	if user.IsLocked(now) {
		logging.Security(ctx, logging.EventAccountLocked, "reason", "login_while_locked", "user_id", user.ID)
		return nil, ErrAccountLocked
	}
	if s.deps.RequireVerified && !user.IsEmailVerified() {
		return nil, ErrEmailNotVerified
	}

	if err := s.deps.Users.ResetFailedLogins(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("service: reset failed logins: %w", err)
	}
	if s.deps.Hasher.NeedsRehash(user.PasswordHash) {
		if err := s.rehashPassword(ctx, user, in.Password); err != nil {
			return nil, err
		}
	}

	return s.startSession(ctx, user, uuid.NewString(), in.Metadata)
}

func (s *AuthService) rehashPassword(ctx context.Context, user *domain.User, password string) error {
	upgraded, err := s.deps.Hasher.Hash(password)
	if err != nil {
		return fmt.Errorf("service: rehash password: %w", err)
	}
	if err := s.deps.Users.UpdatePasswordHash(ctx, user.ID, upgraded); err != nil {
		return fmt.Errorf("service: persist rehashed password: %w", err)
	}
	user.PasswordHash = upgraded
	s.deps.Logger.InfoContext(ctx, "password hash upgraded to current argon2id parameters",
		slog.String("user_id", user.ID))
	return nil
}

func (s *AuthService) registerFailedLogin(ctx context.Context, user *domain.User, now time.Time) error {
	attempts, err := s.deps.Users.RecordFailedLogin(ctx, user.ID, now)
	if err != nil {
		return fmt.Errorf("service: record failed login: %w", err)
	}
	if attempts < s.deps.Lockout.Threshold {
		return nil
	}

	window := lockWindow(s.deps.Lockout, attempts)
	until := now.Add(window)
	if err := s.deps.Users.ApplyLock(ctx, user.ID, until); err != nil {
		return fmt.Errorf("service: apply account lock: %w", err)
	}
	logging.Security(ctx, logging.EventAccountLocked,
		"user_id", user.ID,
		"failed_attempts", attempts,
		"locked_for_seconds", int(window.Seconds()),
	)
	return nil
}

func lockWindow(policy LockoutPolicy, attempts int) time.Duration {
	over := attempts - policy.Threshold
	if over < 0 {
		over = 0
	}
	step := policy.BackoffStep
	if step <= 0 {
		step = 1
	}
	exponent := float64(over / step)
	window := time.Duration(float64(policy.BaseWindow) * math.Pow(2, exponent))
	if policy.MaxWindow > 0 && window > policy.MaxWindow {
		return policy.MaxWindow
	}
	return window
}

func (s *AuthService) startSession(ctx context.Context, user *domain.User, familyID string, meta SessionMetadata) (*Session, error) {
	access, err := s.deps.Tokens.Issue(user.ID)
	if err != nil {
		return nil, fmt.Errorf("service: issue access token: %w", err)
	}
	refresh, err := security.NewOpaqueToken()
	if err != nil {
		return nil, fmt.Errorf("service: generate refresh token: %w", err)
	}
	csrf, err := security.NewCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("service: generate csrf token: %w", err)
	}

	expiresAt := s.now().Add(s.deps.TTL.Refresh)
	if _, err := s.deps.RefreshTokens.Create(ctx, repository.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: refresh.Hash,
		FamilyID:  familyID,
		ExpiresAt: expiresAt,
		UserAgent: truncate(meta.UserAgent, 256),
		IP:        meta.IP,
	}); err != nil {
		return nil, fmt.Errorf("service: persist refresh token: %w", err)
	}

	return &Session{
		User:             user,
		AccessToken:      access.Token,
		AccessExpiresAt:  access.ExpiresAt,
		RefreshToken:     refresh.Plaintext,
		RefreshExpiresAt: expiresAt,
		CSRFToken:        csrf,
		FamilyID:         familyID,
	}, nil
}

func (s *AuthService) Refresh(ctx context.Context, presented string, meta SessionMetadata) (*Session, error) {
	hash, err := security.HashOpaqueToken(presented)
	if err != nil {
		return nil, ErrInvalidToken
	}
	now := s.now()

	consumed, err := s.deps.RefreshTokens.ConsumeByHash(ctx, hash, now)
	if err == nil {
		user, err := s.deps.Users.GetByID(ctx, consumed.UserID)
		if err != nil {
			return nil, fmt.Errorf("service: load user for refresh: %w", err)
		}
		if user.IsLocked(now) {
			if _, err := s.deps.RefreshTokens.RevokeFamily(ctx, consumed.FamilyID, now); err != nil {
				return nil, fmt.Errorf("service: revoke family for locked user: %w", err)
			}
			return nil, ErrAccountLocked
		}
		return s.startSession(ctx, user, consumed.FamilyID, meta)
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("service: consume refresh token: %w", err)
	}

	existing, lookupErr := s.deps.RefreshTokens.GetByHash(ctx, hash)
	if lookupErr != nil {
		if errors.Is(lookupErr, domain.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("service: inspect refresh token: %w", lookupErr)
	}
	if existing.UsedAt != nil {
		revoked, revokeErr := s.deps.RefreshTokens.RevokeFamily(ctx, existing.FamilyID, now)
		if revokeErr != nil {
			return nil, fmt.Errorf("service: revoke reused token family: %w", revokeErr)
		}
		logging.Security(ctx, logging.EventRefreshReuseDetected,
			"user_id", existing.UserID,
			"family_id", existing.FamilyID,
			"revoked_tokens", revoked,
		)
	}
	return nil, ErrInvalidToken
}

func (s *AuthService) Logout(ctx context.Context, presented string) error {
	hash, err := security.HashOpaqueToken(presented)
	if err != nil {
		return nil
	}
	token, err := s.deps.RefreshTokens.GetByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("service: load refresh token: %w", err)
	}
	if _, err := s.deps.RefreshTokens.RevokeFamily(ctx, token.FamilyID, s.now()); err != nil {
		return fmt.Errorf("service: revoke refresh token family: %w", err)
	}
	return nil
}

func (s *AuthService) LogoutAll(ctx context.Context, userID string) error {
	if _, err := s.deps.RefreshTokens.RevokeAllForUser(ctx, userID, s.now()); err != nil {
		return fmt.Errorf("service: revoke all refresh tokens: %w", err)
	}
	return nil
}

func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	normalized := domain.NormalizeEmail(email)
	logging.Security(ctx, logging.EventPasswordResetRequest, "email_domain", emailDomain(normalized))

	user, err := s.deps.Users.GetByEmail(ctx, normalized)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("service: load user for reset: %w", err)
	}

	token, err := security.NewOpaqueToken()
	if err != nil {
		return fmt.Errorf("service: generate reset token: %w", err)
	}
	now := s.now()
	if _, err := s.deps.ResetTokens.InvalidateForUser(ctx, user.ID, now); err != nil {
		return fmt.Errorf("service: invalidate reset tokens: %w", err)
	}
	if _, err := s.deps.ResetTokens.Create(ctx, repository.CreateOneTimeTokenParams{
		UserID:    user.ID,
		TokenHash: token.Hash,
		ExpiresAt: now.Add(s.deps.TTL.Reset),
	}); err != nil {
		return fmt.Errorf("service: store reset token: %w", err)
	}

	msg, err := s.deps.Composer.PasswordReset(user.DisplayEmail, user.Name, token.Plaintext, humanizeTTL(s.deps.TTL.Reset))
	if err != nil {
		return fmt.Errorf("service: compose reset email: %w", err)
	}
	if err := s.deps.Mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("service: queue reset email: %w", err)
	}
	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, presented, newPassword string) error {
	hash, err := security.HashOpaqueToken(presented)
	if err != nil {
		return ErrInvalidToken
	}
	now := s.now()

	userID, err := s.deps.ResetTokens.ConsumeByHash(ctx, hash, now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrInvalidToken
		}
		return fmt.Errorf("service: consume reset token: %w", err)
	}

	user, err := s.deps.Users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("service: load user for reset: %w", err)
	}
	if issue := s.deps.Policy.Validate("new_password", newPassword, user.Email); issue != nil {
		return fmt.Errorf("%w: %s", ErrWeakPassword, issue.Message)
	}

	newHash, err := s.deps.Hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("service: hash new password: %w", err)
	}
	if err := s.deps.Users.UpdatePasswordHash(ctx, user.ID, newHash); err != nil {
		return fmt.Errorf("service: persist new password: %w", err)
	}
	if _, err := s.deps.ResetTokens.InvalidateForUser(ctx, user.ID, now); err != nil {
		return fmt.Errorf("service: invalidate remaining reset tokens: %w", err)
	}
	if _, err := s.deps.RefreshTokens.RevokeAllForUser(ctx, user.ID, now); err != nil {
		return fmt.Errorf("service: revoke sessions after reset: %w", err)
	}

	logging.Security(ctx, logging.EventPasswordResetComplete, "user_id", user.ID)
	s.notifyPasswordChanged(ctx, user)
	return nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, presented string) error {
	hash, err := security.HashOpaqueToken(presented)
	if err != nil {
		return ErrInvalidToken
	}
	now := s.now()

	userID, err := s.deps.VerificationTokens.ConsumeByHash(ctx, hash, now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrInvalidToken
		}
		return fmt.Errorf("service: consume verification token: %w", err)
	}
	if err := s.deps.Users.MarkEmailVerified(ctx, userID, now); err != nil {
		return fmt.Errorf("service: mark email verified: %w", err)
	}
	s.deps.Logger.InfoContext(ctx, "email address verified",
		slog.String("event", logging.EventEmailVerified),
		slog.String("user_id", userID))
	return nil
}

type ChangePasswordInput struct {
	UserID          string
	CurrentPassword string
	NewPassword     string
	Metadata        SessionMetadata
}

func (s *AuthService) ChangePassword(ctx context.Context, in ChangePasswordInput) (*Session, error) {
	user, err := s.deps.Users.GetByID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("service: load user: %w", err)
	}

	matches, err := s.deps.Hasher.Verify(in.CurrentPassword, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("service: verify current password: %w", err)
	}
	if !matches {
		logging.Security(ctx, logging.EventLoginFailed, "reason", "change_password_bad_current", "user_id", user.ID)
		return nil, ErrInvalidCredentials
	}
	if in.CurrentPassword == in.NewPassword {
		return nil, ErrPasswordUnchanged
	}
	if issue := s.deps.Policy.Validate("new_password", in.NewPassword, user.Email); issue != nil {
		return nil, fmt.Errorf("%w: %s", ErrWeakPassword, issue.Message)
	}

	newHash, err := s.deps.Hasher.Hash(in.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("service: hash new password: %w", err)
	}
	if err := s.deps.Users.UpdatePasswordHash(ctx, user.ID, newHash); err != nil {
		return nil, fmt.Errorf("service: persist new password: %w", err)
	}

	now := s.now()
	if _, err := s.deps.RefreshTokens.RevokeAllForUser(ctx, user.ID, now); err != nil {
		return nil, fmt.Errorf("service: revoke sessions after password change: %w", err)
	}
	if _, err := s.deps.ResetTokens.InvalidateForUser(ctx, user.ID, now); err != nil {
		return nil, fmt.Errorf("service: invalidate reset tokens after password change: %w", err)
	}

	s.deps.Logger.InfoContext(ctx, "password changed",
		slog.String("event", logging.EventPasswordChanged),
		slog.String("user_id", user.ID))
	s.notifyPasswordChanged(ctx, user)

	user.PasswordHash = newHash
	return s.startSession(ctx, user, uuid.NewString(), in.Metadata)
}

func (s *AuthService) Profile(ctx context.Context, userID string) (*domain.User, error) {
	user, err := s.deps.Users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("service: load profile: %w", err)
	}
	return user, nil
}

func (s *AuthService) UpdateProfile(ctx context.Context, userID, name string) (*domain.User, error) {
	user, err := s.deps.Users.UpdateName(ctx, userID, name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("service: update profile: %w", err)
	}
	return user, nil
}

func (s *AuthService) notifyPasswordChanged(ctx context.Context, user *domain.User) {
	msg, err := s.deps.Composer.PasswordChanged(user.DisplayEmail, user.Name)
	if err != nil {
		s.deps.Logger.ErrorContext(ctx, "failed to compose password change notice", slog.Any("error", err))
		return
	}
	if err := s.deps.Mailer.Send(ctx, msg); err != nil {
		s.deps.Logger.ErrorContext(ctx, "failed to queue password change notice", slog.Any("error", err))
	}
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}

func emailDomain(email string) string {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			return email[i+1:]
		}
	}
	return "unknown"
}

func humanizeTTL(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	case d >= time.Minute:
		minutes := int(d.Minutes())
		if minutes == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	default:
		return d.String()
	}
}
