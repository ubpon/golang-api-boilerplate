package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/repository"
)

type Cleanup struct {
	store    repository.Store
	log      *slog.Logger
	interval time.Duration
	now      Clock
}

func NewCleanup(store repository.Store, log *slog.Logger, interval time.Duration, clock Clock) *Cleanup {
	if interval <= 0 {
		interval = time.Hour
	}
	if clock == nil {
		clock = time.Now
	}
	return &Cleanup{store: store, log: log, interval: interval, now: clock}
}

func (c *Cleanup) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Once(ctx)
		}
	}
}

func (c *Cleanup) Once(ctx context.Context) {
	cutoff := c.now()
	refresh, err := c.store.RefreshTokens().DeleteExpired(ctx, cutoff)
	if err != nil {
		c.log.ErrorContext(ctx, "failed to purge expired refresh tokens", slog.Any("error", err))
	}
	resets, err := c.store.PasswordResetTokens().DeleteExpired(ctx, cutoff)
	if err != nil {
		c.log.ErrorContext(ctx, "failed to purge expired reset tokens", slog.Any("error", err))
	}
	verifications, err := c.store.EmailVerificationTokens().DeleteExpired(ctx, cutoff)
	if err != nil {
		c.log.ErrorContext(ctx, "failed to purge expired verification tokens", slog.Any("error", err))
	}

	if refresh+resets+verifications > 0 {
		c.log.InfoContext(ctx, "purged expired tokens",
			slog.Int64("refresh_tokens", refresh),
			slog.Int64("password_reset_tokens", resets),
			slog.Int64("email_verification_tokens", verifications),
		)
	}
}
