package ratelimit

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
)

type FailoverLimiter struct {
	primary  Limiter
	fallback Limiter
	log      *slog.Logger
	degraded atomic.Bool
}

func NewFailoverLimiter(primary, fallback Limiter, log *slog.Logger) *FailoverLimiter {
	return &FailoverLimiter{primary: primary, fallback: fallback, log: log}
}

func (l *FailoverLimiter) Allow(ctx context.Context, key string, rule Rule) (Decision, error) {
	decision, err := l.primary.Allow(ctx, key, rule)
	if err == nil {
		if l.degraded.CompareAndSwap(true, false) {
			l.log.Info("rate limiter primary backend recovered", slog.String("rule", rule.Name))
		}
		return decision, nil
	}
	if l.degraded.CompareAndSwap(false, true) {
		l.log.Warn("rate limiter primary backend unavailable, falling back to in-process limiter",
			slog.String("rule", rule.Name),
			slog.Any("error", err),
		)
	}
	return l.fallback.Allow(ctx, key, rule)
}

func (l *FailoverLimiter) Degraded() bool { return l.degraded.Load() }

func (l *FailoverLimiter) Close() error {
	return errors.Join(l.primary.Close(), l.fallback.Close())
}
