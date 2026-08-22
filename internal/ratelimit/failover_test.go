package ratelimit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type stubLimiter struct {
	decision Decision
	err      error
	calls    int
}

func (s *stubLimiter) Allow(context.Context, string, Rule) (Decision, error) {
	s.calls++
	return s.decision, s.err
}

func (s *stubLimiter) Close() error { return nil }

func TestFailoverUsesPrimaryWhenHealthy(t *testing.T) {
	t.Parallel()

	primary := &stubLimiter{decision: Decision{Allowed: true, Limit: 5, Remaining: 4}}
	fallback := &stubLimiter{decision: Decision{Allowed: true}}
	limiter := NewFailoverLimiter(primary, fallback, slog.New(slog.NewTextHandler(io.Discard, nil)))

	decision, err := limiter.Allow(context.Background(), "key", Rule{Name: "r", Limit: 5, Window: time.Minute})
	require.NoError(t, err)
	require.Equal(t, 4, decision.Remaining)
	require.Equal(t, 1, primary.calls)
	require.Zero(t, fallback.calls)
	require.False(t, limiter.Degraded())
}

func TestFailoverDegradesToFallback(t *testing.T) {
	t.Parallel()

	primary := &stubLimiter{err: errors.New("redis is down")}
	fallback := &stubLimiter{decision: Decision{Allowed: false, RetryAfter: time.Second}}
	limiter := NewFailoverLimiter(primary, fallback, slog.New(slog.NewTextHandler(io.Discard, nil)))

	decision, err := limiter.Allow(context.Background(), "key", Rule{Name: "r", Limit: 5, Window: time.Minute})
	require.NoError(t, err)
	require.False(t, decision.Allowed)
	require.Equal(t, 1, fallback.calls)
	require.True(t, limiter.Degraded())

	primary.err = nil
	primary.decision = Decision{Allowed: true}
	_, err = limiter.Allow(context.Background(), "key", Rule{Name: "r", Limit: 5, Window: time.Minute})
	require.NoError(t, err)
	require.False(t, limiter.Degraded())
}
