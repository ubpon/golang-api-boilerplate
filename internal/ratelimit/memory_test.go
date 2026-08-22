package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestMemoryLimiterTripsAtThreshold(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	limiter := NewMemoryLimiter(MemoryOptions{Clock: clock.Now})
	t.Cleanup(func() { require.NoError(t, limiter.Close()) })

	rule := Rule{Name: "login.ip", Limit: 5, Window: 15 * time.Minute}
	ctx := context.Background()

	for i := 0; i < rule.Limit; i++ {
		decision, err := limiter.Allow(ctx, "203.0.113.7", rule)
		require.NoError(t, err)
		require.True(t, decision.Allowed, "request %d should be allowed", i+1)
		require.Equal(t, rule.Limit, decision.Limit)
		require.Equal(t, rule.Limit-i-1, decision.Remaining)
	}

	decision, err := limiter.Allow(ctx, "203.0.113.7", rule)
	require.NoError(t, err)
	require.False(t, decision.Allowed)
	require.Zero(t, decision.Remaining)
	require.Greater(t, decision.RetryAfter, time.Duration(0))
	require.LessOrEqual(t, decision.RetryAfter, 3*time.Minute)
}

func TestMemoryLimiterRefillsOverTime(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	limiter := NewMemoryLimiter(MemoryOptions{Clock: clock.Now})
	t.Cleanup(func() { require.NoError(t, limiter.Close()) })

	rule := Rule{Name: "login.ip", Limit: 5, Window: 15 * time.Minute}
	ctx := context.Background()

	for i := 0; i < rule.Limit; i++ {
		_, err := limiter.Allow(ctx, "key", rule)
		require.NoError(t, err)
	}
	denied, err := limiter.Allow(ctx, "key", rule)
	require.NoError(t, err)
	require.False(t, denied.Allowed)

	clock.Advance(3 * time.Minute)
	allowed, err := limiter.Allow(ctx, "key", rule)
	require.NoError(t, err)
	require.True(t, allowed.Allowed)

	again, err := limiter.Allow(ctx, "key", rule)
	require.NoError(t, err)
	require.False(t, again.Allowed)

	clock.Advance(rule.Window)
	for i := 0; i < rule.Limit; i++ {
		decision, err := limiter.Allow(ctx, "key", rule)
		require.NoError(t, err)
		require.True(t, decision.Allowed, "request %d after a full window should be allowed", i+1)
	}
}

func TestMemoryLimiterIsolatesKeysAndRules(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	limiter := NewMemoryLimiter(MemoryOptions{Clock: clock.Now})
	t.Cleanup(func() { require.NoError(t, limiter.Close()) })

	ctx := context.Background()
	loginRule := Rule{Name: "login.ip", Limit: 1, Window: time.Minute}
	registerRule := Rule{Name: "register.ip", Limit: 1, Window: time.Minute}

	first, err := limiter.Allow(ctx, "a", loginRule)
	require.NoError(t, err)
	require.True(t, first.Allowed)

	blocked, err := limiter.Allow(ctx, "a", loginRule)
	require.NoError(t, err)
	require.False(t, blocked.Allowed)

	otherKey, err := limiter.Allow(ctx, "b", loginRule)
	require.NoError(t, err)
	require.True(t, otherKey.Allowed)

	otherRule, err := limiter.Allow(ctx, "a", registerRule)
	require.NoError(t, err)
	require.True(t, otherRule.Allowed)
}

func TestMemoryLimiterEvictsIdleBuckets(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	limiter := NewMemoryLimiter(MemoryOptions{Clock: clock.Now, IdleTTL: 10 * time.Minute})
	t.Cleanup(func() { require.NoError(t, limiter.Close()) })

	ctx := context.Background()
	rule := Rule{Name: "global.ip", Limit: 100, Window: time.Minute}

	for i := 0; i < 500; i++ {
		_, err := limiter.Allow(ctx, fmt.Sprintf("10.0.0.%d", i), rule)
		require.NoError(t, err)
	}
	require.Equal(t, 500, limiter.Len())

	clock.Advance(5 * time.Minute)
	require.Zero(t, limiter.Sweep())
	require.Equal(t, 500, limiter.Len())

	clock.Advance(10 * time.Minute)
	require.Equal(t, 500, limiter.Sweep())
	require.Zero(t, limiter.Len())
}

func TestMemoryLimiterAllowsInvalidRules(t *testing.T) {
	t.Parallel()

	limiter := NewMemoryLimiter(MemoryOptions{})
	t.Cleanup(func() { require.NoError(t, limiter.Close()) })

	decision, err := limiter.Allow(context.Background(), "key", Rule{Name: "disabled"})
	require.NoError(t, err)
	require.True(t, decision.Allowed)
}

func TestMemoryLimiterIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	limiter := NewMemoryLimiter(MemoryOptions{})
	t.Cleanup(func() { require.NoError(t, limiter.Close()) })

	rule := Rule{Name: "global.ip", Limit: 1000, Window: time.Minute}
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := limiter.Allow(ctx, fmt.Sprintf("key-%d", worker%4), rule); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestJanitorStopsOnClose(t *testing.T) {
	t.Parallel()

	limiter := NewMemoryLimiter(MemoryOptions{StartJanitor: true, SweepEvery: time.Millisecond})
	require.NoError(t, limiter.Close())
	require.NoError(t, limiter.Close())
}

func TestRuleStringAndValidity(t *testing.T) {
	t.Parallel()

	rule := Rule{Name: "login.ip", Limit: 5, Window: 15 * time.Minute}
	require.True(t, rule.Valid())
	require.Equal(t, "login.ip(5/15m0s)", rule.String())
	require.False(t, Rule{Name: "x"}.Valid())
}

func TestDefaultRulesMatchDocumentedThresholds(t *testing.T) {
	t.Parallel()

	rules := DefaultRules()
	require.Equal(t, Rule{Name: "global.ip", Limit: 100, Window: time.Minute}, rules.Global)
	require.Equal(t, Rule{Name: "login.ip", Limit: 5, Window: 15 * time.Minute}, rules.LoginIP)
	require.Equal(t, Rule{Name: "login.email", Limit: 5, Window: 15 * time.Minute}, rules.LoginEmail)
	require.Equal(t, Rule{Name: "register.ip", Limit: 5, Window: time.Hour}, rules.RegisterIP)
	require.Equal(t, Rule{Name: "forgot.ip", Limit: 3, Window: time.Hour}, rules.ForgotIP)
	require.Equal(t, Rule{Name: "forgot.email", Limit: 3, Window: time.Hour}, rules.ForgotEmail)
	require.Equal(t, Rule{Name: "refresh.ip", Limit: 30, Window: time.Hour}, rules.RefreshIP)
}
