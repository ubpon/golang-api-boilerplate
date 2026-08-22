package ratelimit

import (
	"context"
	"fmt"
	"time"
)

type Rule struct {
	Name   string
	Limit  int
	Window time.Duration
}

func (r Rule) Valid() bool {
	return r.Limit > 0 && r.Window > 0
}

func (r Rule) String() string {
	return fmt.Sprintf("%s(%d/%s)", r.Name, r.Limit, r.Window)
}

type Decision struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
	ResetAfter time.Duration
}

type Limiter interface {
	Allow(ctx context.Context, key string, rule Rule) (Decision, error)
	Close() error
}

type Clock func() time.Time

func allowedDecision(rule Rule, remaining int, reset time.Duration) Decision {
	return Decision{
		Allowed:    true,
		Limit:      rule.Limit,
		Remaining:  remaining,
		ResetAfter: reset,
	}
}

func deniedDecision(rule Rule, retry time.Duration) Decision {
	return Decision{
		Allowed:    false,
		Limit:      rule.Limit,
		Remaining:  0,
		RetryAfter: retry,
		ResetAfter: retry,
	}
}
