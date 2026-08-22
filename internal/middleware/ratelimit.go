package middleware

import (
	"log/slog"
	"net/http"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/ratelimit"
)

type KeyFunc func(r *http.Request) string

func ClientIPKey(r *http.Request) string {
	ip := httpx.ClientIP(r.Context())
	if ip == "" {
		return "unknown"
	}
	return ip
}

type RateLimitOptions struct {
	Limiter ratelimit.Limiter
	Rule    ratelimit.Rule
	Key     KeyFunc
	Skip    func(r *http.Request) bool
}

func RateLimit(limiter ratelimit.Limiter, rule ratelimit.Rule, key KeyFunc) Middleware {
	return RateLimitWith(RateLimitOptions{Limiter: limiter, Rule: rule, Key: key})
}

func RateLimitWith(opts RateLimitOptions) Middleware {
	limiter, rule, key := opts.Limiter, opts.Rule, opts.Key
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opts.Skip != nil && opts.Skip(r) {
				next.ServeHTTP(w, r)
				return
			}
			ctx := r.Context()
			decision, err := limiter.Allow(ctx, key(r), rule)
			if err != nil {
				logging.FromContext(ctx).Error("rate limiter unavailable, allowing request",
					slog.String("rule", rule.Name),
					slog.Any("error", err),
				)
				next.ServeHTTP(w, r)
				return
			}

			ratelimit.WriteHeaders(w, decision)
			if !decision.Allowed {
				logging.Security(ctx, logging.EventRateLimitExceeded,
					"rule", rule.Name,
					"client_ip", httpx.ClientIP(ctx),
					"route", httpx.Route(ctx),
				)
				httpx.WriteError(w, r, httpx.ErrRateLimited)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
