package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
)

func AccessLog() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := newRecorder(w)
			ctx := httpx.WithIdentityCapture(httpx.WithRouteCapture(r.Context()))
			r = r.WithContext(ctx)

			next.ServeHTTP(rec, r)

			route := httpx.Route(ctx)
			if route == "" {
				route = "unmatched"
			}

			level := slog.LevelInfo
			switch {
			case rec.status >= http.StatusInternalServerError:
				level = slog.LevelError
			case rec.status >= http.StatusBadRequest:
				level = slog.LevelWarn
			}

			logging.FromContext(ctx).LogAttrs(ctx, level, "http request",
				slog.String("method", r.Method),
				slog.String("route", route),
				slog.Int("status", rec.status),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.Int("bytes", rec.bytes),
				slog.String("client_ip", httpx.ClientIP(ctx)),
				slog.String("user_agent", truncate(r.UserAgent(), 256)),
				slog.String("user_id", httpx.UserID(ctx)),
			)
		})
	}
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
