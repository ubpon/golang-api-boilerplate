package logging

import (
	"context"
	"log/slog"
)

const (
	EventLoginFailed           = "auth.login_failed"
	EventLoginSucceeded        = "auth.login_succeeded"
	EventAccountLocked         = "auth.account_locked"
	EventRefreshReuseDetected  = "auth.refresh_reuse_detected"
	EventPasswordResetRequest  = "auth.password_reset_requested"
	EventPasswordResetComplete = "auth.password_reset_completed"
	EventPasswordChanged       = "auth.password_changed"
	EventEmailVerified         = "auth.email_verified"
	EventRateLimitExceeded     = "ratelimit.exceeded"
	EventCSRFFailed            = "csrf.failed"
	EventPanicRecovered        = "http.panic_recovered"
)

func Security(ctx context.Context, event string, args ...any) {
	FromContext(ctx).LogAttrs(ctx, slog.LevelWarn, "security event",
		append([]slog.Attr{slog.String("event", event)}, attrs(args)...)...)
}

func attrs(args []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		out = append(out, slog.Any(key, args[i+1]))
	}
	return out
}
