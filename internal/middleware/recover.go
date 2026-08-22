package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
)

func Recover() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(rec)
				}

				logging.FromContext(ctx).LogAttrs(ctx, slog.LevelError, "recovered from panic",
					slog.String("event", logging.EventPanicRecovered),
					slog.Any("panic", rec),
					slog.String("request_id", httpx.RequestID(ctx)),
					slog.String("stack", string(debug.Stack())),
				)
				httpx.WriteError(w, r, httpx.ErrInternal)
			}()

			next.ServeHTTP(w, r)
		})
	}
}
