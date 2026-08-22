package middleware

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
)

const HeaderRequestID = "X-Request-ID"

func RequestID(base *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(HeaderRequestID)
			if parsed, err := uuid.Parse(id); err == nil {
				id = parsed.String()
			} else {
				id = uuid.NewString()
			}

			ctx := httpx.WithRequestID(r.Context(), id)
			ctx = logging.NewContext(ctx, base.With(slog.String("request_id", id)))

			w.Header().Set(HeaderRequestID, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
