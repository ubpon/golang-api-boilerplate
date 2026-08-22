package middleware

import (
	"net/http"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
)

func MaxBytes(limit int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r.WithContext(httpx.WithBodyLimit(r.Context(), limit)))
		})
	}
}
