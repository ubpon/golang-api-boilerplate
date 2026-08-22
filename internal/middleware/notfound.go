package middleware

import (
	"net/http"
	"strings"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
)

type fallbackWriter struct {
	http.ResponseWriter
	request   *http.Request
	committed bool
	swallow   bool
}

func (f *fallbackWriter) WriteHeader(status int) {
	if f.committed {
		return
	}
	f.committed = true

	isJSON := strings.HasPrefix(f.Header().Get("Content-Type"), "application/json")
	if !isJSON && (status == http.StatusNotFound || status == http.StatusMethodNotAllowed) {
		f.swallow = true
		if status == http.StatusMethodNotAllowed {
			httpx.WriteError(f.ResponseWriter, f.request, httpx.ErrMethod)
		} else {
			httpx.WriteError(f.ResponseWriter, f.request, httpx.ErrNotFound)
		}
		return
	}
	f.ResponseWriter.WriteHeader(status)
}

func (f *fallbackWriter) Write(b []byte) (int, error) {
	if !f.committed {
		f.WriteHeader(http.StatusOK)
	}
	if f.swallow {
		return len(b), nil
	}
	return f.ResponseWriter.Write(b)
}

func (f *fallbackWriter) Unwrap() http.ResponseWriter { return f.ResponseWriter }

func JSONRoutingErrors() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&fallbackWriter{ResponseWriter: w, request: r}, r)
		})
	}
}
