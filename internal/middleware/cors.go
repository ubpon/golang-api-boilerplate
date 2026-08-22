package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
)

type CORSOptions struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
}

func CORS(opts CORSOptions) Middleware {
	allowed := make(map[string]struct{}, len(opts.AllowedOrigins))
	wildcard := false
	for _, origin := range opts.AllowedOrigins {
		if origin == "*" {
			wildcard = true
			continue
		}
		allowed[strings.ToLower(strings.TrimRight(origin, "/"))] = struct{}{}
	}
	if wildcard && opts.AllowCredentials {
		wildcard = false
	}

	methods := strings.Join(opts.AllowedMethods, ", ")
	headers := strings.Join(opts.AllowedHeaders, ", ")
	exposed := strings.Join(opts.ExposedHeaders, ", ")
	maxAge := strconv.Itoa(int(opts.MaxAge.Seconds()))

	isAllowed := func(origin string) bool {
		if wildcard {
			return true
		}
		_, ok := allowed[strings.ToLower(strings.TrimRight(origin, "/"))]
		return ok
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""

			if origin == "" {
				if preflight {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Add("Vary", "Origin")
			if !isAllowed(origin) {
				httpx.WriteError(w, r, httpx.ErrOrigin)
				return
			}

			if wildcard {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			if opts.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			if exposed != "" {
				w.Header().Set("Access-Control-Expose-Headers", exposed)
			}

			if preflight {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				w.Header().Set("Access-Control-Allow-Methods", methods)
				w.Header().Set("Access-Control-Allow-Headers", headers)
				w.Header().Set("Access-Control-Max-Age", maxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
