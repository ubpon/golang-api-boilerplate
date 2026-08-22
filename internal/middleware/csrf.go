package middleware

import (
	"net/http"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/security"
)

const HeaderCSRFToken = "X-CSRF-Token" // #nosec G101 -- header name, not a credential

type CSRFOptions struct {
	CookieName        string
	AuthCookieNames   []string
	HeaderName        string
	AlwaysRequireForm bool
}

func CSRF(opts CSRFOptions) Middleware {
	header := opts.HeaderName
	if header == "" {
		header = HeaderCSRFToken
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if !usesCookieAuth(r, opts.AuthCookieNames) {
				next.ServeHTTP(w, r)
				return
			}

			cookie, err := r.Cookie(opts.CookieName)
			if err != nil || cookie.Value == "" {
				rejectCSRF(w, r)
				return
			}
			if err := security.ValidateCSRF(cookie.Value, r.Header.Get(header)); err != nil {
				rejectCSRF(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func rejectCSRF(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logging.Security(ctx, logging.EventCSRFFailed,
		"route", httpx.Route(ctx),
		"client_ip", httpx.ClientIP(ctx),
	)
	httpx.WriteError(w, r, httpx.ErrCSRF)
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func usesCookieAuth(r *http.Request, names []string) bool {
	if r.Header.Get("Authorization") != "" {
		return false
	}
	for _, name := range names {
		if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
			return true
		}
	}
	return false
}
