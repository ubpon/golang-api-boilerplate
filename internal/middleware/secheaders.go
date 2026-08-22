package middleware

import (
	"fmt"
	"net/http"
	"time"
)

type SecurityHeadersOptions struct {
	EnableHSTS    bool
	HSTSMaxAge    time.Duration
	HSTSSubdomain bool
	HSTSPreload   bool
	AssumeTLS     bool
}

func SecurityHeaders(opts SecurityHeadersOptions) Middleware {
	hsts := buildHSTS(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Cross-Origin-Embedder-Policy", "require-corp")
			h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()")
			h.Set("X-Permitted-Cross-Domain-Policies", "none")

			if hsts != "" && (r.TLS != nil || opts.AssumeTLS) {
				h.Set("Strict-Transport-Security", hsts)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func buildHSTS(opts SecurityHeadersOptions) string {
	if !opts.EnableHSTS {
		return ""
	}
	maxAge := opts.HSTSMaxAge
	if maxAge <= 0 {
		maxAge = 365 * 24 * time.Hour
	}
	value := fmt.Sprintf("max-age=%d", int(maxAge.Seconds()))
	if opts.HSTSSubdomain {
		value += "; includeSubDomains"
	}
	if opts.HSTSPreload {
		value += "; preload"
	}
	return value
}
