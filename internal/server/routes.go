package server

import (
	"net/http"

	"github.com/ubpon/golang-api-boilerplate/internal/config"
	"github.com/ubpon/golang-api-boilerplate/internal/handler"
	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/middleware"
	"github.com/ubpon/golang-api-boilerplate/internal/ratelimit"
)

type Routes struct {
	Auth   *handler.Auth
	Me     *handler.Me
	Health *handler.Health
}

func (d *Deps) mux() *http.ServeMux {
	mux := http.NewServeMux()
	rules := d.Rules

	authenticate := middleware.Authenticate(middleware.AuthOptions{
		Verifier:   d.Tokens,
		CookieName: d.Config.Cookies.AccessName,
	})
	csrf := middleware.CSRF(middleware.CSRFOptions{
		CookieName: d.Config.Cookies.CSRFName,
		AuthCookieNames: []string{
			d.Config.Cookies.AccessName,
			d.Config.Cookies.RefreshName,
		},
	})
	perIP := func(rule ratelimit.Rule) middleware.Middleware {
		return middleware.RateLimit(d.Limiter, rule, middleware.ClientIPKey)
	}

	register(mux, "GET /healthz", d.Routes.Health.Live)
	register(mux, "GET /readyz", d.Routes.Health.Ready)

	register(mux, "POST /v1/auth/register", d.Routes.Auth.Register, perIP(rules.RegisterIP))
	register(mux, "POST /v1/auth/login", d.Routes.Auth.Login, perIP(rules.LoginIP))
	register(mux, "POST /v1/auth/refresh", d.Routes.Auth.Refresh, perIP(rules.RefreshIP), csrf)
	register(mux, "POST /v1/auth/logout", d.Routes.Auth.Logout, csrf, authenticate)
	register(mux, "POST /v1/auth/logout-all", d.Routes.Auth.LogoutAll, csrf, authenticate)
	register(mux, "POST /v1/auth/forgot-password", d.Routes.Auth.ForgotPassword, perIP(rules.ForgotIP))
	register(mux, "POST /v1/auth/reset-password", d.Routes.Auth.ResetPassword, perIP(rules.ResetIP))
	register(mux, "POST /v1/auth/verify-email", d.Routes.Auth.VerifyEmail, perIP(rules.VerifyIP))

	register(mux, "GET /v1/me", d.Routes.Me.Show, authenticate)
	register(mux, "PATCH /v1/me", d.Routes.Me.Update, csrf, authenticate)
	register(mux, "POST /v1/me/change-password", d.Routes.Me.ChangePassword, csrf, authenticate)

	return mux
}

func register(mux *http.ServeMux, pattern string, h http.HandlerFunc, mw ...middleware.Middleware) {
	labelled := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.SetRoute(r.Context(), pattern)
		h(w, r)
	})
	mux.Handle(pattern, middleware.Chain(labelled, mw...))
}

func globalChain(cfg *config.Config, d *Deps) []middleware.Middleware {
	return []middleware.Middleware{
		middleware.RequestID(d.Logger),
		middleware.ClientIP(middleware.NewClientIPResolver(cfg.Proxy.TrustedCIDRs)),
		middleware.AccessLog(),
		middleware.Recover(),
		middleware.JSONRoutingErrors(),
		middleware.SecurityHeaders(middleware.SecurityHeadersOptions{
			EnableHSTS:    cfg.IsProduction(),
			HSTSSubdomain: true,
			AssumeTLS:     cfg.Cookies.Secure && cfg.IsProduction(),
		}),
		middleware.CORS(middleware.CORSOptions{
			AllowedOrigins:   cfg.CORS.AllowedOrigins,
			AllowedMethods:   cfg.CORS.AllowedMethods,
			AllowedHeaders:   cfg.CORS.AllowedHeaders,
			ExposedHeaders:   cfg.CORS.ExposedHeaders,
			AllowCredentials: cfg.CORS.AllowCredentials,
			MaxAge:           cfg.CORS.MaxAge,
		}),
		middleware.RateLimitWith(middleware.RateLimitOptions{
			Limiter: d.Limiter,
			Rule:    d.Rules.Global,
			Key:     middleware.ClientIPKey,
			Skip:    skipHealthChecks,
		}),
		middleware.MaxBytes(cfg.HTTP.MaxBodyBytes),
		middleware.Timeout(cfg.HTTP.HandlerTimeout),
	}
}

func skipHealthChecks(r *http.Request) bool {
	return r.URL.Path == "/healthz" || r.URL.Path == "/readyz"
}
