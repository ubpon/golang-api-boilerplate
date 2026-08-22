package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/security"
)

type AccessTokenVerifier interface {
	Verify(token string) (*security.AccessClaims, error)
}

type AuthOptions struct {
	Verifier    AccessTokenVerifier
	CookieName  string
	ContextOnly bool
}

func Authenticate(opts AuthOptions) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractAccessToken(r, opts.CookieName)
			if !ok {
				if opts.ContextOnly {
					next.ServeHTTP(w, r)
					return
				}
				httpx.WriteError(w, r, httpx.ErrUnauthorized)
				return
			}

			claims, err := opts.Verifier.Verify(raw)
			if err != nil {
				if opts.ContextOnly {
					next.ServeHTTP(w, r)
					return
				}
				logging.FromContext(r.Context()).Debug("access token rejected", slog.Any("error", err))
				httpx.WriteError(w, r, httpx.ErrInvalidToken)
				return
			}

			ctx := r.Context()
			httpx.SetUserID(ctx, claims.Subject)
			ctx = httpx.WithPrincipal(ctx, httpx.Principal{UserID: claims.Subject, TokenID: claims.ID})
			ctx = logging.NewContext(ctx, logging.FromContext(ctx).With(slog.String("user_id", claims.Subject)))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractAccessToken(r *http.Request, cookieName string) (string, bool) {
	if header := r.Header.Get("Authorization"); header != "" {
		const prefix = "Bearer "
		if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
			token := strings.TrimSpace(header[len(prefix):])
			if token != "" {
				return token, true
			}
		}
		return "", false
	}
	if cookieName != "" {
		if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
			return cookie.Value, true
		}
	}
	return "", false
}
