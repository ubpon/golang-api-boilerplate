package handler

import (
	"net/http"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/service"
)

type CookieSettings struct {
	Domain      string
	Secure      bool
	RefreshPath string
	AccessName  string
	RefreshName string
	CSRFName    string
}

type CookieWriter struct {
	settings CookieSettings
}

func NewCookieWriter(settings CookieSettings) *CookieWriter {
	if settings.RefreshPath == "" {
		settings.RefreshPath = "/v1/auth"
	}
	return &CookieWriter{settings: settings}
}

func (c *CookieWriter) Settings() CookieSettings { return c.settings }

func (c *CookieWriter) Write(w http.ResponseWriter, session *service.Session, now time.Time) {
	http.SetCookie(w, c.build(c.settings.AccessName, session.AccessToken, "/", true,
		int(session.AccessExpiresAt.Sub(now).Seconds())))
	http.SetCookie(w, c.build(c.settings.RefreshName, session.RefreshToken, c.settings.RefreshPath, true,
		int(session.RefreshExpiresAt.Sub(now).Seconds())))
	http.SetCookie(w, c.build(c.settings.CSRFName, session.CSRFToken, "/", false,
		int(session.RefreshExpiresAt.Sub(now).Seconds())))
}

func (c *CookieWriter) Clear(w http.ResponseWriter) {
	http.SetCookie(w, c.build(c.settings.AccessName, "", "/", true, -1))
	http.SetCookie(w, c.build(c.settings.RefreshName, "", c.settings.RefreshPath, true, -1))
	http.SetCookie(w, c.build(c.settings.CSRFName, "", "/", false, -1))
}

func (c *CookieWriter) build(name, value, path string, httpOnly bool, maxAge int) *http.Cookie {
	// #nosec G124 -- Secure is driven by COOKIE_SECURE, which config.Load forces to
	// true in production; local HTTP development needs it off.
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   c.settings.Domain,
		HttpOnly: httpOnly,
		Secure:   c.settings.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
	if maxAge < 0 {
		cookie.Expires = time.Unix(0, 0)
	}
	return cookie
}

func (c *CookieWriter) refreshTokenFrom(r *http.Request) string {
	if cookie, err := r.Cookie(c.settings.RefreshName); err == nil {
		return cookie.Value
	}
	return ""
}
