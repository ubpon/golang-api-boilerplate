package server_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/mailer"
)

var errNotReady = errors.New("database is unavailable")

func TestHealthEndpoints(t *testing.T) {
	h := newHarness(t, harnessOptions{})

	live := h.do(http.MethodGet, "/healthz", nil)
	require.Equal(t, http.StatusOK, live.Status)
	require.Contains(t, string(live.Body), `"status":"ok"`)

	ready := h.do(http.MethodGet, "/readyz", nil)
	require.Equal(t, http.StatusOK, ready.Status)
	require.Contains(t, string(ready.Body), `"database":"ok"`)
}

func TestReadyzReportsDegradedDatabase(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.store.pingErr = errNotReady

	resp := h.do(http.MethodGet, "/readyz", nil)
	require.Equal(t, http.StatusServiceUnavailable, resp.Status)
	require.Contains(t, string(resp.Body), `"database":"unavailable"`)
}

func TestFullAuthenticationLifecycle(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	const email = "lifecycle@example.com"

	registered := h.register(email, testPassword, "Ada Lovelace")
	require.Equal(t, http.StatusAccepted, registered.Status)
	require.Equal(t, 1, h.mailer.count(mailer.TemplateVerifyEmail))

	verification := h.mailer.lastToken(t, mailer.TemplateVerifyEmail)
	require.Equal(t, http.StatusOK, h.verifyEmail(verification).Status)

	replay := h.verifyEmail(verification)
	require.Equal(t, http.StatusUnauthorized, replay.Status)
	require.Equal(t, httpx.CodeInvalidToken, replay.envelope(t).Error.Code)

	loginResp := h.login(email, testPassword)
	require.Equal(t, http.StatusOK, loginResp.Status)

	var session sessionPayload
	loginResp.decode(t, &session)
	require.Equal(t, "Bearer", session.TokenType)
	require.NotEmpty(t, session.AccessToken)
	require.NotEmpty(t, session.RefreshToken)
	require.NotEmpty(t, session.CSRFToken)
	require.True(t, session.User.EmailVerified)
	require.Equal(t, email, session.User.Email)

	accessCookie := loginResp.cookie("access_token")
	require.NotNil(t, accessCookie)
	require.True(t, accessCookie.HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, accessCookie.SameSite)
	require.Equal(t, "/", accessCookie.Path)

	refreshCookie := loginResp.cookie("refresh_token")
	require.NotNil(t, refreshCookie)
	require.True(t, refreshCookie.HttpOnly)
	require.Equal(t, "/v1/auth", refreshCookie.Path)
	require.Positive(t, refreshCookie.MaxAge)

	csrfCookie := loginResp.cookie("csrf_token")
	require.NotNil(t, csrfCookie)
	require.False(t, csrfCookie.HttpOnly)

	profile := h.do(http.MethodGet, "/v1/me", nil)
	require.Equal(t, http.StatusOK, profile.Status)
	require.Contains(t, string(profile.Body), `"name":"Ada Lovelace"`)

	updated := h.do(http.MethodPatch, "/v1/me", map[string]string{"name": "Ada King"})
	require.Equal(t, http.StatusOK, updated.Status)
	require.Contains(t, string(updated.Body), `"name":"Ada King"`)

	refreshed := h.do(http.MethodPost, "/v1/auth/refresh", nil)
	require.Equal(t, http.StatusOK, refreshed.Status)

	var rotated sessionPayload
	refreshed.decode(t, &rotated)
	require.NotEqual(t, session.RefreshToken, rotated.RefreshToken)
	require.NotEmpty(t, rotated.AccessToken)

	changed := h.do(http.MethodPost, "/v1/me/change-password", map[string]string{
		"current_password": testPassword,
		"new_password":     testNewPassword,
	})
	require.Equal(t, http.StatusOK, changed.Status)
	require.Equal(t, 1, h.mailer.count(mailer.TemplatePasswordChange))

	stale := h.do(http.MethodPost, "/v1/auth/refresh", nil, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "refresh_token", Value: rotated.RefreshToken})
	})
	require.Equal(t, http.StatusUnauthorized, stale.Status)

	require.Equal(t, http.StatusUnauthorized, h.login(email, testPassword).Status)
	fresh := h.loginSession(email, testNewPassword)
	require.NotEmpty(t, fresh.AccessToken)

	logout := h.do(http.MethodPost, "/v1/auth/logout", nil)
	require.Equal(t, http.StatusNoContent, logout.Status)
	require.Equal(t, -1, logout.cookie("access_token").MaxAge)
	require.Equal(t, -1, logout.cookie("refresh_token").MaxAge)

	revoked := h.do(http.MethodPost, "/v1/auth/refresh",
		map[string]string{"refresh_token": fresh.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, revoked.Status)
}

func TestBearerClientsCanUseEveryAuthenticatedRoute(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const email = "bearer@example.com"

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Bearer Bob").Status)
	require.Equal(t, http.StatusOK, h.verifyEmail(h.mailer.lastToken(t, mailer.TemplateVerifyEmail)).Status)
	session := h.loginSession(email, testPassword)

	profile := h.do(http.MethodGet, "/v1/me", nil, bearer(session.AccessToken))
	require.Equal(t, http.StatusOK, profile.Status)

	patched := h.do(http.MethodPatch, "/v1/me", map[string]string{"name": "Bob B"}, bearer(session.AccessToken))
	require.Equal(t, http.StatusOK, patched.Status)

	refreshed := h.do(http.MethodPost, "/v1/auth/refresh",
		map[string]string{"refresh_token": session.RefreshToken})
	require.Equal(t, http.StatusOK, refreshed.Status)

	var rotated sessionPayload
	refreshed.decode(t, &rotated)

	logoutAll := h.do(http.MethodPost, "/v1/auth/logout-all", nil, bearer(rotated.AccessToken))
	require.Equal(t, http.StatusNoContent, logoutAll.Status)

	dead := h.do(http.MethodPost, "/v1/auth/refresh",
		map[string]string{"refresh_token": rotated.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, dead.Status)
}

func TestLogoutAllRevokesEverySession(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const email = "sessions@example.com"

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Multi Device").Status)
	require.Equal(t, http.StatusOK, h.verifyEmail(h.mailer.lastToken(t, mailer.TemplateVerifyEmail)).Status)

	phone := h.loginSession(email, testPassword)
	laptop := h.loginSession(email, testPassword)
	require.NotEqual(t, phone.RefreshToken, laptop.RefreshToken)

	require.Equal(t, http.StatusNoContent,
		h.do(http.MethodPost, "/v1/auth/logout-all", nil, bearer(laptop.AccessToken)).Status)

	for _, token := range []string{phone.RefreshToken, laptop.RefreshToken} {
		resp := h.do(http.MethodPost, "/v1/auth/refresh", map[string]string{"refresh_token": token})
		require.Equal(t, http.StatusUnauthorized, resp.Status)
	}
}

func TestForgotAndResetPasswordFlow(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const email = "reset@example.com"

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Reset Person").Status)
	session := h.loginSession(email, testPassword)

	forgot := h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": email})
	require.Equal(t, http.StatusAccepted, forgot.Status)

	token := h.mailer.lastToken(t, mailer.TemplatePasswordReset)
	reset := h.do(http.MethodPost, "/v1/auth/reset-password", map[string]string{
		"token": token, "new_password": testNewPassword,
	})
	require.Equal(t, http.StatusOK, reset.Status)
	require.True(t, h.hasSecurityEvent(logging.EventPasswordResetComplete))

	dead := h.do(http.MethodPost, "/v1/auth/refresh", map[string]string{"refresh_token": session.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, dead.Status)

	require.Equal(t, http.StatusUnauthorized, h.login(email, testPassword).Status)
	require.NotEmpty(t, h.loginSession(email, testNewPassword).AccessToken)
}

func TestIssuingANewResetTokenInvalidatesThePreviousOne(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const email = "rotate-reset@example.com"

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Rotate").Status)

	require.Equal(t, http.StatusAccepted,
		h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": email}).Status)
	first := h.mailer.lastToken(t, mailer.TemplatePasswordReset)

	require.Equal(t, http.StatusAccepted,
		h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": email}).Status)
	second := h.mailer.lastToken(t, mailer.TemplatePasswordReset)
	require.NotEqual(t, first, second)

	stale := h.do(http.MethodPost, "/v1/auth/reset-password", map[string]string{
		"token": first, "new_password": testNewPassword,
	})
	require.Equal(t, http.StatusUnauthorized, stale.Status)

	current := h.do(http.MethodPost, "/v1/auth/reset-password", map[string]string{
		"token": second, "new_password": testNewPassword,
	})
	require.Equal(t, http.StatusOK, current.Status)
}

func TestChangePasswordRequiresCorrectCurrentPassword(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	session := h.registerVerifiedUser("change@example.com")

	wrong := h.do(http.MethodPost, "/v1/me/change-password", map[string]string{
		"current_password": "definitely-not-the-password",
		"new_password":     testNewPassword,
	}, bearer(session.AccessToken))
	require.Equal(t, http.StatusUnauthorized, wrong.Status)
	require.Equal(t, httpx.CodeInvalidCredentials, wrong.envelope(t).Error.Code)

	same := h.do(http.MethodPost, "/v1/me/change-password", map[string]string{
		"current_password": testPassword,
		"new_password":     testPassword,
	}, bearer(session.AccessToken))
	require.Equal(t, http.StatusUnprocessableEntity, same.Status)
	require.Equal(t, httpx.CodePasswordUnchanged, same.envelope(t).Error.Code)
}

func TestUnauthenticatedAccessIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/me"},
		{http.MethodPatch, "/v1/me"},
		{http.MethodPost, "/v1/me/change-password"},
		{http.MethodPost, "/v1/auth/logout"},
		{http.MethodPost, "/v1/auth/logout-all"},
	} {
		resp := h.do(tc.method, tc.path, map[string]string{})
		require.Equal(t, http.StatusUnauthorized, resp.Status, "%s %s", tc.method, tc.path)
		require.Equal(t, httpx.CodeUnauthorized, resp.envelope(t).Error.Code)
	}
}

func TestInvalidAndExpiredAccessTokensAreRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	session := h.registerVerifiedUser("expiry@example.com")

	require.Equal(t, http.StatusOK, h.do(http.MethodGet, "/v1/me", nil, bearer(session.AccessToken)).Status)

	garbage := h.do(http.MethodGet, "/v1/me", nil, bearer("not.a.jwt"))
	require.Equal(t, http.StatusUnauthorized, garbage.Status)
	require.Equal(t, httpx.CodeInvalidToken, garbage.envelope(t).Error.Code)

	h.clock.Advance(16 * time.Minute)
	expired := h.do(http.MethodGet, "/v1/me", nil, bearer(session.AccessToken))
	require.Equal(t, http.StatusUnauthorized, expired.Status)
	require.Equal(t, httpx.CodeInvalidToken, expired.envelope(t).Error.Code)
}

func TestRoutingErrorsUseTheJSONEnvelope(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	missing := h.do(http.MethodGet, "/v1/does-not-exist", nil)
	require.Equal(t, http.StatusNotFound, missing.Status)
	require.Equal(t, httpx.CodeNotFound, missing.envelope(t).Error.Code)
	require.NotEmpty(t, missing.envelope(t).Error.RequestID)

	wrongMethod := h.do(http.MethodDelete, "/v1/auth/login", nil)
	require.Equal(t, http.StatusMethodNotAllowed, wrongMethod.Status)
	require.Equal(t, httpx.CodeMethodNotAllowed, wrongMethod.envelope(t).Error.Code)
}

func TestValidationFailuresReturn422WithDetails(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	resp := h.do(http.MethodPost, "/v1/auth/register", map[string]string{
		"email": "not-an-email", "password": "short", "name": "x",
	})
	require.Equal(t, http.StatusUnprocessableEntity, resp.Status)

	envelope := resp.envelope(t)
	require.Equal(t, httpx.CodeValidationFailed, envelope.Error.Code)
	require.Len(t, envelope.Error.Details, 2)

	fields := map[string]string{}
	for _, detail := range envelope.Error.Details {
		fields[detail.Field] = detail.Issue
	}
	require.Contains(t, fields, "email")
	require.Contains(t, fields, "password")
}

func TestUnknownFieldsAndMalformedBodiesAreRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	unknown := h.doRaw(http.MethodPost, "/v1/auth/login",
		`{"email":"a@example.com","password":"whatever-long","is_admin":true}`)
	require.Equal(t, http.StatusUnprocessableEntity, unknown.Status)
	require.Equal(t, "is_admin", unknown.envelope(t).Error.Details[0].Field)

	malformed := h.doRaw(http.MethodPost, "/v1/auth/login", `{"email":`)
	require.Equal(t, http.StatusBadRequest, malformed.Status)
	require.Equal(t, httpx.CodeMalformedJSON, malformed.envelope(t).Error.Code)

	trailing := h.doRaw(http.MethodPost, "/v1/auth/login",
		`{"email":"a@example.com","password":"whatever-long"}{"email":"b@example.com"}`)
	require.Equal(t, http.StatusBadRequest, trailing.Status)
	require.Equal(t, httpx.CodeMalformedJSON, trailing.envelope(t).Error.Code)

	wrongType := h.doRaw(http.MethodPost, "/v1/auth/login", `{"email":123,"password":"whatever-long"}`)
	require.Equal(t, http.StatusUnprocessableEntity, wrongType.Status)

	empty := h.doRaw(http.MethodPost, "/v1/auth/login", ``)
	require.Equal(t, http.StatusBadRequest, empty.Status)
}

func TestNonJSONContentTypeIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	resp := h.doRaw(http.MethodPost, "/v1/auth/login", `{"email":"a@example.com"}`, func(r *http.Request) {
		r.Header.Set("Content-Type", "text/plain")
	})
	require.Equal(t, http.StatusUnsupportedMediaType, resp.Status)
	require.Equal(t, httpx.CodeUnsupportedMedia, resp.envelope(t).Error.Code)
}

func TestSecurityHeadersAreAppliedToEveryResponse(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	resp := h.do(http.MethodGet, "/healthz", nil)
	require.Equal(t, "nosniff", resp.Headers.Get("X-Content-Type-Options"))
	require.Equal(t, "DENY", resp.Headers.Get("X-Frame-Options"))
	require.Equal(t, "no-referrer", resp.Headers.Get("Referrer-Policy"))
	require.Contains(t, resp.Headers.Get("Content-Security-Policy"), "frame-ancestors 'none'")
	require.NotEmpty(t, resp.Headers.Get("X-Request-ID"))
}

func TestPasswordsAndTokensNeverReachTheLogs(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	session := h.registerVerifiedUser("quiet@example.com")

	require.Equal(t, http.StatusOK, h.do(http.MethodGet, "/v1/me", nil, bearer(session.AccessToken)).Status)
	require.Equal(t, http.StatusAccepted,
		h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": "quiet@example.com"}).Status)

	logs := h.logs.String()
	require.NotEmpty(t, logs)
	require.NotContains(t, logs, testPassword)
	require.NotContains(t, logs, session.AccessToken)
	require.NotContains(t, logs, session.RefreshToken)
	require.NotContains(t, logs, session.CSRFToken)
	require.NotContains(t, logs, h.mailer.lastToken(t, mailer.TemplatePasswordReset))
	require.NotContains(t, strings.ToLower(logs), "reset-password?token=")
}

func TestAccessLogUsesRoutePatternsNotRawPaths(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	require.Equal(t, http.StatusOK, h.do(http.MethodGet, "/healthz", nil).Status)

	found := false
	for _, entry := range h.logLines() {
		if entry["msg"] == "http request" && entry["route"] == "GET /healthz" {
			found = true
			require.Equal(t, float64(200), entry["status"])
			require.Contains(t, entry, "duration_ms")
			require.Contains(t, entry, "bytes")
			require.Contains(t, entry, "client_ip")
			require.Contains(t, entry, "request_id")
		}
	}
	require.True(t, found, "expected an access log line for GET /healthz")
}
