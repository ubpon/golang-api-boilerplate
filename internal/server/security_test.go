package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/mailer"
	"github.com/ubpon/golang-api-boilerplate/internal/ratelimit"
)

func TestLoginDoesNotLeakAccountExistence(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const known = "known@example.com"

	require.Equal(t, http.StatusAccepted, h.register(known, testPassword, "Known").Status)

	unknown := h.login("definitely-not-registered@example.com", "some-other-long-password")
	existing := h.login(known, "some-other-long-password")

	require.Equal(t, unknown.Status, existing.Status)
	require.Equal(t, http.StatusUnauthorized, unknown.Status)
	require.JSONEq(t, normaliseRequestID(t, unknown.Body), normaliseRequestID(t, existing.Body))
}

func TestRegisterDoesNotLeakAccountExistence(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const email = "duplicate@example.com"

	first := h.register(email, testPassword, "First")
	require.Equal(t, http.StatusAccepted, first.Status)
	require.Equal(t, http.StatusOK, h.verifyEmail(h.mailer.lastToken(t, mailer.TemplateVerifyEmail)).Status)

	h.mailer.reset()
	second := h.register(email, "a-completely-different-phrase", "Impostor")

	require.Equal(t, first.Status, second.Status)
	require.JSONEq(t, string(first.Body), string(second.Body))
	require.Zero(t, h.mailer.count(mailer.TemplateVerifyEmail))

	require.Equal(t, http.StatusUnauthorized, h.login(email, "a-completely-different-phrase").Status)
	require.NotEmpty(t, h.loginSession(email, testPassword).AccessToken)
}

func TestForgotPasswordDoesNotLeakAccountExistence(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const known = "present@example.com"

	require.Equal(t, http.StatusAccepted, h.register(known, testPassword, "Present").Status)
	h.mailer.reset()

	present := h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": known})
	absent := h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": "absent@example.com"})

	require.Equal(t, http.StatusAccepted, present.Status)
	require.Equal(t, present.Status, absent.Status)
	require.JSONEq(t, string(present.Body), string(absent.Body))
	require.Equal(t, 1, h.mailer.count(mailer.TemplatePasswordReset))
}

func TestReusedRefreshTokenRevokesTheWholeFamily(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	session := h.registerVerifiedUser("reuse@example.com")

	first := h.do(http.MethodPost, "/v1/auth/refresh", map[string]string{"refresh_token": session.RefreshToken})
	require.Equal(t, http.StatusOK, first.Status)

	var rotated sessionPayload
	first.decode(t, &rotated)

	replay := h.do(http.MethodPost, "/v1/auth/refresh", map[string]string{"refresh_token": session.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, replay.Status)
	require.Equal(t, httpx.CodeInvalidToken, replay.envelope(t).Error.Code)
	require.True(t, h.hasSecurityEvent(logging.EventRefreshReuseDetected))

	descendant := h.do(http.MethodPost, "/v1/auth/refresh", map[string]string{"refresh_token": rotated.RefreshToken})
	require.Equal(t, http.StatusUnauthorized, descendant.Status,
		"the rotated descendant token must be revoked once reuse is detected")
}

func TestRefreshRejectsUnknownAndMalformedTokens(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	for _, token := range []string{"", "not-base64!!", "AAAA", strings.Repeat("A", 43)} {
		resp := h.do(http.MethodPost, "/v1/auth/refresh", map[string]string{"refresh_token": token})
		require.Equal(t, http.StatusUnauthorized, resp.Status, "token %q must be rejected", token)
	}
}

func TestExpiredResetTokenIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true, env: map[string]string{"RESET_TOKEN_TTL": "15m"}})
	const email = "expired-reset@example.com"

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Expired").Status)
	require.Equal(t, http.StatusAccepted,
		h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": email}).Status)

	token := h.mailer.lastToken(t, mailer.TemplatePasswordReset)
	h.clock.Advance(16 * time.Minute)

	resp := h.do(http.MethodPost, "/v1/auth/reset-password", map[string]string{
		"token": token, "new_password": testNewPassword,
	})
	require.Equal(t, http.StatusUnauthorized, resp.Status)
	require.Equal(t, httpx.CodeInvalidToken, resp.envelope(t).Error.Code)
	require.NotEmpty(t, h.loginSession(email, testPassword).AccessToken)
}

func TestResetTokenCannotBeUsedTwice(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const email = "single-use@example.com"

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Single Use").Status)
	require.Equal(t, http.StatusAccepted,
		h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": email}).Status)

	token := h.mailer.lastToken(t, mailer.TemplatePasswordReset)

	first := h.do(http.MethodPost, "/v1/auth/reset-password", map[string]string{
		"token": token, "new_password": testNewPassword,
	})
	require.Equal(t, http.StatusOK, first.Status)

	second := h.do(http.MethodPost, "/v1/auth/reset-password", map[string]string{
		"token": token, "new_password": "yet-another-distinct-phrase",
	})
	require.Equal(t, http.StatusUnauthorized, second.Status)
	require.NotEmpty(t, h.loginSession(email, testNewPassword).AccessToken)
}

func TestExpiredVerificationTokenIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true, env: map[string]string{"VERIFY_TOKEN_TTL": "1h"}})

	require.Equal(t, http.StatusAccepted, h.register("slow@example.com", testPassword, "Slow").Status)
	token := h.mailer.lastToken(t, mailer.TemplateVerifyEmail)

	h.clock.Advance(2 * time.Hour)
	require.Equal(t, http.StatusUnauthorized, h.verifyEmail(token).Status)
}

func TestOversizedBodyReturns413(t *testing.T) {
	h := newHarness(t, harnessOptions{
		noJar: true,
		env:   map[string]string{"HTTP_MAX_BODY_BYTES": "1024"},
	})

	body := `{"email":"big@example.com","password":"` + strings.Repeat("a", 4096) + `"}`
	resp := h.doRaw(http.MethodPost, "/v1/auth/login", body)

	require.Equal(t, http.StatusRequestEntityTooLarge, resp.Status)
	require.Equal(t, httpx.CodePayloadTooLarge, resp.envelope(t).Error.Code)
}

func TestStateChangingCookieRequestWithoutCSRFTokenIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	require.NotEmpty(t, h.registerVerifiedUser("csrf@example.com").AccessToken)

	missing := h.do(http.MethodPatch, "/v1/me", map[string]string{"name": "No CSRF"}, withoutCSRFHeader)
	require.Equal(t, http.StatusForbidden, missing.Status)
	require.Equal(t, httpx.CodeCSRFFailed, missing.envelope(t).Error.Code)

	wrong := h.do(http.MethodPatch, "/v1/me", map[string]string{"name": "Bad CSRF"}, func(r *http.Request) {
		r.Header.Set("X-CSRF-Token", "attacker-supplied-value")
	})
	require.Equal(t, http.StatusForbidden, wrong.Status)
	require.True(t, h.hasSecurityEvent(logging.EventCSRFFailed))

	valid := h.do(http.MethodPatch, "/v1/me", map[string]string{"name": "Good CSRF"})
	require.Equal(t, http.StatusOK, valid.Status)
}

func TestCSRFProtectsRefreshLogoutAndChangePassword(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	require.NotEmpty(t, h.registerVerifiedUser("csrf-routes@example.com").AccessToken)

	for _, path := range []string{"/v1/auth/refresh", "/v1/auth/logout", "/v1/auth/logout-all"} {
		resp := h.do(http.MethodPost, path, nil, withoutCSRFHeader)
		require.Equal(t, http.StatusForbidden, resp.Status, "%s must require a CSRF token", path)
	}

	resp := h.do(http.MethodPost, "/v1/me/change-password", map[string]string{
		"current_password": testPassword,
		"new_password":     testNewPassword,
	}, withoutCSRFHeader)
	require.Equal(t, http.StatusForbidden, resp.Status)
}

func TestRateLimitTripsAtConfiguredThresholdWithRetryAfter(t *testing.T) {
	rules := ratelimit.DefaultRules()
	h := newHarness(t, harnessOptions{noJar: true, rules: &rules})

	var last apiResponse
	for i := 0; i < rules.LoginIP.Limit; i++ {
		last = h.login("rate@example.com", "some-long-enough-password")
		require.Equal(t, http.StatusUnauthorized, last.Status, "attempt %d should reach the handler", i+1)
		require.Equal(t, "5", last.Headers.Get(ratelimit.HeaderLimit))
	}

	blocked := h.login("rate@example.com", "some-long-enough-password")
	require.Equal(t, http.StatusTooManyRequests, blocked.Status)
	require.Equal(t, httpx.CodeRateLimited, blocked.envelope(t).Error.Code)
	require.NotEmpty(t, blocked.Headers.Get(ratelimit.HeaderRetryAfter))
	require.Equal(t, "0", blocked.Headers.Get(ratelimit.HeaderRemaining))
	require.NotEmpty(t, blocked.Headers.Get(ratelimit.HeaderReset))
	require.True(t, h.hasSecurityEvent(logging.EventRateLimitExceeded))
}

func TestForgotPasswordIsRateLimitedPerEmail(t *testing.T) {
	rules := ratelimit.DefaultRules()
	rules.ForgotIP.Limit = 1000
	h := newHarness(t, harnessOptions{noJar: true, rules: &rules})

	payload := map[string]string{"email": "flooded@example.com"}
	for i := 0; i < rules.ForgotEmail.Limit; i++ {
		require.Equal(t, http.StatusAccepted,
			h.do(http.MethodPost, "/v1/auth/forgot-password", payload).Status)
	}

	blocked := h.do(http.MethodPost, "/v1/auth/forgot-password", payload)
	require.Equal(t, http.StatusTooManyRequests, blocked.Status)
	require.NotEmpty(t, blocked.Headers.Get(ratelimit.HeaderRetryAfter))
}

func TestAccountLocksAfterRepeatedFailures(t *testing.T) {
	h := newHarness(t, harnessOptions{
		noJar: true,
		env:   map[string]string{"LOCKOUT_THRESHOLD": "3", "LOCKOUT_BASE_WINDOW": "15m"},
	})
	const email = "locked@example.com"

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Locked Out").Status)

	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusUnauthorized, h.login(email, "wrong-but-long-enough").Status)
	}
	require.True(t, h.hasSecurityEvent(logging.EventAccountLocked))

	locked := h.login(email, testPassword)
	require.Equal(t, http.StatusForbidden, locked.Status)
	require.Equal(t, httpx.CodeAccountLocked, locked.envelope(t).Error.Code)

	h.clock.Advance(16 * time.Minute)
	require.NotEmpty(t, h.loginSession(email, testPassword).AccessToken)

	for i := 0; i < 2; i++ {
		require.Equal(t, http.StatusUnauthorized, h.login(email, "wrong-but-long-enough").Status)
	}
	require.Equal(t, http.StatusOK, h.login(email, testPassword).Status,
		"a successful login must reset the failure counter")
}

func TestUnverifiedLoginIsBlockedWhenVerificationIsRequired(t *testing.T) {
	h := newHarness(t, harnessOptions{
		noJar: true,
		env:   map[string]string{"REQUIRE_VERIFIED_EMAIL": "true"},
	})
	const email = "unverified@example.com"

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Unverified").Status)

	blocked := h.login(email, testPassword)
	require.Equal(t, http.StatusForbidden, blocked.Status)
	require.Equal(t, httpx.CodeEmailNotVerified, blocked.envelope(t).Error.Code)

	require.Equal(t, http.StatusOK, h.verifyEmail(h.mailer.lastToken(t, mailer.TemplateVerifyEmail)).Status)
	require.NotEmpty(t, h.loginSession(email, testPassword).AccessToken)
}

func TestWeakPasswordsAreRejectedEverywhere(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	const email = "policy@example.com"

	weak := h.register(email, "passwordpassword", "Weak")
	require.Equal(t, http.StatusUnprocessableEntity, weak.Status)
	require.Equal(t, "password", weak.envelope(t).Error.Details[0].Field)

	require.Equal(t, http.StatusAccepted, h.register(email, testPassword, "Strong").Status)
	session := h.loginSession(email, testPassword)

	change := h.do(http.MethodPost, "/v1/me/change-password", map[string]string{
		"current_password": testPassword,
		"new_password":     "short",
	}, bearer(session.AccessToken))
	require.Equal(t, http.StatusUnprocessableEntity, change.Status)

	require.Equal(t, http.StatusAccepted,
		h.do(http.MethodPost, "/v1/auth/forgot-password", map[string]string{"email": email}).Status)
	token := h.mailer.lastToken(t, mailer.TemplatePasswordReset)

	reset := h.do(http.MethodPost, "/v1/auth/reset-password", map[string]string{
		"token": token, "new_password": "correcthorsebatterystaple",
	})
	require.Equal(t, http.StatusUnprocessableEntity, reset.Status)
}

func TestErrorEnvelopesNeverCarryInternalDetail(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	resp := h.login("nobody@example.com", "some-long-enough-password")
	envelope := resp.envelope(t)

	require.Equal(t, httpx.CodeInvalidCredentials, envelope.Error.Code)
	require.Equal(t, "Email or password is incorrect.", envelope.Error.Message)
	require.NotEmpty(t, envelope.Error.RequestID)
	require.Empty(t, envelope.Error.Details)
	require.NotContains(t, string(resp.Body), "service:")
	require.NotContains(t, string(resp.Body), "postgres:")
}

func normaliseRequestID(t *testing.T, body []byte) string {
	t.Helper()
	var envelope httpx.ErrorEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	envelope.Error.RequestID = "fixed"
	encoded, err := json.Marshal(envelope)
	require.NoError(t, err)
	return string(encoded)
}

func TestConcurrentRefreshRotatesExactlyOnce(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})
	session := h.registerVerifiedUser("race@example.com")

	const attempts = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []int
	)

	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp := h.do(http.MethodPost, "/v1/auth/refresh",
				map[string]string{"refresh_token": session.RefreshToken})
			mu.Lock()
			results = append(results, resp.Status)
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for _, status := range results {
		switch status {
		case http.StatusOK:
			succeeded++
		case http.StatusUnauthorized:
		default:
			t.Fatalf("unexpected status %d from a concurrent refresh", status)
		}
	}

	require.Equal(t, 1, succeeded, "exactly one concurrent refresh may rotate the token")
	require.True(t, h.hasSecurityEvent(logging.EventRefreshReuseDetected),
		"the losing requests must be treated as reuse")
}
