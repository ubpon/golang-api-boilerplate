package middleware

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/ratelimit"
	"github.com/ubpon/golang-api-boilerplate/internal/security"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func rawHeader(h http.Header, key string) string {
	return strings.Join(h[key], ",")
}

func decodeEnvelope(t *testing.T, body []byte) httpx.ErrorEnvelope {
	t.Helper()
	var envelope httpx.ErrorEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	return envelope
}

func TestRequestIDEchoesWellFormedInboundValue(t *testing.T) {
	t.Parallel()

	const inbound = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	handler := RequestID(discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		require.Equal(t, inbound, httpx.RequestID(r.Context()))
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderRequestID, inbound)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.Equal(t, inbound, w.Header().Get(HeaderRequestID))
}

func TestRequestIDReplacesMalformedInboundValue(t *testing.T) {
	t.Parallel()

	var seen string
	handler := RequestID(discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = httpx.RequestID(r.Context())
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderRequestID, "../../etc/passwd")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.NotEqual(t, "../../etc/passwd", seen)
	require.Len(t, seen, 36)
	require.Equal(t, seen, w.Header().Get(HeaderRequestID))
}

func TestRecoverReturnsGenericInternalError(t *testing.T) {
	t.Parallel()

	handler := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret internal detail")
	}), RequestID(discardLogger()), Recover())

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusInternalServerError, w.Code)
	envelope := decodeEnvelope(t, w.Body.Bytes())
	require.Equal(t, httpx.CodeInternal, envelope.Error.Code)
	require.NotContains(t, w.Body.String(), "secret internal detail")
	require.NotEmpty(t, envelope.Error.RequestID)
	require.Empty(t, envelope.Error.Details)
}

func TestSecurityHeadersAreAlwaysSet(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(SecurityHeadersOptions{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	require.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'none'")
	require.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	require.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Opener-Policy"))
	require.Equal(t, "same-origin", w.Header().Get("Cross-Origin-Resource-Policy"))
	require.Contains(t, w.Header().Get("Permissions-Policy"), "geolocation=()")
	require.Empty(t, w.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeadersEmitHSTSWhenTLSIsAssumed(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(SecurityHeadersOptions{
		EnableHSTS: true, AssumeTLS: true, HSTSSubdomain: true,
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, "max-age=31536000; includeSubDomains", w.Header().Get("Strict-Transport-Security"))
}

func corsHandler() http.Handler {
	return Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}),
		RequestID(discardLogger()),
		CORS(CORSOptions{
			AllowedOrigins:   []string{"https://app.example.com"},
			AllowedMethods:   []string{"GET", "POST"},
			AllowedHeaders:   []string{"Content-Type", "X-CSRF-Token"},
			ExposedHeaders:   []string{"X-Request-ID"},
			AllowCredentials: true,
			MaxAge:           10 * time.Minute,
		}),
	)
}

func TestCORSAllowsConfiguredOrigin(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	corsHandler().ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	require.Contains(t, w.Header().Values("Vary"), "Origin")
}

func TestCORSRejectsUnknownOriginInsteadOfEchoing(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	corsHandler().ServeHTTP(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, httpx.CodeOriginNotAllowed, decodeEnvelope(t, w.Body.Bytes()).Error.Code)
}

func TestCORSPreflightIsCached(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	corsHandler().ServeHTTP(w, r)

	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, "GET, POST", w.Header().Get("Access-Control-Allow-Methods"))
	require.Equal(t, "Content-Type, X-CSRF-Token", w.Header().Get("Access-Control-Allow-Headers"))
	require.Equal(t, "600", w.Header().Get("Access-Control-Max-Age"))
}

func TestCORSNeverPairsWildcardWithCredentials(t *testing.T) {
	t.Parallel()

	handler := CORS(CORSOptions{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://anywhere.example.com")
	w := httptest.NewRecorder()
	Chain(handler, RequestID(discardLogger())).ServeHTTP(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestMaxBytesRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Value string `json:"value"`
		}
		if err := httpx.DecodeJSON(w, r, &payload); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), RequestID(discardLogger()), MaxBytes(64))

	body := `{"value":"` + strings.Repeat("a", 512) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	require.Equal(t, httpx.CodePayloadTooLarge, decodeEnvelope(t, w.Body.Bytes()).Error.Code)
}

func TestCSRFAllowsBearerAuthenticatedRequests(t *testing.T) {
	t.Parallel()

	handler := csrfHandler()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer some-token")
	r.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie-token"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestCSRFAllowsUnauthenticatedRequests(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	csrfHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestCSRFAllowsSafeMethods(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie-token"})
	w := httptest.NewRecorder()
	csrfHandler().ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestCSRFRejectsCookieRequestWithoutHeader(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie-token"})
	r.AddCookie(&http.Cookie{Name: "csrf_token", Value: "expected"})
	w := httptest.NewRecorder()
	csrfHandler().ServeHTTP(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, httpx.CodeCSRFFailed, decodeEnvelope(t, w.Body.Bytes()).Error.Code)
}

func TestCSRFRejectsMismatchedHeader(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie-token"})
	r.AddCookie(&http.Cookie{Name: "csrf_token", Value: "expected"})
	r.Header.Set(HeaderCSRFToken, "attacker-guess")
	w := httptest.NewRecorder()
	csrfHandler().ServeHTTP(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFAcceptsMatchingDoubleSubmit(t *testing.T) {
	t.Parallel()

	token, err := security.NewCSRFToken()
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie-token"})
	r.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	r.Header.Set(HeaderCSRFToken, token)
	w := httptest.NewRecorder()
	csrfHandler().ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
}

func csrfHandler() http.Handler {
	return Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}),
		RequestID(discardLogger()),
		CSRF(CSRFOptions{
			CookieName:      "csrf_token",
			AuthCookieNames: []string{"access_token", "refresh_token"},
		}),
	)
}

func TestRateLimitMiddlewareEmitsHeadersAndRetryAfter(t *testing.T) {
	t.Parallel()

	limiter := ratelimit.NewMemoryLimiter(ratelimit.MemoryOptions{})
	t.Cleanup(func() { require.NoError(t, limiter.Close()) })

	rule := ratelimit.Rule{Name: "login.ip", Limit: 2, Window: time.Minute}
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}),
		RequestID(discardLogger()),
		ClientIP(NewClientIPResolver(nil)),
		RateLimit(limiter, rule, ClientIPKey),
	)

	newRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
		r.RemoteAddr = "192.0.2.10:5555"
		return r
	}

	for i := 0; i < rule.Limit; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newRequest())
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "2", rawHeader(w.Header(), ratelimit.HeaderLimit))
		require.Equal(t, strconv.Itoa(rule.Limit-i-1), rawHeader(w.Header(), ratelimit.HeaderRemaining))
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest())

	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.Equal(t, httpx.CodeRateLimited, decodeEnvelope(t, w.Body.Bytes()).Error.Code)
	require.NotEmpty(t, w.Header().Get(ratelimit.HeaderRetryAfter))
	require.Equal(t, "0", rawHeader(w.Header(), ratelimit.HeaderRemaining))
	require.NotEmpty(t, rawHeader(w.Header(), ratelimit.HeaderReset))
}

func TestRateLimitSkipPredicate(t *testing.T) {
	t.Parallel()

	limiter := ratelimit.NewMemoryLimiter(ratelimit.MemoryOptions{})
	t.Cleanup(func() { require.NoError(t, limiter.Close()) })

	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}),
		RequestID(discardLogger()),
		ClientIP(NewClientIPResolver(nil)),
		RateLimitWith(RateLimitOptions{
			Limiter: limiter,
			Rule:    ratelimit.Rule{Name: "global.ip", Limit: 1, Window: time.Minute},
			Key:     ClientIPKey,
			Skip:    func(r *http.Request) bool { return r.URL.Path == "/healthz" },
		}),
	)

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		require.Equal(t, http.StatusOK, w.Code)
	}
}

func TestJSONRoutingErrorsRewritesMuxResponses(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/thing", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Chain(mux, RequestID(discardLogger()), JSONRoutingErrors())

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/nope", nil))
	require.Equal(t, http.StatusNotFound, missing.Code)
	require.Equal(t, httpx.CodeNotFound, decodeEnvelope(t, missing.Body.Bytes()).Error.Code)

	wrongMethod := httptest.NewRecorder()
	handler.ServeHTTP(wrongMethod, httptest.NewRequest(http.MethodDelete, "/v1/thing", nil))
	require.Equal(t, http.StatusMethodNotAllowed, wrongMethod.Code)
	require.Equal(t, httpx.CodeMethodNotAllowed, decodeEnvelope(t, wrongMethod.Body.Bytes()).Error.Code)

	ok := httptest.NewRecorder()
	handler.ServeHTTP(ok, httptest.NewRequest(http.MethodPost, "/v1/thing", nil))
	require.Equal(t, http.StatusOK, ok.Code)
}
