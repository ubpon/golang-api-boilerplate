package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ubpon/golang-api-boilerplate/internal/config"
	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/mailer"
	"github.com/ubpon/golang-api-boilerplate/internal/ratelimit"
	"github.com/ubpon/golang-api-boilerplate/internal/security"
	"github.com/ubpon/golang-api-boilerplate/internal/server"
)

const (
	testPassword    = "an-adequately-long-passphrase"
	testNewPassword = "another-entirely-different-phrase"
)

type captureMailer struct {
	mu       sync.Mutex
	messages []mailer.Message
}

func (m *captureMailer) Send(_ context.Context, msg mailer.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *captureMailer) Close() error { return nil }

func (m *captureMailer) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = nil
}

func (m *captureMailer) lastToken(t *testing.T, template string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := len(m.messages) - 1; i >= 0; i-- {
		if m.messages[i].Template != template {
			continue
		}
		for _, line := range strings.Fields(m.messages[i].TextBody) {
			if !strings.Contains(line, "token=") {
				continue
			}
			parsed, err := url.Parse(line)
			require.NoError(t, err)
			token := parsed.Query().Get("token")
			require.NotEmpty(t, token)
			return token
		}
	}
	t.Fatalf("no %s email captured", template)
	return ""
}

func (m *captureMailer) count(template string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, msg := range m.messages {
		if msg.Template == template {
			n++
		}
	}
	return n
}

type harness struct {
	t       *testing.T
	server  *httptest.Server
	client  *http.Client
	mailer  *captureMailer
	store   *fakeStore
	logs    *bytes.Buffer
	clock   *testClock
	baseURL string
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type harnessOptions struct {
	rules  *ratelimit.Rules
	env    map[string]string
	noJar  bool
	client *http.Client
}

func relaxedRules() *ratelimit.Rules {
	rules := ratelimit.DefaultRules()
	generous := func(r ratelimit.Rule) ratelimit.Rule {
		r.Limit = 10_000
		return r
	}
	rules.Global = generous(rules.Global)
	rules.LoginIP = generous(rules.LoginIP)
	rules.LoginEmail = generous(rules.LoginEmail)
	rules.RegisterIP = generous(rules.RegisterIP)
	rules.ForgotIP = generous(rules.ForgotIP)
	rules.ForgotEmail = generous(rules.ForgotEmail)
	rules.RefreshIP = generous(rules.RefreshIP)
	rules.ResetIP = generous(rules.ResetIP)
	rules.VerifyIP = generous(rules.VerifyIP)
	rules.ChangePasswdUID = generous(rules.ChangePasswdUID)
	return &rules
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	env := map[string]string{
		"APP_ENV":                "test",
		"JWT_SECRET":             "0123456789abcdef0123456789abcdef",
		"DATABASE_URL":           "postgres://unused:unused@localhost:5432/unused",
		"APP_BASE_URL":           "https://app.test",
		"CORS_ALLOWED_ORIGINS":   "https://app.test",
		"COOKIE_SECURE":          "false",
		"LOG_LEVEL":              "debug",
		"LOG_FORMAT":             "json",
		"MAILER_DRIVER":          "noop",
		"REQUIRE_VERIFIED_EMAIL": "false",
		"LOCKOUT_THRESHOLD":      "10",
	}
	for k, v := range opts.env {
		env[k] = v
	}
	for k, v := range env {
		t.Setenv(k, v)
	}

	cfg, err := config.Load()
	require.NoError(t, err)

	logs := &bytes.Buffer{}
	log := logging.New(&syncWriter{w: logs}, logging.Options{Level: slog.LevelDebug, Format: logging.FormatJSON})

	post := &captureMailer{}
	store := newFakeStore()
	clock := &testClock{now: time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)}

	rules := opts.rules
	if rules == nil {
		rules = relaxedRules()
	}

	cheapArgon2 := security.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	app, err := server.Build(context.Background(), server.BuildOptions{
		Config: cfg,
		Logger: log,
		Store:  store,
		Mailer: post,
		Clock:  clock.Now,
		Rules:  rules,
		Argon2: &cheapArgon2,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, app.Close()) })

	ts := httptest.NewServer(app.Server.Handler())
	t.Cleanup(ts.Close)

	client := opts.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
		if !opts.noJar {
			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			client.Jar = jar
		}
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &harness{
		t: t, server: ts, client: client, mailer: post,
		store: store, logs: logs, clock: clock, baseURL: ts.URL,
	}
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

type apiResponse struct {
	Status  int
	Body    []byte
	Headers http.Header
	Cookies []*http.Cookie
}

func (r apiResponse) decode(t *testing.T, dst any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(r.Body, dst))
}

func (r apiResponse) envelope(t *testing.T) httpx.ErrorEnvelope {
	t.Helper()
	var envelope httpx.ErrorEnvelope
	require.NoError(t, json.Unmarshal(r.Body, &envelope))
	return envelope
}

func (r apiResponse) cookie(name string) *http.Cookie {
	for _, c := range r.Cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (h *harness) do(method, path string, payload any, mutate ...func(*http.Request)) apiResponse {
	h.t.Helper()

	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		require.NoError(h.t, err)
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, h.baseURL+path, body)
	require.NoError(h.t, err)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf := h.csrfToken(); csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	for _, m := range mutate {
		m(req)
	}

	resp, err := h.client.Do(req)
	require.NoError(h.t, err)
	defer func() { require.NoError(h.t, resp.Body.Close()) }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)

	return apiResponse{Status: resp.StatusCode, Body: raw, Headers: resp.Header, Cookies: resp.Cookies()}
}

func (h *harness) doRaw(method, path, body string, mutate ...func(*http.Request)) apiResponse {
	h.t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, h.baseURL+path, strings.NewReader(body))
	require.NoError(h.t, err)
	req.Header.Set("Content-Type", "application/json")
	if csrf := h.csrfToken(); csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	for _, m := range mutate {
		m(req)
	}

	resp, err := h.client.Do(req)
	require.NoError(h.t, err)
	defer func() { require.NoError(h.t, resp.Body.Close()) }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)

	return apiResponse{Status: resp.StatusCode, Body: raw, Headers: resp.Header, Cookies: resp.Cookies()}
}

func (h *harness) csrfToken() string {
	if h.client.Jar == nil {
		return ""
	}
	parsed, err := url.Parse(h.baseURL)
	require.NoError(h.t, err)
	for _, c := range h.client.Jar.Cookies(parsed) {
		if c.Name == "csrf_token" {
			return c.Value
		}
	}
	return ""
}

type sessionPayload struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int       `json:"expires_in"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	CSRFToken        string    `json:"csrf_token"`
	User             struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified bool   `json:"email_verified"`
	} `json:"user"`
}

func (h *harness) register(email, password, name string) apiResponse {
	h.t.Helper()
	return h.do(http.MethodPost, "/v1/auth/register", map[string]string{
		"email": email, "password": password, "name": name,
	})
}

func (h *harness) verifyEmail(token string) apiResponse {
	h.t.Helper()
	return h.do(http.MethodPost, "/v1/auth/verify-email", map[string]string{"token": token})
}

func (h *harness) login(email, password string) apiResponse {
	h.t.Helper()
	return h.do(http.MethodPost, "/v1/auth/login", map[string]string{
		"email": email, "password": password,
	})
}

func (h *harness) loginSession(email, password string) sessionPayload {
	h.t.Helper()
	resp := h.login(email, password)
	require.Equal(h.t, http.StatusOK, resp.Status, "login failed: %s", resp.Body)

	var session sessionPayload
	resp.decode(h.t, &session)
	return session
}

func (h *harness) registerVerifiedUser(email string) sessionPayload {
	h.t.Helper()

	require.Equal(h.t, http.StatusAccepted, h.register(email, testPassword, "Test Person").Status)
	token := h.mailer.lastToken(h.t, mailer.TemplateVerifyEmail)
	require.Equal(h.t, http.StatusOK, h.verifyEmail(token).Status)

	return h.loginSession(email, testPassword)
}

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
	}
}

func withoutCSRFHeader(r *http.Request) {
	r.Header.Del("X-CSRF-Token")
}

func (h *harness) logLines() []map[string]any {
	h.t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (h *harness) hasSecurityEvent(name string) bool {
	for _, entry := range h.logLines() {
		if entry["event"] == name {
			return true
		}
	}
	return false
}
