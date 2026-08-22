package handler

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/ratelimit"
	"github.com/ubpon/golang-api-boilerplate/internal/service"
	"github.com/ubpon/golang-api-boilerplate/internal/validation"
)

type AuthDeps struct {
	Service *service.AuthService
	Cookies *CookieWriter
	Limiter ratelimit.Limiter
	Rules   ratelimit.Rules
	Policy  validation.PasswordPolicy
	Clock   func() time.Time
}

type Auth struct {
	deps AuthDeps
	now  func() time.Time
}

func NewAuth(deps AuthDeps) *Auth {
	clock := deps.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Auth{deps: deps, now: clock}
}

var acceptedRegistration = acceptedResponse{
	Status:  "accepted",
	Message: "If the address can receive mail, a verification link is on its way.",
}

var acceptedPasswordReset = acceptedResponse{
	Status:  "accepted",
	Message: "If an account exists for that address, a password reset link is on its way.",
}

func (h *Auth) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	v := validation.New()
	email := v.Email("email", req.Email)
	name := v.MaxLen("name", strings.TrimSpace(req.Name), 200)
	v.Password("password", req.Password, email, h.deps.Policy)
	if !v.OK() {
		httpx.WriteError(w, r, validationError(v))
		return
	}

	if err := h.deps.Service.Register(r.Context(), service.RegisterInput{
		Email:    email,
		Password: req.Password,
		Name:     name,
	}); err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	httpx.WriteJSON(w, r, http.StatusAccepted, acceptedRegistration)
}

func (h *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	v := validation.New()
	email := v.Email("email", req.Email)
	v.Required("password", req.Password)
	if !v.OK() {
		httpx.WriteError(w, r, validationError(v))
		return
	}

	if blocked := h.enforce(w, r, h.deps.Rules.LoginEmail, domain.NormalizeEmail(email)); blocked {
		return
	}

	session, err := h.deps.Service.Login(r.Context(), service.LoginInput{
		Email:    email,
		Password: req.Password,
		Metadata: sessionMetadata(r),
	})
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	h.deps.Cookies.Write(w, session, h.now())
	httpx.WriteJSON(w, r, http.StatusOK, newSessionResponse(session))
}

func (h *Auth) Refresh(w http.ResponseWriter, r *http.Request) {
	presented := h.deps.Cookies.refreshTokenFrom(r)
	if presented == "" {
		var req refreshRequest
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		presented = strings.TrimSpace(req.RefreshToken)
	}
	if presented == "" {
		httpx.WriteError(w, r, httpx.ErrInvalidToken)
		return
	}

	session, err := h.deps.Service.Refresh(r.Context(), presented, sessionMetadata(r))
	if err != nil {
		h.deps.Cookies.Clear(w)
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	h.deps.Cookies.Write(w, session, h.now())
	httpx.WriteJSON(w, r, http.StatusOK, newSessionResponse(session))
}

func (h *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	presented := h.deps.Cookies.refreshTokenFrom(r)
	if presented == "" && r.ContentLength > 0 {
		var req logoutRequest
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		presented = strings.TrimSpace(req.RefreshToken)
	}

	if presented != "" {
		if err := h.deps.Service.Logout(r.Context(), presented); err != nil {
			httpx.WriteError(w, r, mapServiceError(err))
			return
		}
	}

	h.deps.Cookies.Clear(w)
	httpx.WriteNoContent(w)
}

func (h *Auth) LogoutAll(w http.ResponseWriter, r *http.Request) {
	principal, ok := httpx.CurrentPrincipal(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}
	if err := h.deps.Service.LogoutAll(r.Context(), principal.UserID); err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	h.deps.Cookies.Clear(w)
	httpx.WriteNoContent(w)
}

func (h *Auth) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	v := validation.New()
	email := v.Email("email", req.Email)
	if !v.OK() {
		httpx.WriteError(w, r, validationError(v))
		return
	}

	if blocked := h.enforce(w, r, h.deps.Rules.ForgotEmail, domain.NormalizeEmail(email)); blocked {
		return
	}

	if err := h.deps.Service.ForgotPassword(r.Context(), email); err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	httpx.WriteJSON(w, r, http.StatusAccepted, acceptedPasswordReset)
}

func (h *Auth) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	v := validation.New()
	token := v.Token("token", req.Token)
	v.Password("new_password", req.NewPassword, "", h.deps.Policy)
	if !v.OK() {
		httpx.WriteError(w, r, validationError(v))
		return
	}

	if err := h.deps.Service.ResetPassword(r.Context(), token, req.NewPassword); err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	h.deps.Cookies.Clear(w)
	httpx.WriteJSON(w, r, http.StatusOK, acceptedResponse{
		Status:  "ok",
		Message: "Your password has been changed and all sessions were signed out.",
	})
}

func (h *Auth) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	v := validation.New()
	token := v.Token("token", req.Token)
	if !v.OK() {
		httpx.WriteError(w, r, validationError(v))
		return
	}

	if err := h.deps.Service.VerifyEmail(r.Context(), token); err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	httpx.WriteJSON(w, r, http.StatusOK, acceptedResponse{
		Status:  "ok",
		Message: "Your email address has been verified.",
	})
}

func (h *Auth) enforce(w http.ResponseWriter, r *http.Request, rule ratelimit.Rule, key string) bool {
	if h.deps.Limiter == nil || !rule.Valid() || key == "" {
		return false
	}

	ctx := r.Context()
	decision, err := h.deps.Limiter.Allow(ctx, key, rule)
	if err != nil {
		logging.FromContext(ctx).Error("rate limiter unavailable, allowing request",
			slog.String("rule", rule.Name), slog.Any("error", err))
		return false
	}

	ratelimit.WriteHeaders(w, decision)
	if decision.Allowed {
		return false
	}

	logging.Security(ctx, logging.EventRateLimitExceeded,
		"rule", rule.Name,
		"route", httpx.Route(ctx),
		"client_ip", httpx.ClientIP(ctx),
	)
	httpx.WriteError(w, r, httpx.ErrRateLimited)
	return true
}

func sessionMetadata(r *http.Request) service.SessionMetadata {
	return service.SessionMetadata{
		UserAgent: r.UserAgent(),
		IP:        httpx.ClientIP(r.Context()),
	}
}
