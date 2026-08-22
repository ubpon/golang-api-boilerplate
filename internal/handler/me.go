package handler

import (
	"net/http"
	"strings"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/service"
	"github.com/ubpon/golang-api-boilerplate/internal/validation"
)

type Me struct {
	deps AuthDeps
	auth *Auth
}

func NewMe(deps AuthDeps) *Me {
	return &Me{deps: deps, auth: NewAuth(deps)}
}

func (h *Me) Show(w http.ResponseWriter, r *http.Request) {
	principal, ok := httpx.CurrentPrincipal(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	user, err := h.deps.Service.Profile(r.Context(), principal.UserID)
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	httpx.WriteJSON(w, r, http.StatusOK, newUserResponse(user))
}

func (h *Me) Update(w http.ResponseWriter, r *http.Request) {
	principal, ok := httpx.CurrentPrincipal(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	var req updateProfileRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if req.Name == nil {
		httpx.WriteError(w, r, httpx.ErrValidation.WithDetails(httpx.FieldError{
			Field: "name",
			Issue: "is required",
		}))
		return
	}

	v := validation.New()
	name := v.MaxLen("name", strings.TrimSpace(*req.Name), 200)
	if !v.OK() {
		httpx.WriteError(w, r, validationError(v))
		return
	}

	user, err := h.deps.Service.UpdateProfile(r.Context(), principal.UserID, name)
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	httpx.WriteJSON(w, r, http.StatusOK, newUserResponse(user))
}

func (h *Me) ChangePassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := httpx.CurrentPrincipal(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	var req changePasswordRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	v := validation.New()
	v.Required("current_password", req.CurrentPassword)
	v.Password("new_password", req.NewPassword, "", h.deps.Policy)
	if !v.OK() {
		httpx.WriteError(w, r, validationError(v))
		return
	}

	if blocked := h.auth.enforce(w, r, h.deps.Rules.ChangePasswdUID, principal.UserID); blocked {
		return
	}

	session, err := h.deps.Service.ChangePassword(r.Context(), service.ChangePasswordInput{
		UserID:          principal.UserID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
		Metadata:        sessionMetadata(r),
	})
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	h.deps.Cookies.Write(w, session, h.auth.now())
	httpx.WriteJSON(w, r, http.StatusOK, newSessionResponse(session))
}
