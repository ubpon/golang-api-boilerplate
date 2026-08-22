package handler

import (
	"errors"
	"net/http"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/service"
	"github.com/ubpon/golang-api-boilerplate/internal/validation"
)

func mapServiceError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, service.ErrInvalidCredentials):
		return httpx.ErrBadCredentials.WithCause(err)
	case errors.Is(err, service.ErrAccountLocked):
		return httpx.ErrAccountLocked.WithCause(err)
	case errors.Is(err, service.ErrEmailNotVerified):
		return httpx.ErrNotVerified.WithCause(err)
	case errors.Is(err, service.ErrInvalidToken):
		return httpx.ErrInvalidToken.WithCause(err)
	case errors.Is(err, service.ErrWeakPassword):
		return httpx.ErrWeakPassword.WithCause(err)
	case errors.Is(err, service.ErrPasswordUnchanged):
		return httpx.ErrSamePassword.WithCause(err)
	case errors.Is(err, service.ErrUserNotFound):
		return httpx.ErrUnauthorized.WithCause(err)
	default:
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) {
			return httpx.ErrTooLarge.WithCause(err)
		}
		return httpx.ErrInternal.WithCause(err)
	}
}

func validationError(v *validation.Validator) error {
	issues := v.Issues()
	details := make([]httpx.FieldError, 0, len(issues))
	for _, issue := range issues {
		details = append(details, httpx.FieldError{Field: issue.Field, Issue: issue.Message})
	}
	return httpx.ErrValidation.WithDetails(details...)
}
