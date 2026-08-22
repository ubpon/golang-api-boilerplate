package httpx

import "net/http"

type ErrorCode string

const (
	CodeValidationFailed    ErrorCode = "validation_failed"
	CodeMalformedJSON       ErrorCode = "malformed_json"
	CodeUnsupportedMedia    ErrorCode = "unsupported_media_type"
	CodePayloadTooLarge     ErrorCode = "payload_too_large"
	CodeInvalidCredentials  ErrorCode = "invalid_credentials" // #nosec G101 -- error code, not a credential
	CodeUnauthorized        ErrorCode = "unauthorized"
	CodeForbidden           ErrorCode = "forbidden"
	CodeCSRFFailed          ErrorCode = "csrf_failed"
	CodeInvalidToken        ErrorCode = "invalid_token"
	CodeAccountLocked       ErrorCode = "account_locked"
	CodeEmailNotVerified    ErrorCode = "email_not_verified"
	CodeNotFound            ErrorCode = "not_found"
	CodeMethodNotAllowed    ErrorCode = "method_not_allowed"
	CodeConflict            ErrorCode = "conflict"
	CodeRateLimited         ErrorCode = "rate_limited"
	CodeOriginNotAllowed    ErrorCode = "origin_not_allowed"
	CodeServiceUnavailable  ErrorCode = "service_unavailable"
	CodeInternal            ErrorCode = "internal_error"
	CodeWeakPassword        ErrorCode = "weak_password"
	CodePasswordUnchanged   ErrorCode = "password_unchanged"
	CodeRequestTimeout      ErrorCode = "request_timeout"
	CodeUnsupportedProtocol ErrorCode = "unsupported_protocol"
)

type FieldError struct {
	Field string `json:"field"`
	Issue string `json:"issue"`
}

type ErrorBody struct {
	Code      ErrorCode    `json:"code"`
	Message   string       `json:"message"`
	RequestID string       `json:"request_id,omitempty"`
	Details   []FieldError `json:"details,omitempty"`
}

type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

type APIError struct {
	Status  int
	Code    ErrorCode
	Message string
	Details []FieldError
	cause   error
}

func (e *APIError) Error() string {
	if e.cause != nil {
		return string(e.Code) + ": " + e.cause.Error()
	}
	return string(e.Code) + ": " + e.Message
}

func (e *APIError) Unwrap() error { return e.cause }

func (e *APIError) WithCause(err error) *APIError {
	clone := *e
	clone.cause = err
	return &clone
}

func (e *APIError) WithDetails(details ...FieldError) *APIError {
	clone := *e
	clone.Details = details
	return &clone
}

func NewError(status int, code ErrorCode, message string) *APIError {
	return &APIError{Status: status, Code: code, Message: message}
}

var (
	ErrValidation      = NewError(http.StatusUnprocessableEntity, CodeValidationFailed, "The request payload failed validation.")
	ErrMalformedJSON   = NewError(http.StatusBadRequest, CodeMalformedJSON, "The request body is not valid JSON.")
	ErrUnsupportedType = NewError(http.StatusUnsupportedMediaType, CodeUnsupportedMedia, "Content-Type must be application/json.")
	ErrTooLarge        = NewError(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "The request body is too large.")
	ErrBadCredentials  = NewError(http.StatusUnauthorized, CodeInvalidCredentials, "Email or password is incorrect.")
	ErrUnauthorized    = NewError(http.StatusUnauthorized, CodeUnauthorized, "Authentication is required.")
	ErrForbidden       = NewError(http.StatusForbidden, CodeForbidden, "You are not allowed to perform this action.")
	ErrCSRF            = NewError(http.StatusForbidden, CodeCSRFFailed, "CSRF token missing or invalid.")
	ErrInvalidToken    = NewError(http.StatusUnauthorized, CodeInvalidToken, "The token is invalid or has expired.")
	ErrAccountLocked   = NewError(http.StatusForbidden, CodeAccountLocked, "This account is temporarily locked. Try again later.")
	ErrNotVerified     = NewError(http.StatusForbidden, CodeEmailNotVerified, "This email address has not been verified.")
	ErrNotFound        = NewError(http.StatusNotFound, CodeNotFound, "The requested resource was not found.")
	ErrMethod          = NewError(http.StatusMethodNotAllowed, CodeMethodNotAllowed, "That method is not allowed on this resource.")
	ErrConflict        = NewError(http.StatusConflict, CodeConflict, "The resource is in a conflicting state.")
	ErrRateLimited     = NewError(http.StatusTooManyRequests, CodeRateLimited, "Too many requests. Slow down and try again later.")
	ErrOrigin          = NewError(http.StatusForbidden, CodeOriginNotAllowed, "This origin is not allowed.")
	ErrUnavailable     = NewError(http.StatusServiceUnavailable, CodeServiceUnavailable, "A required dependency is unavailable.")
	ErrInternal        = NewError(http.StatusInternalServerError, CodeInternal, "Something went wrong. Please try again.")
	ErrWeakPassword    = NewError(http.StatusUnprocessableEntity, CodeWeakPassword, "The password does not meet the password policy.")
	ErrSamePassword    = NewError(http.StatusUnprocessableEntity, CodePasswordUnchanged, "The new password must differ from the current password.")
	ErrTimeout         = NewError(http.StatusGatewayTimeout, CodeRequestTimeout, "The request timed out.")
)
