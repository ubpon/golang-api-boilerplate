package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/ubpon/golang-api-boilerplate/internal/logging"
)

const contentTypeJSON = "application/json; charset=utf-8"

func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/json" {
			return ErrUnsupportedType
		}
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, currentBodyLimit(r)))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrMalformedJSON.WithDetails(FieldError{
			Field: "body",
			Issue: "must contain exactly one JSON object",
		})
	}
	return nil
}

func decodeError(err error) error {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var maxBytesErr *http.MaxBytesError

	switch {
	case errors.As(err, &maxBytesErr):
		return ErrTooLarge.WithCause(err)
	case errors.As(err, &syntaxErr):
		return ErrMalformedJSON.WithDetails(FieldError{
			Field: "body",
			Issue: fmt.Sprintf("malformed JSON at byte offset %d", syntaxErr.Offset),
		})
	case errors.As(err, &typeErr):
		field := typeErr.Field
		if field == "" {
			field = "body"
		}
		return ErrValidation.WithDetails(FieldError{
			Field: field,
			Issue: fmt.Sprintf("must be of type %s", typeErr.Type.String()),
		})
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return ErrMalformedJSON.WithDetails(FieldError{Field: "body", Issue: "must not be empty"})
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		name := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return ErrValidation.WithDetails(FieldError{Field: name, Issue: "is not a recognised field"})
	default:
		return ErrMalformedJSON.WithCause(err)
	}
}

func WriteJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		logging.FromContext(r.Context()).Error("failed to encode response body", slog.Any("error", err))
		writeRaw(w, http.StatusInternalServerError, mustEnvelope(ErrInternal, RequestID(r.Context())))
		return
	}
	writeRaw(w, status, body)
}

func WriteNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr := AsAPIError(err)
	ctx := r.Context()
	log := logging.FromContext(ctx)

	if apiErr.Status >= http.StatusInternalServerError {
		log.Error("request failed",
			slog.String("code", string(apiErr.Code)),
			slog.Any("error", err),
		)
	} else {
		log.Debug("request rejected",
			slog.String("code", string(apiErr.Code)),
			slog.Int("status", apiErr.Status),
		)
	}

	writeRaw(w, apiErr.Status, mustEnvelope(apiErr, RequestID(ctx)))
}

func AsAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return ErrTooLarge
	}
	return ErrInternal
}

func mustEnvelope(apiErr *APIError, requestID string) []byte {
	envelope := ErrorEnvelope{Error: ErrorBody{
		Code:      apiErr.Code,
		Message:   apiErr.Message,
		RequestID: requestID,
	}}
	if apiErr.Status < http.StatusInternalServerError {
		envelope.Error.Details = apiErr.Details
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		// Marshalling a struct of strings cannot fail; fall back to a fixed body regardless.
		return []byte(`{"error":{"code":"internal_error","message":"Something went wrong. Please try again."}}`)
	}
	return body
}

func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// The client may have disconnected; there is nothing useful left to do with a write error here.
	_, _ = w.Write(body)
}
