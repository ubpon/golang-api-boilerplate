package security

import (
	"crypto/sha256"
	"errors"
)

const CSRFTokenBytes = 32

var ErrCSRFMismatch = errors.New("security: csrf token mismatch")

func NewCSRFToken() (string, error) {
	return RandomURLSafeString(CSRFTokenBytes)
}

func ValidateCSRF(cookieValue, headerValue string) error {
	if cookieValue == "" || headerValue == "" {
		return ErrCSRFMismatch
	}
	cookieDigest := sha256.Sum256([]byte(cookieValue))
	headerDigest := sha256.Sum256([]byte(headerValue))
	if !ConstantTimeEqual(cookieDigest[:], headerDigest[:]) {
		return ErrCSRFMismatch
	}
	return nil
}
