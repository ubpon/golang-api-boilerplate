package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

const OpaqueTokenBytes = 32

var ErrMalformedToken = errors.New("security: malformed opaque token")

type OpaqueToken struct {
	Plaintext string
	Hash      []byte
}

func NewOpaqueToken() (OpaqueToken, error) {
	raw := make([]byte, OpaqueTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return OpaqueToken{}, fmt.Errorf("security: read random bytes: %w", err)
	}
	sum := sha256.Sum256(raw)
	return OpaqueToken{
		Plaintext: base64.RawURLEncoding.EncodeToString(raw),
		Hash:      sum[:],
	}, nil
}

func HashOpaqueToken(plaintext string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(plaintext)
	if err != nil {
		return nil, ErrMalformedToken
	}
	if len(raw) != OpaqueTokenBytes {
		return nil, ErrMalformedToken
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func ConstantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func RandomURLSafeString(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("security: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
