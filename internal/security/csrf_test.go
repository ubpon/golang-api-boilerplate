package security

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCSRFTokenIsRandomAndLongEnough(t *testing.T) {
	t.Parallel()

	first, err := NewCSRFToken()
	require.NoError(t, err)
	second, err := NewCSRFToken()
	require.NoError(t, err)
	require.NotEqual(t, first, second)

	raw, err := base64.RawURLEncoding.Strict().DecodeString(first)
	require.NoError(t, err)
	require.Len(t, raw, CSRFTokenBytes)
}

func TestValidateCSRF(t *testing.T) {
	t.Parallel()

	token, err := NewCSRFToken()
	require.NoError(t, err)

	require.NoError(t, ValidateCSRF(token, token))
	require.ErrorIs(t, ValidateCSRF(token, token+"x"), ErrCSRFMismatch)
	require.ErrorIs(t, ValidateCSRF(token, ""), ErrCSRFMismatch)
	require.ErrorIs(t, ValidateCSRF("", token), ErrCSRFMismatch)
	require.ErrorIs(t, ValidateCSRF("", ""), ErrCSRFMismatch)

	other, err := NewCSRFToken()
	require.NoError(t, err)
	require.ErrorIs(t, ValidateCSRF(token, other), ErrCSRFMismatch)
}
