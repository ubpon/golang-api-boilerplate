package security

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewOpaqueTokenHashesPlaintext(t *testing.T) {
	t.Parallel()

	token, err := NewOpaqueToken()
	require.NoError(t, err)
	require.Len(t, token.Hash, sha256.Size)

	raw, err := base64.RawURLEncoding.Strict().DecodeString(token.Plaintext)
	require.NoError(t, err)
	require.Len(t, raw, OpaqueTokenBytes)

	expected := sha256.Sum256(raw)
	require.Equal(t, expected[:], token.Hash)
}

func TestOpaqueTokensAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		token, err := NewOpaqueToken()
		require.NoError(t, err)
		_, duplicate := seen[token.Plaintext]
		require.False(t, duplicate)
		seen[token.Plaintext] = struct{}{}
	}
}

func TestHashOpaqueTokenMatchesIssuedHash(t *testing.T) {
	t.Parallel()

	token, err := NewOpaqueToken()
	require.NoError(t, err)

	hash, err := HashOpaqueToken(token.Plaintext)
	require.NoError(t, err)
	require.True(t, ConstantTimeEqual(token.Hash, hash))
}

func TestHashOpaqueTokenRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"", "!!!not-base64!!!", base64.RawURLEncoding.EncodeToString([]byte("short"))} {
		_, err := HashOpaqueToken(input)
		require.ErrorIs(t, err, ErrMalformedToken)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()

	require.True(t, ConstantTimeEqual([]byte("abc"), []byte("abc")))
	require.False(t, ConstantTimeEqual([]byte("abc"), []byte("abd")))
	require.False(t, ConstantTimeEqual([]byte("abc"), []byte("abcd")))
	require.True(t, ConstantTimeEqualString("token", "token"))
	require.False(t, ConstantTimeEqualString("token", "TOKEN"))
}
