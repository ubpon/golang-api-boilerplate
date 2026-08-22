package security

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func newTestIssuer(t *testing.T, now func() time.Time) *TokenIssuer {
	t.Helper()
	issuer, err := NewTokenIssuer(TokenIssuerOptions{
		Secret:   testSecret,
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      15 * time.Minute,
		Clock:    now,
	})
	require.NoError(t, err)
	return issuer
}

func TestNewTokenIssuerValidatesOptions(t *testing.T) {
	t.Parallel()

	_, err := NewTokenIssuer(TokenIssuerOptions{Secret: []byte("short"), Issuer: "i", Audience: "a", TTL: time.Minute})
	require.Error(t, err)

	_, err = NewTokenIssuer(TokenIssuerOptions{Secret: testSecret, Audience: "a", TTL: time.Minute})
	require.Error(t, err)

	_, err = NewTokenIssuer(TokenIssuerOptions{Secret: testSecret, Issuer: "i", Audience: "a"})
	require.Error(t, err)
}

func TestIssueAndVerifyPopulatesEveryClaim(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	issuer := newTestIssuer(t, func() time.Time { return base })

	issued, err := issuer.Issue("user-123")
	require.NoError(t, err)
	require.NotEmpty(t, issued.JTI)
	require.Equal(t, base.Add(15*time.Minute), issued.ExpiresAt)

	claims, err := issuer.Verify(issued.Token)
	require.NoError(t, err)
	require.Equal(t, "user-123", claims.Subject)
	require.Equal(t, "test-issuer", claims.Issuer)
	require.Equal(t, jwt.ClaimStrings{"test-audience"}, claims.Audience)
	require.Equal(t, TokenTypeAccess, claims.Type)
	require.Equal(t, issued.JTI, claims.ID)
	require.Equal(t, base, claims.IssuedAt.UTC())
	require.Equal(t, base, claims.NotBefore.UTC())
	require.Equal(t, base.Add(15*time.Minute), claims.ExpiresAt.UTC())
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	issuer := newTestIssuer(t, func() time.Time { return now })

	issued, err := issuer.Issue("user-123")
	require.NoError(t, err)

	now = now.Add(16 * time.Minute)
	_, err = issuer.Verify(issued.Token)
	require.ErrorIs(t, err, ErrTokenExpired)
}

func TestVerifyRejectsTokenUsedBeforeNotBefore(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	issuer := newTestIssuer(t, func() time.Time { return now })

	issued, err := issuer.Issue("user-123")
	require.NoError(t, err)

	now = now.Add(-time.Hour)
	_, err = issuer.Verify(issued.Token)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t, time.Now)
	issued, err := issuer.Issue("user-123")
	require.NoError(t, err)

	parts := strings.Split(issued.Token, ".")
	require.Len(t, parts, 3)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.NotEmpty(t, signature)
	signature[0] ^= 0xff
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)

	_, err = issuer.Verify(tampered)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t, time.Now)
	claims := AccessClaims{
		Type: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ID:        "jti",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = issuer.Verify(unsigned)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyRejectsWrongAlgorithmFamily(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t, time.Now)
	claims := jwt.RegisteredClaims{
		Subject:   "user-123",
		Issuer:    "test-issuer",
		Audience:  jwt.ClaimStrings{"test-audience"},
		ID:        "jti",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	hs512, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(testSecret)
	require.NoError(t, err)

	_, err = issuer.Verify(hs512)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyRejectsWrongIssuerAudienceAndType(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t, time.Now)

	sign := func(c AccessClaims) string {
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(testSecret)
		require.NoError(t, err)
		return token
	}
	base := func() AccessClaims {
		return AccessClaims{
			Type: TokenTypeAccess,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "user-123",
				Issuer:    "test-issuer",
				Audience:  jwt.ClaimStrings{"test-audience"},
				ID:        "jti",
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
	}

	wrongIssuer := base()
	wrongIssuer.Issuer = "someone-else"
	_, err := issuer.Verify(sign(wrongIssuer))
	require.ErrorIs(t, err, ErrTokenInvalid)

	wrongAudience := base()
	wrongAudience.Audience = jwt.ClaimStrings{"another-audience"}
	_, err = issuer.Verify(sign(wrongAudience))
	require.ErrorIs(t, err, ErrTokenInvalid)

	wrongType := base()
	wrongType.Type = "refresh"
	_, err = issuer.Verify(sign(wrongType))
	require.ErrorIs(t, err, ErrTokenWrongType)

	missingJTI := base()
	missingJTI.ID = ""
	_, err = issuer.Verify(sign(missingJTI))
	require.ErrorIs(t, err, ErrTokenInvalid)

	missingNotBefore := base()
	missingNotBefore.NotBefore = nil
	_, err = issuer.Verify(sign(missingNotBefore))
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyRejectsForeignSecret(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t, time.Now)
	other, err := NewTokenIssuer(TokenIssuerOptions{
		Secret:   []byte("ffffffffffffffffffffffffffffffff"),
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      time.Minute,
	})
	require.NoError(t, err)

	issued, err := other.Issue("user-123")
	require.NoError(t, err)

	_, err = issuer.Verify(issued.Token)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	t.Parallel()

	issuer := newTestIssuer(t, time.Now)
	issued, err := issuer.Issue("user-123")
	require.NoError(t, err)

	parts := strings.Split(issued.Token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	forged := strings.Replace(string(payload), `"sub":"user-123"`, `"sub":"user-999"`, 1)
	require.NotEqual(t, string(payload), forged)

	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + parts[2]
	_, err = issuer.Verify(tampered)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestClockSkewToleranceIsConfigurable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	strict := newTestIssuer(t, func() time.Time { return now })

	tolerant, err := NewTokenIssuer(TokenIssuerOptions{
		Secret:    testSecret,
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		TTL:       15 * time.Minute,
		ClockSkew: 60 * time.Second,
		Clock:     func() time.Time { return now },
	})
	require.NoError(t, err)

	issued, err := strict.Issue("user-123")
	require.NoError(t, err)

	now = now.Add(15*time.Minute + 30*time.Second)
	_, err = strict.Verify(issued.Token)
	require.ErrorIs(t, err, ErrTokenExpired)

	claims, err := tolerant.Verify(issued.Token)
	require.NoError(t, err)
	require.Equal(t, "user-123", claims.Subject)

	now = now.Add(time.Minute)
	_, err = tolerant.Verify(issued.Token)
	require.ErrorIs(t, err, ErrTokenExpired)
}

func TestNegativeClockSkewIsRejected(t *testing.T) {
	t.Parallel()

	_, err := NewTokenIssuer(TokenIssuerOptions{
		Secret: testSecret, Issuer: "i", Audience: "a", TTL: time.Minute, ClockSkew: -time.Second,
	})
	require.Error(t, err)
}
