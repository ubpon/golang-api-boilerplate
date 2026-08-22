package security

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const TokenTypeAccess = "access"

var (
	ErrTokenInvalid   = errors.New("security: access token is invalid")
	ErrTokenExpired   = errors.New("security: access token has expired")
	ErrTokenWrongType = errors.New("security: token is not an access token")
)

type AccessClaims struct {
	Type string `json:"typ"`
	jwt.RegisteredClaims
}

type Clock func() time.Time

type TokenIssuer struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
	now      Clock
	parser   *jwt.Parser
}

type TokenIssuerOptions struct {
	Secret    []byte
	Issuer    string
	Audience  string
	TTL       time.Duration
	ClockSkew time.Duration
	Clock     Clock
}

func NewTokenIssuer(opts TokenIssuerOptions) (*TokenIssuer, error) {
	if len(opts.Secret) < 32 {
		return nil, errors.New("security: jwt secret must be at least 32 bytes")
	}
	if opts.Issuer == "" || opts.Audience == "" {
		return nil, errors.New("security: jwt issuer and audience are required")
	}
	if opts.TTL <= 0 {
		return nil, errors.New("security: jwt ttl must be positive")
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	if opts.ClockSkew < 0 {
		return nil, errors.New("security: jwt clock skew must not be negative")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithLeeway(opts.ClockSkew),
		jwt.WithIssuer(opts.Issuer),
		jwt.WithAudience(opts.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(func() time.Time { return clock() }),
	)
	return &TokenIssuer{
		secret:   opts.Secret,
		issuer:   opts.Issuer,
		audience: opts.Audience,
		ttl:      opts.TTL,
		now:      clock,
		parser:   parser,
	}, nil
}

func (t *TokenIssuer) TTL() time.Duration { return t.ttl }

type IssuedAccessToken struct {
	Token     string
	JTI       string
	ExpiresAt time.Time
}

func (t *TokenIssuer) Issue(subject string) (IssuedAccessToken, error) {
	if subject == "" {
		return IssuedAccessToken{}, errors.New("security: subject is required")
	}
	jti, err := RandomURLSafeString(16)
	if err != nil {
		return IssuedAccessToken{}, err
	}

	now := t.now().UTC()
	expiresAt := now.Add(t.ttl)
	claims := AccessClaims{
		Type: TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    t.issuer,
			Audience:  jwt.ClaimStrings{t.audience},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.secret)
	if err != nil {
		return IssuedAccessToken{}, fmt.Errorf("security: sign access token: %w", err)
	}
	return IssuedAccessToken{Token: signed, JTI: jti, ExpiresAt: expiresAt}, nil
}

func (t *TokenIssuer) Verify(token string) (*AccessClaims, error) {
	claims := &AccessClaims{}
	parsed, err := t.parser.ParseWithClaims(token, claims, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}
		return t.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %s", ErrTokenInvalid, err.Error())
	}
	if !parsed.Valid {
		return nil, ErrTokenInvalid
	}
	if claims.Type != TokenTypeAccess {
		return nil, ErrTokenWrongType
	}
	if claims.ID == "" {
		return nil, fmt.Errorf("%w: missing jti", ErrTokenInvalid)
	}
	if claims.NotBefore == nil {
		return nil, fmt.Errorf("%w: missing nbf", ErrTokenInvalid)
	}
	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("%w: missing iat", ErrTokenInvalid)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrTokenInvalid)
	}
	return claims, nil
}
