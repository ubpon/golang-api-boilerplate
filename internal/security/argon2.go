package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const maxEncodedFieldLength = 1024

var (
	ErrInvalidHash         = errors.New("security: password hash is not a valid argon2id encoding")
	ErrIncompatibleVersion = errors.New("security: incompatible argon2 version")
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

type PasswordHasher struct {
	params    Argon2Params
	dummyHash string
}

func NewPasswordHasher(params Argon2Params) (*PasswordHasher, error) {
	if params.Memory < 8*1024 {
		return nil, errors.New("security: argon2 memory must be at least 8192 KiB")
	}
	if params.Iterations < 1 {
		return nil, errors.New("security: argon2 iterations must be at least 1")
	}
	if params.Parallelism < 1 {
		return nil, errors.New("security: argon2 parallelism must be at least 1")
	}
	if params.SaltLength < 16 || params.KeyLength < 32 {
		return nil, errors.New("security: argon2 salt must be >= 16 bytes and key >= 32 bytes")
	}
	h := &PasswordHasher{params: params}
	dummy, err := h.Hash("dummy-password-for-constant-time-login")
	if err != nil {
		return nil, err
	}
	h.dummyHash = dummy
	return h, nil
}

func (h *PasswordHasher) Params() Argon2Params { return h.params }

func (h *PasswordHasher) DummyHash() string { return h.dummyHash }

func (h *PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("security: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	return encodeHash(h.params, salt, key), nil
}

func (h *PasswordHasher) Verify(password, encoded string) (bool, error) {
	params, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	candidate := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return subtle.ConstantTimeCompare(candidate, key) == 1, nil
}

func (h *PasswordHasher) VerifyDummy(password string) {
	// The result is deliberately discarded: this call exists only to equalise timing
	// between logins for existing and non-existing accounts.
	_, _ = h.Verify(password, h.dummyHash)
}

func (h *PasswordHasher) NeedsRehash(encoded string) bool {
	params, _, _, err := decodeHash(encoded)
	if err != nil {
		return true
	}
	return params.Memory != h.params.Memory ||
		params.Iterations != h.params.Iterations ||
		params.Parallelism != h.params.Parallelism ||
		params.KeyLength != h.params.KeyLength ||
		params.SaltLength != h.params.SaltLength
}

func encodeHash(p Argon2Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return p, nil, nil, ErrIncompatibleVersion
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, ErrInvalidHash
	}

	if len(salt) > maxEncodedFieldLength || len(key) > maxEncodedFieldLength {
		return p, nil, nil, ErrInvalidHash
	}
	// #nosec G115 -- both lengths are bounded by maxEncodedFieldLength immediately above.
	p.SaltLength = uint32(len(salt))
	// #nosec G115 -- both lengths are bounded by maxEncodedFieldLength immediately above.
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}
