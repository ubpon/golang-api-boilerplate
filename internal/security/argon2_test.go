package security

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testParams() Argon2Params {
	return Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func TestPasswordHasherRejectsWeakParameters(t *testing.T) {
	t.Parallel()

	cases := map[string]Argon2Params{
		"memory too low":     {Memory: 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		"no iterations":      {Memory: 8 * 1024, Iterations: 0, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		"no parallelism":     {Memory: 8 * 1024, Iterations: 3, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		"salt too short":     {Memory: 8 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 8, KeyLength: 32},
		"key length too low": {Memory: 8 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 16},
	}

	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewPasswordHasher(params)
			require.Error(t, err)
		})
	}
}

func TestHashAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	hasher, err := NewPasswordHasher(testParams())
	require.NoError(t, err)

	encoded, err := hasher.Hash("correct horse battery staple")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(encoded, "$argon2id$v=19$m=8192,t=1,p=1$"))

	ok, err := hasher.Verify("correct horse battery staple", encoded)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = hasher.Verify("wrong password entirely", encoded)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestHashProducesDistinctSalts(t *testing.T) {
	t.Parallel()

	hasher, err := NewPasswordHasher(testParams())
	require.NoError(t, err)

	first, err := hasher.Hash("a-very-long-password")
	require.NoError(t, err)
	second, err := hasher.Hash("a-very-long-password")
	require.NoError(t, err)
	require.NotEqual(t, first, second)
}

func TestVerifyRejectsMalformedEncoding(t *testing.T) {
	t.Parallel()

	hasher, err := NewPasswordHasher(testParams())
	require.NoError(t, err)

	for _, encoded := range []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2E$a2V5",
		"$argon2id$v=19$m=8192,t=1,p=1$!!!!$a2V5",
		"$argon2id$v=99$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2E$a2V5",
	} {
		ok, err := hasher.Verify("password", encoded)
		require.Error(t, err, "expected %q to be rejected", encoded)
		require.False(t, ok)
	}
}

func TestNeedsRehashDetectsParameterUpgrade(t *testing.T) {
	t.Parallel()

	weak, err := NewPasswordHasher(testParams())
	require.NoError(t, err)
	legacy, err := weak.Hash("a-sufficiently-long-password")
	require.NoError(t, err)
	require.False(t, weak.NeedsRehash(legacy))

	upgraded := testParams()
	upgraded.Iterations = 3
	strong, err := NewPasswordHasher(upgraded)
	require.NoError(t, err)

	require.True(t, strong.NeedsRehash(legacy))
	require.True(t, strong.NeedsRehash("garbage"))

	current, err := strong.Hash("a-sufficiently-long-password")
	require.NoError(t, err)
	require.False(t, strong.NeedsRehash(current))
}

func TestDummyHashVerifiesAgainstItself(t *testing.T) {
	t.Parallel()

	hasher, err := NewPasswordHasher(testParams())
	require.NoError(t, err)
	require.NotEmpty(t, hasher.DummyHash())

	ok, err := hasher.Verify("some attacker supplied value", hasher.DummyHash())
	require.NoError(t, err)
	require.False(t, ok)

	hasher.VerifyDummy("some attacker supplied value")
}
