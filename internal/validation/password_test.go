package validation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordPolicyAcceptsStrongPassword(t *testing.T) {
	t.Parallel()

	policy := DefaultPasswordPolicy()
	require.Nil(t, policy.Validate("password", "a-perfectly-fine-passphrase", "person@example.com"))
}

func TestPasswordPolicyEnforcesLengthBounds(t *testing.T) {
	t.Parallel()

	policy := DefaultPasswordPolicy()

	short := policy.Validate("password", strings.Repeat("a", MinPasswordLength-1), "")
	require.NotNil(t, short)
	require.Contains(t, short.Message, "at least 12 characters")

	long := policy.Validate("password", strings.Repeat("a", MaxPasswordLength+1), "")
	require.NotNil(t, long)
	require.Contains(t, long.Message, "at most 128 characters")

	require.Nil(t, policy.Validate("password", strings.Repeat("aX9!", 3), ""))
}

func TestPasswordPolicyCountsRunesNotBytes(t *testing.T) {
	t.Parallel()

	policy := DefaultPasswordPolicy()
	require.NotNil(t, policy.Validate("password", strings.Repeat("é", 11), ""))
	require.Nil(t, policy.Validate("password", strings.Repeat("é", 12), ""))
}

func TestPasswordPolicyRejectsCommonPasswords(t *testing.T) {
	t.Parallel()

	policy := DefaultPasswordPolicy()
	for _, candidate := range []string{"correcthorsebatterystaple", "passwordpassword", "WELCOMETOTHEJUNGLE"} {
		issue := policy.Validate("password", candidate, "")
		require.NotNil(t, issue, "expected %q to be rejected", candidate)
		require.Contains(t, issue.Message, "too common")
	}
}

func TestPasswordPolicyRejectsEmailLocalPart(t *testing.T) {
	t.Parallel()

	policy := DefaultPasswordPolicy()

	issue := policy.Validate("password", "my-jane.doe-secret", "Jane.Doe@Example.COM")
	require.NotNil(t, issue)
	require.Contains(t, issue.Message, "local part")

	require.Nil(t, policy.Validate("password", "unrelated-strong-phrase", "jane.doe@example.com"))
}

func TestPasswordPolicyIgnoresVeryShortLocalParts(t *testing.T) {
	t.Parallel()

	policy := DefaultPasswordPolicy()
	require.Nil(t, policy.Validate("password", "abandoned-lighthouse", "ab@example.com"))
}

func TestPasswordPolicyRejectsWhitespaceOnly(t *testing.T) {
	t.Parallel()

	policy := DefaultPasswordPolicy()
	issue := policy.Validate("password", strings.Repeat(" ", 20), "")
	require.NotNil(t, issue)
	require.Contains(t, issue.Message, "whitespace")
}

func TestValidatorEmail(t *testing.T) {
	t.Parallel()

	v := New()
	require.Equal(t, "person@example.com", v.Email("email", "  person@example.com  "))
	require.True(t, v.OK())

	for _, bad := range []string{"", "not-an-email", "a@b", "two@@example.com", "Person <person@example.com>"} {
		v := New()
		v.Email("email", bad)
		require.False(t, v.OK(), "expected %q to be rejected", bad)
	}
}

func TestValidatorCollectsMultipleIssues(t *testing.T) {
	t.Parallel()

	v := New()
	v.Email("email", "nope")
	v.Password("password", "short", "", DefaultPasswordPolicy())
	v.Required("name", "   ")

	require.False(t, v.OK())
	require.Len(t, v.Issues(), 3)
}

func TestValidatorToken(t *testing.T) {
	t.Parallel()

	v := New()
	require.Equal(t, "abc", v.Token("token", " abc "))
	require.True(t, v.OK())

	v = New()
	v.Token("token", strings.Repeat("a", 513))
	require.False(t, v.OK())
}
