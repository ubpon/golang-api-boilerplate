package validation

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
)

const (
	MinPasswordLength = 12
	MaxPasswordLength = 128
)

type PasswordPolicy struct {
	MinLength int
	MaxLength int
}

func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{MinLength: MinPasswordLength, MaxLength: MaxPasswordLength}
}

func (p PasswordPolicy) Validate(field, password, email string) *Issue {
	length := utf8.RuneCountInString(password)
	switch {
	case length < p.MinLength:
		return &Issue{Field: field, Message: fmt.Sprintf("must be at least %d characters", p.MinLength)}
	case length > p.MaxLength:
		return &Issue{Field: field, Message: fmt.Sprintf("must be at most %d characters", p.MaxLength)}
	}
	if strings.TrimSpace(password) == "" {
		return &Issue{Field: field, Message: "must not be only whitespace"}
	}
	if IsCommonPassword(password) {
		return &Issue{Field: field, Message: "is too common; choose something less predictable"}
	}
	if email != "" {
		local := domain.EmailLocalPart(email)
		if len(local) >= 3 && strings.Contains(strings.ToLower(password), local) {
			return &Issue{Field: field, Message: "must not contain the local part of your email address"}
		}
	}
	return nil
}
