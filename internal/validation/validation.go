package validation

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"
)

type Issue struct {
	Field   string
	Message string
}

type Validator struct {
	issues []Issue
}

func New() *Validator { return &Validator{} }

func (v *Validator) Add(field, message string) {
	v.issues = append(v.issues, Issue{Field: field, Message: message})
}

func (v *Validator) AddIssue(issue *Issue) {
	if issue != nil {
		v.issues = append(v.issues, *issue)
	}
}

func (v *Validator) Issues() []Issue { return v.issues }

func (v *Validator) OK() bool { return len(v.issues) == 0 }

func (v *Validator) Email(field, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		v.Add(field, "is required")
		return ""
	}
	if utf8.RuneCountInString(trimmed) > 254 {
		v.Add(field, "must be at most 254 characters")
		return trimmed
	}
	addr, err := mail.ParseAddress(trimmed)
	if err != nil || addr.Address != trimmed || strings.Count(trimmed, "@") != 1 {
		v.Add(field, "must be a valid email address")
		return trimmed
	}
	if parts := strings.SplitN(trimmed, "@", 2); len(parts) != 2 || parts[0] == "" || !strings.Contains(parts[1], ".") {
		v.Add(field, "must be a valid email address")
	}
	return trimmed
}

func (v *Validator) Required(field, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		v.Add(field, "is required")
	}
	return trimmed
}

func (v *Validator) MaxLen(field, value string, limit int) string {
	if utf8.RuneCountInString(value) > limit {
		v.Add(field, fmt.Sprintf("must be at most %d characters", limit))
	}
	return value
}

func (v *Validator) Password(field, password, email string, policy PasswordPolicy) {
	if password == "" {
		v.Add(field, "is required")
		return
	}
	v.AddIssue(policy.Validate(field, password, email))
}

func (v *Validator) Token(field, value string) string {
	trimmed := strings.TrimSpace(value)
	switch {
	case trimmed == "":
		v.Add(field, "is required")
	case utf8.RuneCountInString(trimmed) > 512:
		v.Add(field, "is not a valid token")
	}
	return trimmed
}
