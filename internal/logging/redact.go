package logging

import (
	"log/slog"
	"strings"
)

const RedactedPlaceholder = "[REDACTED]"

var sensitiveKeys = map[string]struct{}{
	"password":         {},
	"new_password":     {},
	"current_password": {},
	"confirm_password": {},
	"token":            {},
	"refresh_token":    {},
	"access_token":     {},
	"reset_token":      {},
	"authorization":    {},
	"cookie":           {},
	"set-cookie":       {},
	"set_cookie":       {},
	"csrf":             {},
	"csrf_token":       {},
	"secret":           {},
	"jwt_secret":       {},
	"api_key":          {},
	"private_key":      {},
}

func IsSensitiveKey(key string) bool {
	_, ok := sensitiveKeys[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

func RedactAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		return a
	}
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, RedactedPlaceholder)
	}
	return a
}
