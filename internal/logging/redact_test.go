package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactAttrCoversEverySensitiveKey(t *testing.T) {
	t.Parallel()

	for key := range sensitiveKeys {
		attr := RedactAttr(nil, slog.String(key, "super-secret-value"))
		require.Equal(t, RedactedPlaceholder, attr.Value.String(), "key %q was not redacted", key)
	}
}

func TestRedactAttrIsCaseInsensitiveAndTrims(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"Password", "SET-COOKIE", "  Authorization  ", "Refresh_Token"} {
		attr := RedactAttr(nil, slog.String(key, "leak"))
		require.Equal(t, RedactedPlaceholder, attr.Value.String(), "key %q was not redacted", key)
	}
}

func TestRedactAttrLeavesOrdinaryKeysAlone(t *testing.T) {
	t.Parallel()

	attr := RedactAttr(nil, slog.String("user_id", "abc-123"))
	require.Equal(t, "abc-123", attr.Value.String())
}

func TestLoggerRedactsNestedAttributes(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := New(&buf, Options{Level: slog.LevelDebug, Format: FormatJSON})

	log.With(slog.String("access_token", "at-value")).
		WithGroup("request").
		Info("handled",
			slog.String("password", "hunter2000000"),
			slog.Group("headers",
				slog.String("authorization", "Bearer leaked"),
				slog.String("cookie", "session=leaked"),
				slog.String("user-agent", "curl/8.0"),
			),
			slog.String("email", "person@example.com"),
		)

	payload := buf.String()
	require.NotContains(t, payload, "at-value")
	require.NotContains(t, payload, "hunter2000000")
	require.NotContains(t, payload, "Bearer leaked")
	require.NotContains(t, payload, "session=leaked")
	require.Contains(t, payload, "curl/8.0")
	require.Contains(t, payload, "person@example.com")
	require.Equal(t, 4, strings.Count(payload, RedactedPlaceholder))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
}

func TestTextHandlerAlsoRedacts(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := New(&buf, Options{Level: slog.LevelInfo, Format: FormatText})
	log.Info("boot", slog.String("jwt_secret", "0123456789abcdef0123456789abcdef"))

	require.NotContains(t, buf.String(), "0123456789abcdef")
	require.Contains(t, buf.String(), RedactedPlaceholder)
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	level, err := ParseLevel("warn")
	require.NoError(t, err)
	require.Equal(t, slog.LevelWarn, level)

	_, err = ParseLevel("not-a-level")
	require.Error(t, err)
}

func TestFromContextFallsBackToDiscardLogger(t *testing.T) {
	t.Parallel()

	log := FromContext(context.Background())
	require.NotNil(t, log)
	require.False(t, log.Enabled(context.Background(), slog.LevelError))
	log.Error("this must not panic")
}

func TestContextLoggerCarriesAttributes(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base := New(&buf, Options{Level: slog.LevelInfo, Format: FormatJSON})

	ctx := NewContext(context.Background(), base.With(slog.String("request_id", "req-1")))
	ctx = With(ctx, slog.String("user_id", "user-1"))
	FromContext(ctx).Info("hello")

	require.Contains(t, buf.String(), `"request_id":"req-1"`)
	require.Contains(t, buf.String(), `"user_id":"user-1"`)
}

func TestSecurityEventLogsAtWarn(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	ctx := NewContext(context.Background(), New(&buf, Options{Level: slog.LevelDebug, Format: FormatJSON}))

	Security(ctx, EventRefreshReuseDetected, "user_id", "user-9", "token", "must-not-leak")

	require.Contains(t, buf.String(), `"level":"WARN"`)
	require.Contains(t, buf.String(), `"event":"auth.refresh_reuse_detected"`)
	require.Contains(t, buf.String(), `"user_id":"user-9"`)
	require.NotContains(t, buf.String(), "must-not-leak")
}
