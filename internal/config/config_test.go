package config

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const validSecret = "0123456789abcdef0123456789abcdef"

func setEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	base := map[string]string{
		"APP_ENV":      "development",
		"JWT_SECRET":   validSecret,
		"DATABASE_URL": "postgres://user:pass@localhost:5432/app?sslmode=disable",
	}
	for k, v := range overrides {
		base[k] = v
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
}

func TestLoadAppliesDocumentedDefaults(t *testing.T) {
	setEnv(t, nil)

	cfg, err := Load()
	require.NoError(t, err)

	require.Equal(t, EnvDevelopment, cfg.Env)
	require.Equal(t, ":8080", cfg.HTTP.Addr)
	require.Equal(t, 5*time.Second, cfg.HTTP.ReadHeaderTimeout)
	require.Equal(t, 15*time.Second, cfg.HTTP.ReadTimeout)
	require.Equal(t, 20*time.Second, cfg.HTTP.WriteTimeout)
	require.Equal(t, 60*time.Second, cfg.HTTP.IdleTimeout)
	require.Equal(t, 1<<20, cfg.HTTP.MaxHeaderBytes)
	require.Equal(t, int64(1<<20), cfg.HTTP.MaxBodyBytes)
	require.Equal(t, 15*time.Minute, cfg.Auth.AccessTokenTTL)
	require.Equal(t, 30*24*time.Hour, cfg.Auth.RefreshTokenTTL)
	require.Equal(t, 15*time.Minute, cfg.Auth.ResetTokenTTL)
	require.Equal(t, 10, cfg.Lockout.Threshold)
	require.Equal(t, slog.LevelInfo, cfg.Log.Level)
	require.False(t, cfg.Redis.Enabled)
	require.False(t, cfg.Cookies.Secure)
	require.Equal(t, "log", cfg.Mailer.Driver)
	require.Empty(t, cfg.Proxy.TrustedCIDRs)
}

func TestLoadFailsFastWithoutRequiredSecrets(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("DATABASE_URL", "")

	_, err := Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "JWT_SECRET is required")
	require.Contains(t, err.Error(), "DATABASE_URL is required")
}

func TestLoadRejectsShortJWTSecret(t *testing.T) {
	setEnv(t, map[string]string{"JWT_SECRET": "too-short"})

	_, err := Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "JWT_SECRET must be at least 32 bytes")
}

func TestLoadRejectsInsecureProductionCombinations(t *testing.T) {
	setEnv(t, map[string]string{
		"APP_ENV":       "production",
		"COOKIE_SECURE": "false",
	})

	_, err := Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "COOKIE_SECURE must be true in production")
	require.Contains(t, err.Error(), "CORS_ALLOWED_ORIGINS must be set in production")
}

func TestLoadRejectsWildcardOriginWithCredentials(t *testing.T) {
	setEnv(t, map[string]string{
		"CORS_ALLOWED_ORIGINS":   "*",
		"CORS_ALLOW_CREDENTIALS": "true",
	})

	_, err := Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), `may not contain "*"`)
}

func TestLoadRejectsMalformedValues(t *testing.T) {
	setEnv(t, map[string]string{
		"APP_ENV":                "staging",
		"LOG_LEVEL":              "chatty",
		"LOG_FORMAT":             "yaml",
		"ACCESS_TOKEN_TTL":       "fifteen-minutes",
		"HTTP_MAX_BODY_BYTES":    "lots",
		"LOCKOUT_THRESHOLD":      "many",
		"TRUSTED_PROXY_CIDRS":    "10.0.0.0/8,not-a-cidr",
		"CORS_ALLOW_CREDENTIALS": "maybe",
		"APP_BASE_URL":           "not a url",
	})

	_, err := Load()
	require.Error(t, err)
	for _, fragment := range []string{
		"APP_ENV must be one of",
		"LOG_LEVEL must be one of",
		"LOG_FORMAT must be json or text",
		"ACCESS_TOKEN_TTL must be a Go duration",
		"HTTP_MAX_BODY_BYTES must be an integer",
		"LOCKOUT_THRESHOLD must be an integer",
		"not a valid CIDR",
		"CORS_ALLOW_CREDENTIALS must be a boolean",
		"APP_BASE_URL must be an absolute URL",
	} {
		require.Contains(t, err.Error(), fragment)
	}
}

func TestLoadRejectsAccessTTLLongerThanRefreshTTL(t *testing.T) {
	setEnv(t, map[string]string{
		"ACCESS_TOKEN_TTL":  "48h",
		"REFRESH_TOKEN_TTL": "1h",
	})

	_, err := Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "ACCESS_TOKEN_TTL must be shorter than REFRESH_TOKEN_TTL")
}

func TestLoadParsesTrustedProxyCIDRs(t *testing.T) {
	setEnv(t, map[string]string{"TRUSTED_PROXY_CIDRS": " 10.0.0.0/8 , 172.16.0.0/12 "})

	cfg, err := Load()
	require.NoError(t, err)
	require.Len(t, cfg.Proxy.TrustedCIDRs, 2)
	require.Equal(t, []string{"10.0.0.0/8", "172.16.0.0/12"}, cfg.Proxy.RawCIDRs())
}

func TestLoadEnablesRedisWhenURLIsPresent(t *testing.T) {
	setEnv(t, map[string]string{"REDIS_URL": "redis://localhost:6379/0"})

	cfg, err := Load()
	require.NoError(t, err)
	require.True(t, cfg.Redis.Enabled)
	require.Contains(t, cfg.Describe(), "redis=true")
}

func TestLoadRequiresSMTPHostForSMTPDriver(t *testing.T) {
	setEnv(t, map[string]string{"MAILER_DRIVER": "smtp"})

	_, err := Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "SMTP_HOST is required")
}

func TestProductionDefaultsAreHardened(t *testing.T) {
	setEnv(t, map[string]string{
		"APP_ENV":              "production",
		"CORS_ALLOWED_ORIGINS": "https://app.example.com",
	})

	cfg, err := Load()
	require.NoError(t, err)
	require.True(t, cfg.IsProduction())
	require.True(t, cfg.Cookies.Secure)
	require.Equal(t, "json", string(cfg.Log.Format))
}
