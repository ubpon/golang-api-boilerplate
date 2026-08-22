package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/logging"
)

type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvProduction  Environment = "production"
	EnvTest        Environment = "test"
)

const minJWTSecretBytes = 32

type Config struct {
	Env      Environment
	BaseURL  string
	HTTP     HTTPConfig
	Log      LogConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Auth     AuthConfig
	Cookies  CookieConfig
	CORS     CORSConfig
	Proxy    ProxyConfig
	Mailer   MailerConfig
	Lockout  LockoutConfig
}

type HTTPConfig struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	MaxBodyBytes      int64
	ShutdownTimeout   time.Duration
	HandlerTimeout    time.Duration
}

type LogConfig struct {
	Level     slog.Level
	Format    logging.Format
	AddSource bool
}

type DatabaseConfig struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	QueryTimeout    time.Duration
}

type RedisConfig struct {
	Enabled bool
	URL     string
}

type AuthConfig struct {
	JWTSecret         []byte
	Issuer            string
	Audience          string
	AccessTokenTTL    time.Duration
	ClockSkew         time.Duration
	RefreshTokenTTL   time.Duration
	ResetTokenTTL     time.Duration
	VerifyTokenTTL    time.Duration
	RequireVerifiedAt bool
}

type CookieConfig struct {
	Domain      string
	Secure      bool
	RefreshPath string
	AccessName  string
	RefreshName string
	CSRFName    string
}

type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
}

type ProxyConfig struct {
	TrustedCIDRs []*net.IPNet
	rawCIDRs     []string
}

func (p ProxyConfig) RawCIDRs() []string { return p.rawCIDRs }

type MailerConfig struct {
	Driver      string
	From        string
	SMTPHost    string
	SMTPPort    int
	SMTPUser    string
	SMTPassword string
	SMTPTLS     bool
	SendTimeout time.Duration
}

type LockoutConfig struct {
	Threshold   int
	BaseWindow  time.Duration
	MaxWindow   time.Duration
	BackoffStep int
}

func Load() (*Config, error) {
	c := &collector{}

	env := Environment(strings.ToLower(c.str("APP_ENV", string(EnvDevelopment))))
	switch env {
	case EnvDevelopment, EnvProduction, EnvTest:
	default:
		c.fail("APP_ENV must be one of development, production, test; got %q", env)
		env = EnvDevelopment
	}

	logLevel, err := logging.ParseLevel(c.str("LOG_LEVEL", "info"))
	if err != nil {
		c.fail("LOG_LEVEL must be one of debug, info, warn, error")
	}

	format := logging.Format(strings.ToLower(c.str("LOG_FORMAT", defaultLogFormat(env))))
	if format != logging.FormatJSON && format != logging.FormatText {
		c.fail("LOG_FORMAT must be json or text; got %q", format)
		format = logging.FormatJSON
	}

	secret := []byte(c.required("JWT_SECRET"))
	if len(secret) > 0 && len(secret) < minJWTSecretBytes {
		c.fail("JWT_SECRET must be at least %d bytes, got %d", minJWTSecretBytes, len(secret))
	}

	baseURL := c.str("APP_BASE_URL", "http://localhost:8080")
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		c.fail("APP_BASE_URL must be an absolute URL; got %q", baseURL)
	}

	dsn := c.required("DATABASE_URL")

	redisURL := c.str("REDIS_URL", "")

	trusted, rawCIDRs := parseCIDRs(c, c.list("TRUSTED_PROXY_CIDRS", nil))

	corsOrigins := c.list("CORS_ALLOWED_ORIGINS", nil)
	allowCredentials := c.boolean("CORS_ALLOW_CREDENTIALS", true)
	for _, origin := range corsOrigins {
		if origin == "*" && allowCredentials {
			c.fail("CORS_ALLOWED_ORIGINS may not contain \"*\" while CORS_ALLOW_CREDENTIALS is true")
		}
	}

	cookieSecure := c.boolean("COOKIE_SECURE", env == EnvProduction)
	if env == EnvProduction && !cookieSecure {
		c.fail("COOKIE_SECURE must be true in production")
	}

	mailerDriver := strings.ToLower(c.str("MAILER_DRIVER", "log"))
	switch mailerDriver {
	case "log", "smtp", "noop":
	default:
		c.fail("MAILER_DRIVER must be one of log, smtp, noop; got %q", mailerDriver)
	}
	if mailerDriver == "smtp" {
		if c.str("SMTP_HOST", "") == "" {
			c.fail("SMTP_HOST is required when MAILER_DRIVER=smtp")
		}
	}

	cfg := &Config{
		Env:     env,
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP: HTTPConfig{
			Addr:              c.str("HTTP_ADDR", ":8080"),
			ReadHeaderTimeout: c.duration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
			ReadTimeout:       c.duration("HTTP_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:      c.duration("HTTP_WRITE_TIMEOUT", 20*time.Second),
			IdleTimeout:       c.duration("HTTP_IDLE_TIMEOUT", 60*time.Second),
			MaxHeaderBytes:    c.integer("HTTP_MAX_HEADER_BYTES", 1<<20),
			MaxBodyBytes:      c.integer64("HTTP_MAX_BODY_BYTES", 1<<20),
			ShutdownTimeout:   c.duration("HTTP_SHUTDOWN_TIMEOUT", 20*time.Second),
			HandlerTimeout:    c.duration("HTTP_HANDLER_TIMEOUT", 15*time.Second),
		},
		Log: LogConfig{
			Level:     logLevel,
			Format:    format,
			AddSource: c.boolean("LOG_ADD_SOURCE", false),
		},
		Database: DatabaseConfig{
			DSN:             dsn,
			MaxOpenConns:    c.integer("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    c.integer("DB_MAX_IDLE_CONNS", 25),
			ConnMaxLifetime: c.duration("DB_CONN_MAX_LIFETIME", 30*time.Minute),
			ConnMaxIdleTime: c.duration("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
			QueryTimeout:    c.duration("DB_QUERY_TIMEOUT", 5*time.Second),
		},
		Redis: RedisConfig{
			Enabled: redisURL != "",
			URL:     redisURL,
		},
		Auth: AuthConfig{
			JWTSecret:         secret,
			Issuer:            c.str("JWT_ISSUER", "golang-api-boilerplate"),
			Audience:          c.str("JWT_AUDIENCE", "golang-api-boilerplate-clients"),
			AccessTokenTTL:    c.duration("ACCESS_TOKEN_TTL", 15*time.Minute),
			ClockSkew:         c.duration("JWT_CLOCK_SKEW", 30*time.Second),
			RefreshTokenTTL:   c.duration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
			ResetTokenTTL:     c.duration("RESET_TOKEN_TTL", 15*time.Minute),
			VerifyTokenTTL:    c.duration("VERIFY_TOKEN_TTL", 24*time.Hour),
			RequireVerifiedAt: c.boolean("REQUIRE_VERIFIED_EMAIL", false),
		},
		Cookies: CookieConfig{
			Domain:      c.str("COOKIE_DOMAIN", ""),
			Secure:      cookieSecure,
			RefreshPath: c.str("COOKIE_REFRESH_PATH", "/v1/auth"),
			AccessName:  c.str("COOKIE_ACCESS_NAME", "access_token"),
			RefreshName: c.str("COOKIE_REFRESH_NAME", "refresh_token"),
			CSRFName:    c.str("COOKIE_CSRF_NAME", "csrf_token"),
		},
		CORS: CORSConfig{
			AllowedOrigins:   corsOrigins,
			AllowedMethods:   c.list("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"}),
			AllowedHeaders:   c.list("CORS_ALLOWED_HEADERS", []string{"Content-Type", "Authorization", "X-CSRF-Token", "X-Request-ID"}),
			ExposedHeaders:   c.list("CORS_EXPOSED_HEADERS", []string{"X-Request-ID", "Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"}),
			AllowCredentials: allowCredentials,
			MaxAge:           c.duration("CORS_MAX_AGE", 10*time.Minute),
		},
		Proxy: ProxyConfig{TrustedCIDRs: trusted, rawCIDRs: rawCIDRs},
		Mailer: MailerConfig{
			Driver:      mailerDriver,
			From:        c.str("MAIL_FROM", "no-reply@example.com"),
			SMTPHost:    c.str("SMTP_HOST", ""),
			SMTPPort:    c.integer("SMTP_PORT", 1025),
			SMTPUser:    c.str("SMTP_USERNAME", ""),
			SMTPassword: c.str("SMTP_PASSWORD", ""),
			SMTPTLS:     c.boolean("SMTP_TLS", false),
			SendTimeout: c.duration("MAIL_SEND_TIMEOUT", 10*time.Second),
		},
		Lockout: LockoutConfig{
			Threshold:   c.integer("LOCKOUT_THRESHOLD", 10),
			BaseWindow:  c.duration("LOCKOUT_BASE_WINDOW", 15*time.Minute),
			MaxWindow:   c.duration("LOCKOUT_MAX_WINDOW", 24*time.Hour),
			BackoffStep: c.integer("LOCKOUT_BACKOFF_STEP", 5),
		},
	}

	if cfg.HTTP.MaxBodyBytes <= 0 {
		c.fail("HTTP_MAX_BODY_BYTES must be positive")
	}
	if cfg.Lockout.Threshold <= 0 {
		c.fail("LOCKOUT_THRESHOLD must be positive")
	}
	if cfg.Lockout.BackoffStep <= 0 {
		c.fail("LOCKOUT_BACKOFF_STEP must be positive")
	}
	if cfg.Auth.AccessTokenTTL >= cfg.Auth.RefreshTokenTTL {
		c.fail("ACCESS_TOKEN_TTL must be shorter than REFRESH_TOKEN_TTL")
	}
	if env == EnvProduction && len(cfg.CORS.AllowedOrigins) == 0 {
		c.fail("CORS_ALLOWED_ORIGINS must be set in production")
	}

	if err := c.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) IsProduction() bool { return c.Env == EnvProduction }

func defaultLogFormat(env Environment) string {
	if env == EnvProduction {
		return string(logging.FormatJSON)
	}
	return string(logging.FormatText)
}

func parseCIDRs(c *collector, raw []string) ([]*net.IPNet, []string) {
	nets := make([]*net.IPNet, 0, len(raw))
	kept := make([]string, 0, len(raw))
	for _, entry := range raw {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			c.fail("TRUSTED_PROXY_CIDRS entry %q is not a valid CIDR: %v", entry, err)
			continue
		}
		nets = append(nets, network)
		kept = append(kept, entry)
	}
	return nets, kept
}

func (c *Config) Describe() string {
	return fmt.Sprintf("env=%s addr=%s redis=%t mailer=%s trusted_proxies=%d",
		c.Env, c.HTTP.Addr, c.Redis.Enabled, c.Mailer.Driver, len(c.Proxy.TrustedCIDRs))
}
