package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/config"
	"github.com/ubpon/golang-api-boilerplate/internal/handler"
	"github.com/ubpon/golang-api-boilerplate/internal/mailer"
	"github.com/ubpon/golang-api-boilerplate/internal/ratelimit"
	"github.com/ubpon/golang-api-boilerplate/internal/repository"
	"github.com/ubpon/golang-api-boilerplate/internal/repository/postgres"
	"github.com/ubpon/golang-api-boilerplate/internal/security"
	"github.com/ubpon/golang-api-boilerplate/internal/service"
	"github.com/ubpon/golang-api-boilerplate/internal/validation"
)

const Version = "0.1.0"

type App struct {
	Server  *Server
	Store   repository.Store
	Limiter ratelimit.Limiter
	Mailer  mailer.Mailer
	Cleanup *service.Cleanup

	log     *slog.Logger
	closers []func() error
}

type BuildOptions struct {
	Config *config.Config
	Logger *slog.Logger
	Store  repository.Store
	Mailer mailer.Mailer
	Clock  func() time.Time
	Rules  *ratelimit.Rules
	Argon2 *security.Argon2Params
}

func Build(ctx context.Context, opts BuildOptions) (*App, error) {
	cfg := opts.Config
	log := opts.Logger
	if cfg == nil || log == nil {
		return nil, errors.New("server: config and logger are required")
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	app := &App{log: log}

	store := opts.Store
	if store == nil {
		pg, err := postgres.Open(ctx, postgres.Options{
			DSN:             cfg.Database.DSN,
			MaxOpenConns:    cfg.Database.MaxOpenConns,
			MaxIdleConns:    cfg.Database.MaxIdleConns,
			ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
			ConnMaxIdleTime: cfg.Database.ConnMaxIdleTime,
			QueryTimeout:    cfg.Database.QueryTimeout,
		})
		if err != nil {
			return nil, err
		}
		store = pg
		app.closers = append(app.closers, pg.Close)
	}
	app.Store = store

	limiter, limiterProbe, err := buildLimiter(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	app.Limiter = limiter
	app.closers = append(app.closers, limiter.Close)

	post := opts.Mailer
	if post == nil {
		base, err := buildMailer(cfg, log)
		if err != nil {
			return nil, err
		}
		//nolint:contextcheck // deliveries deliberately outlive the request that queued them.
		post = mailer.NewAsync(base, log, mailer.AsyncOptions{SendTimeout: cfg.Mailer.SendTimeout})
	}
	app.Mailer = post
	app.closers = append(app.closers, post.Close)

	argon2Params := security.DefaultArgon2Params()
	if opts.Argon2 != nil {
		argon2Params = *opts.Argon2
	}
	rules := ratelimit.DefaultRules()
	if opts.Rules != nil {
		rules = *opts.Rules
	}

	hasher, err := security.NewPasswordHasher(argon2Params)
	if err != nil {
		return nil, err
	}
	tokens, err := security.NewTokenIssuer(security.TokenIssuerOptions{
		Secret:    cfg.Auth.JWTSecret,
		Issuer:    cfg.Auth.Issuer,
		Audience:  cfg.Auth.Audience,
		TTL:       cfg.Auth.AccessTokenTTL,
		ClockSkew: cfg.Auth.ClockSkew,
		Clock:     security.Clock(clock),
	})
	if err != nil {
		return nil, err
	}

	authService, err := service.NewAuthService(service.AuthDeps{
		Users:              store.Users(),
		RefreshTokens:      store.RefreshTokens(),
		ResetTokens:        store.PasswordResetTokens(),
		VerificationTokens: store.EmailVerificationTokens(),
		Hasher:             hasher,
		Tokens:             tokens,
		Mailer:             post,
		Composer:           mailer.NewComposer(cfg.Auth.Issuer, cfg.BaseURL),
		Policy:             validation.DefaultPasswordPolicy(),
		Lockout: service.LockoutPolicy{
			Threshold:   cfg.Lockout.Threshold,
			BaseWindow:  cfg.Lockout.BaseWindow,
			MaxWindow:   cfg.Lockout.MaxWindow,
			BackoffStep: cfg.Lockout.BackoffStep,
		},
		TTL: service.TTLs{
			Access:  cfg.Auth.AccessTokenTTL,
			Refresh: cfg.Auth.RefreshTokenTTL,
			Reset:   cfg.Auth.ResetTokenTTL,
			Verify:  cfg.Auth.VerifyTokenTTL,
		},
		Logger:          log,
		Clock:           service.Clock(clock),
		RequireVerified: cfg.Auth.RequireVerifiedAt,
	})
	if err != nil {
		return nil, err
	}

	handlerDeps := handler.AuthDeps{
		Service: authService,
		Cookies: handler.NewCookieWriter(handler.CookieSettings{
			Domain:      cfg.Cookies.Domain,
			Secure:      cfg.Cookies.Secure,
			RefreshPath: cfg.Cookies.RefreshPath,
			AccessName:  cfg.Cookies.AccessName,
			RefreshName: cfg.Cookies.RefreshName,
			CSRFName:    cfg.Cookies.CSRFName,
		}),
		Limiter: limiter,
		Rules:   rules,
		Policy:  validation.DefaultPasswordPolicy(),
		Clock:   clock,
	}

	probes := []handler.Probe{{Name: "database", Check: store.Ping}}
	if limiterProbe != nil {
		probes = append(probes, handler.Probe{Name: "redis", Check: limiterProbe})
	}

	srv, err := New(Deps{
		Config:  cfg,
		Logger:  log,
		Limiter: limiter,
		Rules:   rules,
		Tokens:  tokens,
		Routes: Routes{
			Auth:   handler.NewAuth(handlerDeps),
			Me:     handler.NewMe(handlerDeps),
			Health: handler.NewHealth(Version, 2*time.Second, probes...),
		},
	})
	if err != nil {
		return nil, err
	}

	app.Server = srv
	app.Cleanup = service.NewCleanup(store, log, time.Hour, service.Clock(clock))
	return app, nil
}

func (a *App) Close() error {
	var errs []error
	for i := len(a.closers) - 1; i >= 0; i-- {
		if err := a.closers[i](); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func buildLimiter(ctx context.Context, cfg *config.Config, log *slog.Logger) (ratelimit.Limiter, func(context.Context) error, error) {
	memory := ratelimit.NewMemoryLimiter(ratelimit.MemoryOptions{
		IdleTTL:      time.Hour,
		SweepEvery:   time.Minute,
		StartJanitor: true,
	})
	if !cfg.Redis.Enabled {
		return memory, nil, nil
	}

	redisLimiter, err := ratelimit.NewRedisLimiter(ratelimit.RedisOptions{URL: cfg.Redis.URL})
	if err != nil {
		return nil, nil, err
	}

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := redisLimiter.Ping(pingCtx); err != nil {
		log.Warn("redis is configured but unreachable at boot, starting in degraded mode",
			slog.Any("error", err))
	}

	return ratelimit.NewFailoverLimiter(redisLimiter, memory, log), redisLimiter.Ping, nil
}

func buildMailer(cfg *config.Config, log *slog.Logger) (mailer.Mailer, error) {
	switch cfg.Mailer.Driver {
	case "smtp":
		return mailer.NewSMTPMailer(mailer.SMTPOptions{
			Host:        cfg.Mailer.SMTPHost,
			Port:        cfg.Mailer.SMTPPort,
			Username:    cfg.Mailer.SMTPUser,
			Password:    cfg.Mailer.SMTPassword,
			From:        cfg.Mailer.From,
			UseTLS:      cfg.Mailer.SMTPTLS,
			SendTimeout: cfg.Mailer.SendTimeout,
		})
	case "noop":
		return mailer.NewNoopMailer(), nil
	case "log":
		return mailer.NewLogMailer(log), nil
	default:
		return nil, fmt.Errorf("server: unknown mailer driver %q", cfg.Mailer.Driver)
	}
}
