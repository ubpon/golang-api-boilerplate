package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/config"
	"github.com/ubpon/golang-api-boilerplate/internal/middleware"
	"github.com/ubpon/golang-api-boilerplate/internal/ratelimit"
)

type Deps struct {
	Config  *config.Config
	Logger  *slog.Logger
	Limiter ratelimit.Limiter
	Rules   ratelimit.Rules
	Tokens  middleware.AccessTokenVerifier
	Routes  Routes
}

type Server struct {
	http     *http.Server
	log      *slog.Logger
	shutdown time.Duration
}

func New(deps Deps) (*Server, error) {
	switch {
	case deps.Config == nil:
		return nil, errors.New("server: config is required")
	case deps.Logger == nil:
		return nil, errors.New("server: logger is required")
	case deps.Limiter == nil:
		return nil, errors.New("server: limiter is required")
	case deps.Tokens == nil:
		return nil, errors.New("server: token verifier is required")
	case deps.Routes.Auth == nil || deps.Routes.Me == nil || deps.Routes.Health == nil:
		return nil, errors.New("server: all route handlers are required")
	}

	cfg := deps.Config
	handler := middleware.Chain(deps.mux(), globalChain(cfg, &deps)...)

	return &Server{
		http: &http.Server{
			Addr:              cfg.HTTP.Addr,
			Handler:           handler,
			ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
			ReadTimeout:       cfg.HTTP.ReadTimeout,
			WriteTimeout:      cfg.HTTP.WriteTimeout,
			IdleTimeout:       cfg.HTTP.IdleTimeout,
			MaxHeaderBytes:    cfg.HTTP.MaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(deps.Logger.Handler(), slog.LevelWarn),
			BaseContext:       func(net.Listener) context.Context { return context.Background() },
		},
		log:      deps.Logger,
		shutdown: cfg.HTTP.ShutdownTimeout,
	}, nil
}

func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) Addr() string { return s.http.Addr }

func (s *Server) Run(ctx context.Context) error {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		return err
	}
	s.http.Addr = listener.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("http server listening", slog.String("addr", s.http.Addr))
		if err := s.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		//nolint:contextcheck // the parent context is already cancelled; draining needs its own deadline.
		return s.Shutdown()
	}
}

func (s *Server) Shutdown() error {
	s.log.Info("shutting down http server", slog.Duration("drain_timeout", s.shutdown))

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdown)
	defer cancel()

	if err := s.http.Shutdown(ctx); err != nil {
		s.log.Error("graceful shutdown timed out, closing connections", slog.Any("error", err))
		return s.http.Close()
	}
	s.log.Info("http server stopped cleanly")
	return nil
}
