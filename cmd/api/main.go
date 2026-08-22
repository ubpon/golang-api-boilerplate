package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ubpon/golang-api-boilerplate/internal/config"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
	"github.com/ubpon/golang-api-boilerplate/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, logging.Options{
		Level:     cfg.Log.Level,
		Format:    cfg.Log.Format,
		AddSource: cfg.Log.AddSource,
	}).With(
		slog.String("service", cfg.Auth.Issuer),
		slog.String("version", server.Version),
		slog.String("env", string(cfg.Env)),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	app, err := server.Build(ctx, server.BuildOptions{Config: cfg, Logger: log})
	if err != nil {
		return err
	}
	defer func() {
		if err := app.Close(); err != nil {
			log.Error("error while releasing resources", slog.Any("error", err))
		}
	}()

	go app.Cleanup.Run(ctx)

	log.Info("starting api", slog.String("config", cfg.Describe()))
	if err := app.Server.Run(ctx); err != nil {
		return err
	}
	return nil
}
