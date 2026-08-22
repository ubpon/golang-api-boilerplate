package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

type Options struct {
	Level     slog.Level
	Format    Format
	AddSource bool
}

func New(w io.Writer, opts Options) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{
		Level:       opts.Level,
		AddSource:   opts.AddSource,
		ReplaceAttr: RedactAttr,
	}
	var h slog.Handler
	if opts.Format == FormatText {
		h = slog.NewTextHandler(w, handlerOpts)
	} else {
		h = slog.NewJSONHandler(w, handlerOpts)
	}
	return slog.New(h)
}

func ParseLevel(s string) (slog.Level, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.TrimSpace(s))); err != nil {
		return slog.LevelInfo, err
	}
	return lvl, nil
}

type contextKey struct{}

var loggerKey contextKey

func NewContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.New(discardHandler{})
}

func With(ctx context.Context, args ...any) context.Context {
	return NewContext(ctx, FromContext(ctx).With(args...))
}

type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }
