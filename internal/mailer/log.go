package mailer

import (
	"context"
	"log/slog"
)

type LogMailer struct {
	log *slog.Logger
}

func NewLogMailer(log *slog.Logger) *LogMailer {
	return &LogMailer{log: log}
}

func (m *LogMailer) Send(ctx context.Context, msg Message) error {
	m.log.LogAttrs(ctx, slog.LevelInfo, "outbound email suppressed in development",
		slog.String("template", msg.Template),
		slog.String("to", maskRecipient(msg.To)),
		slog.String("subject", msg.Subject),
	)
	return nil
}

func (m *LogMailer) Close() error { return nil }

type NoopMailer struct{}

func NewNoopMailer() *NoopMailer { return &NoopMailer{} }

func (NoopMailer) Send(context.Context, Message) error { return nil }

func (NoopMailer) Close() error { return nil }
