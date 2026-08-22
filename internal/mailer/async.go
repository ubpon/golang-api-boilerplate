package mailer

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type AsyncOptions struct {
	QueueSize   int
	Workers     int
	SendTimeout time.Duration
}

type Async struct {
	inner     Mailer
	log       *slog.Logger
	queue     chan Message
	wg        sync.WaitGroup
	timeout   time.Duration
	closeOnce sync.Once
}

func NewAsync(inner Mailer, log *slog.Logger, opts AsyncOptions) *Async {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 256
	}
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.SendTimeout <= 0 {
		opts.SendTimeout = 15 * time.Second
	}

	a := &Async{
		inner:   inner,
		log:     log,
		queue:   make(chan Message, opts.QueueSize),
		timeout: opts.SendTimeout,
	}
	a.wg.Add(opts.Workers)
	for i := 0; i < opts.Workers; i++ {
		go a.worker()
	}
	return a
}

func (a *Async) Send(_ context.Context, msg Message) error {
	select {
	case a.queue <- msg:
		return nil
	default:
		a.log.Warn("email queue is full, message dropped",
			slog.String("template", msg.Template),
			slog.String("to", maskRecipient(msg.To)),
		)
		return nil
	}
}

func (a *Async) Close() error {
	a.closeOnce.Do(func() {
		close(a.queue)
		a.wg.Wait()
	})
	return a.inner.Close()
}

func (a *Async) worker() {
	defer a.wg.Done()
	for msg := range a.queue {
		a.deliver(msg)
	}
}

func (a *Async) deliver(msg Message) {
	defer func() {
		if rec := recover(); rec != nil {
			a.log.Error("panic while delivering email",
				slog.String("template", msg.Template),
				slog.Any("panic", rec),
			)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	if err := a.inner.Send(ctx, msg); err != nil {
		a.log.Error("failed to deliver email",
			slog.String("template", msg.Template),
			slog.String("to", maskRecipient(msg.To)),
			slog.Any("error", err),
		)
	}
}

func maskRecipient(address string) string {
	at := strings.LastIndex(address, "@")
	if at <= 0 {
		return "***"
	}
	local := address[:at]
	domain := address[at:]
	if len(local) <= 2 {
		return "**" + domain
	}
	return local[:1] + strings.Repeat("*", len(local)-2) + local[len(local)-1:] + domain
}
