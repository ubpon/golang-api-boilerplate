package mailer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestComposerBuildsVerificationEmail(t *testing.T) {
	t.Parallel()

	composer := NewComposer("Example App", "https://app.example.com/")
	msg, err := composer.VerifyEmail("person@example.com", "Ada", "tok en+/value", "24 hours")
	require.NoError(t, err)

	require.Equal(t, "person@example.com", msg.To)
	require.Equal(t, TemplateVerifyEmail, msg.Template)
	require.Equal(t, "Confirm your email address", msg.Subject)
	require.Contains(t, msg.TextBody, "Hi Ada,")
	require.Contains(t, msg.TextBody, "Example App")
	require.Contains(t, msg.TextBody, "24 hours")
	require.Contains(t, msg.HTMLBody, "Confirm email address")

	link := extractLink(t, msg.TextBody)
	require.Equal(t, "https", link.Scheme)
	require.Equal(t, "/verify-email", link.Path)
	require.Equal(t, "tok en+/value", link.Query().Get("token"))
}

func TestComposerBuildsResetAndChangeEmails(t *testing.T) {
	t.Parallel()

	composer := NewComposer("Example App", "https://app.example.com")

	reset, err := composer.PasswordReset("person@example.com", "", "reset-token", "15 minutes")
	require.NoError(t, err)
	require.Equal(t, TemplatePasswordReset, reset.Template)
	require.Contains(t, reset.TextBody, "Hi,")
	require.Equal(t, "/reset-password", extractLink(t, reset.TextBody).Path)

	changed, err := composer.PasswordChanged("person@example.com", "Ada")
	require.NoError(t, err)
	require.Equal(t, TemplatePasswordChange, changed.Template)
	require.Contains(t, changed.TextBody, "all other sessions were signed out")
	require.NotContains(t, changed.TextBody, "token=")
}

func TestComposerEscapesHTMLInNames(t *testing.T) {
	t.Parallel()

	composer := NewComposer("Example App", "https://app.example.com")
	msg, err := composer.VerifyEmail("person@example.com", `<script>alert(1)</script>`, "token", "1 hour")
	require.NoError(t, err)

	require.NotContains(t, msg.HTMLBody, "<script>")
	require.Contains(t, msg.HTMLBody, "&lt;script&gt;")
}

func TestLogMailerMasksRecipientAndOmitsBody(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	m := NewLogMailer(slog.New(slog.NewJSONHandler(&buf, nil)))

	require.NoError(t, m.Send(context.Background(), Message{
		To:       "someone@example.com",
		Subject:  "Reset your password",
		TextBody: "https://app.example.com/reset-password?token=super-secret",
		Template: TemplatePasswordReset,
	}))
	require.NoError(t, m.Close())

	logged := buf.String()
	require.NotContains(t, logged, "someone@example.com")
	require.NotContains(t, logged, "super-secret")
	require.Contains(t, logged, "s*****e@example.com")
	require.Contains(t, logged, TemplatePasswordReset)
}

func TestMaskRecipient(t *testing.T) {
	t.Parallel()

	require.Equal(t, "a******e@example.com", maskRecipient("alicexxe@example.com"))
	require.Equal(t, "**@example.com", maskRecipient("ab@example.com"))
	require.Equal(t, "***", maskRecipient("not-an-address"))
}

type recordingMailer struct {
	mu       sync.Mutex
	received []Message
	err      error
	panics   bool
	done     chan struct{}
	once     sync.Once
}

func (m *recordingMailer) Send(_ context.Context, msg Message) error {
	m.mu.Lock()
	m.received = append(m.received, msg)
	m.mu.Unlock()
	m.once.Do(func() { close(m.done) })
	if m.panics {
		panic("delivery exploded")
	}
	return m.err
}

func (m *recordingMailer) Close() error { return nil }

func TestAsyncDoesNotBlockTheCaller(t *testing.T) {
	t.Parallel()

	inner := &recordingMailer{done: make(chan struct{})}
	async := NewAsync(inner, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), AsyncOptions{Workers: 1})

	start := time.Now()
	require.NoError(t, async.Send(context.Background(), Message{To: "a@example.com", Template: "t"}))
	require.Less(t, time.Since(start), time.Second)

	select {
	case <-inner.done:
	case <-time.After(5 * time.Second):
		t.Fatal("message was never delivered")
	}
	require.NoError(t, async.Close())

	inner.mu.Lock()
	defer inner.mu.Unlock()
	require.Len(t, inner.received, 1)
}

func TestAsyncSwallowsDeliveryFailures(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	inner := &recordingMailer{err: errors.New("smtp refused"), done: make(chan struct{})}
	async := NewAsync(inner, slog.New(slog.NewJSONHandler(&logs, nil)), AsyncOptions{Workers: 1})

	require.NoError(t, async.Send(context.Background(), Message{To: "a@example.com", Template: "t"}))
	<-inner.done
	require.NoError(t, async.Close())

	require.Contains(t, logs.String(), "failed to deliver email")
	require.Contains(t, logs.String(), "smtp refused")
}

func TestAsyncRecoversFromPanickingBackend(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	inner := &recordingMailer{panics: true, done: make(chan struct{})}
	async := NewAsync(inner, slog.New(slog.NewJSONHandler(&logs, nil)), AsyncOptions{Workers: 1})

	require.NoError(t, async.Send(context.Background(), Message{To: "a@example.com", Template: "t"}))
	<-inner.done
	require.NoError(t, async.Close())

	require.Contains(t, logs.String(), "panic while delivering email")
}

func TestAsyncDropsInsteadOfBlockingWhenTheQueueIsFull(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	blocker := make(chan struct{})
	inner := &blockingMailer{release: blocker}
	async := NewAsync(inner, slog.New(slog.NewJSONHandler(&logs, nil)), AsyncOptions{Workers: 1, QueueSize: 1})

	for i := 0; i < 8; i++ {
		require.NoError(t, async.Send(context.Background(), Message{To: "a@example.com", Template: "t"}))
	}
	close(blocker)
	require.NoError(t, async.Close())

	require.Contains(t, logs.String(), "email queue is full")
}

type blockingMailer struct {
	release chan struct{}
}

func (m *blockingMailer) Send(context.Context, Message) error {
	<-m.release
	return nil
}

func (m *blockingMailer) Close() error { return nil }

func TestNoopMailerIsInert(t *testing.T) {
	t.Parallel()

	m := NewNoopMailer()
	require.NoError(t, m.Send(context.Background(), Message{To: "a@example.com"}))
	require.NoError(t, m.Close())
}

func TestSMTPMailerValidatesOptions(t *testing.T) {
	t.Parallel()

	_, err := NewSMTPMailer(SMTPOptions{From: "a@example.com"})
	require.Error(t, err)

	_, err = NewSMTPMailer(SMTPOptions{Host: "localhost"})
	require.Error(t, err)

	m, err := NewSMTPMailer(SMTPOptions{Host: "localhost", Port: 1025, From: "a@example.com"})
	require.NoError(t, err)
	require.NoError(t, m.Close())
}

func TestSMTPRenderProducesMultipartMessage(t *testing.T) {
	t.Parallel()

	m, err := NewSMTPMailer(SMTPOptions{Host: "localhost", Port: 1025, From: "no-reply@example.com"})
	require.NoError(t, err)

	body, err := m.render(Message{
		To:       "person@example.com",
		Subject:  "Hello\r\nBcc: attacker@example.com",
		TextBody: "plain body",
		HTMLBody: "<p>html body</p>",
	})
	require.NoError(t, err)

	rendered := string(body)
	require.Contains(t, rendered, "From: no-reply@example.com")
	require.Contains(t, rendered, "To: person@example.com")
	require.Contains(t, rendered, "Subject: Hello  Bcc: attacker@example.com")
	require.Equal(t, 1, strings.Count(rendered, "Subject:"))
	require.Contains(t, rendered, "multipart/alternative")
	require.Contains(t, rendered, "plain body")
	require.Contains(t, rendered, "<p>html body</p>")
}

func extractLink(t *testing.T, body string) *url.URL {
	t.Helper()
	for _, field := range strings.Fields(body) {
		if strings.HasPrefix(field, "http") {
			parsed, err := url.Parse(field)
			require.NoError(t, err)
			return parsed
		}
	}
	t.Fatal("no link found in message body")
	return nil
}
