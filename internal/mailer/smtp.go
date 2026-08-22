package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

type SMTPOptions struct {
	Host        string
	Port        int
	Username    string
	Password    string
	From        string
	UseTLS      bool
	SendTimeout time.Duration
}

type SMTPMailer struct {
	opts SMTPOptions
}

func NewSMTPMailer(opts SMTPOptions) (*SMTPMailer, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("mailer: smtp host is required")
	}
	if opts.From == "" {
		return nil, fmt.Errorf("mailer: smtp from address is required")
	}
	if opts.SendTimeout <= 0 {
		opts.SendTimeout = 10 * time.Second
	}
	return &SMTPMailer{opts: opts}, nil
}

func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	body, err := m.render(msg)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(m.opts.Host, fmt.Sprintf("%d", m.opts.Port))
	dialer := &net.Dialer{Timeout: m.opts.SendTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mailer: dial smtp: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		// A deadline failure here is non-fatal: the dialer timeout already bounds the call.
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(m.opts.SendTimeout))
	}

	client, err := smtp.NewClient(conn, m.opts.Host)
	if err != nil {
		// The connection is already unusable if the client handshake failed.
		_ = conn.Close()
		return fmt.Errorf("mailer: smtp handshake: %w", err)
	}
	defer func() {
		// Quit failures only affect the already-finished session.
		_ = client.Quit()
	}()

	if m.opts.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: m.opts.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("mailer: starttls: %w", err)
			}
		} else {
			return fmt.Errorf("mailer: smtp server does not advertise STARTTLS")
		}
	}

	if m.opts.Username != "" {
		auth := smtp.PlainAuth("", m.opts.Username, m.opts.Password, m.opts.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mailer: smtp auth: %w", err)
		}
	}

	if err := client.Mail(m.opts.From); err != nil {
		return fmt.Errorf("mailer: smtp mail from: %w", err)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return fmt.Errorf("mailer: smtp rcpt to: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: smtp data: %w", err)
	}
	if _, err := writer.Write(body); err != nil {
		// The write failed; the close error below is redundant detail.
		_ = writer.Close()
		return fmt.Errorf("mailer: smtp write: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("mailer: smtp close data: %w", err)
	}
	return nil
}

func (m *SMTPMailer) Close() error { return nil }

func (m *SMTPMailer) render(msg Message) ([]byte, error) {
	var buf strings.Builder
	mp := multipart.NewWriter(&buf)

	headers := []string{
		"From: " + m.opts.From,
		"To: " + msg.To,
		"Subject: " + sanitizeHeader(msg.Subject),
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=" + mp.Boundary(),
		"",
		"",
	}
	header := strings.Join(headers, "\r\n")

	textPart, err := mp.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/plain; charset=utf-8"},
	})
	if err != nil {
		return nil, fmt.Errorf("mailer: build text part: %w", err)
	}
	if _, err := textPart.Write([]byte(msg.TextBody)); err != nil {
		return nil, fmt.Errorf("mailer: write text part: %w", err)
	}

	htmlPart, err := mp.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/html; charset=utf-8"},
	})
	if err != nil {
		return nil, fmt.Errorf("mailer: build html part: %w", err)
	}
	if _, err := htmlPart.Write([]byte(msg.HTMLBody)); err != nil {
		return nil, fmt.Errorf("mailer: write html part: %w", err)
	}
	if err := mp.Close(); err != nil {
		return nil, fmt.Errorf("mailer: close multipart: %w", err)
	}

	return []byte(header + buf.String()), nil
}

func sanitizeHeader(value string) string {
	replacer := strings.NewReplacer("\r", " ", "\n", " ")
	return replacer.Replace(value)
}
