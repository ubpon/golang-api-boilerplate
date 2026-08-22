package mailer

import "context"

type Message struct {
	To        string
	Subject   string
	TextBody  string
	HTMLBody  string
	Template  string
	MessageID string
}

type Mailer interface {
	Send(ctx context.Context, msg Message) error
	Close() error
}
