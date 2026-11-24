// Package mail abstracts sending transactional email.
package mail

import "context"

// Message is a single transactional email.
type Message struct {
	To       string
	Subject  string
	TextBody string
	HTMLBody string // optional
}

// Mailer sends transactional email.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}
