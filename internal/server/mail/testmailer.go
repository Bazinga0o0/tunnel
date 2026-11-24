package mail

import (
	"context"
	"sync"
)

// TestMailer collects every message sent. Safe for concurrent use.
// Intended for integration tests; build-tagged into all builds since the
// type is small and pulling in a build tag complicates imports.
type TestMailer struct {
	mu       sync.Mutex
	messages []Message
}

// NewTestMailer returns an empty TestMailer.
func NewTestMailer() *TestMailer { return &TestMailer{} }

// Send records msg and always succeeds.
func (t *TestMailer) Send(_ context.Context, msg Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.messages = append(t.messages, msg)
	return nil
}

// Sent returns a snapshot copy of captured messages.
func (t *TestMailer) Sent() []Message {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Message, len(t.messages))
	copy(out, t.messages)
	return out
}

// Reset clears captured messages.
func (t *TestMailer) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.messages = nil
}
