package mail

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestMailerCaptures(t *testing.T) {
	m := NewTestMailer()
	require.NoError(t, m.Send(context.Background(), Message{
		To: "a@b.example.com", Subject: "hi", TextBody: "hello",
	}))
	sent := m.Sent()
	require.Len(t, sent, 1)
	assert.Equal(t, "a@b.example.com", sent[0].To)
	assert.Equal(t, "hi", sent[0].Subject)
}

func TestTestMailerReset(t *testing.T) {
	m := NewTestMailer()
	_ = m.Send(context.Background(), Message{To: "x@y.example.com"})
	require.Len(t, m.Sent(), 1)
	m.Reset()
	assert.Empty(t, m.Sent())
}

func TestTestMailerSnapshotIsDetached(t *testing.T) {
	m := NewTestMailer()
	_ = m.Send(context.Background(), Message{To: "x@y.example.com"})
	snap := m.Sent()
	snap[0].To = "mutated@example.com"
	assert.Equal(t, "x@y.example.com", m.Sent()[0].To)
}
