package frontend

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/mail"
)

// DefaultMailQueueSize is the default of Options.MailQueueSize.
const DefaultMailQueueSize = 256

// mailWorkers is the number of goroutines that send queued mail.
const mailWorkers = 2

// mailQueue sends the mail of the handlers in the background, so that no
// response waits for SMTP: how long a request takes must not tell whether a
// mail went out (whether an account exists). It is a bounded queue served
// by mailWorkers goroutines; a mail that finds the queue full is dropped
// and logged (at most one line per minute). Send errors are logged with the
// recipient quoted; nothing about a mail reaches a response.
//
// The workers start with the first mail and run until close; each Send is
// bounded by the mailer's own timeouts.
type mailQueue struct {
	mailer mail.Mailer
	jobs   chan mail.Message
	start  sync.Once
	// pending counts mails that were queued and not yet sent; wait uses it.
	pending sync.WaitGroup
	// workers counts the running worker goroutines; close waits for them.
	workers sync.WaitGroup

	mu       sync.Mutex // guards closed, inflight, the send into jobs, and the drop logs
	closed   bool       // set by close; jobs is closed then
	inflight int        // mails queued or being sent; close returns at once when zero
	// One log limit per reason, so that one reason cannot hide the other.
	stoppedLog, fullLog dropLog
	now                 func() time.Time
}

// dropLog is the log limit of one reason for dropping mail.
type dropLog struct {
	dropped  int // drops since the last log line
	lastWarn time.Time
}

func newMailQueue(m mail.Mailer, size int, now func() time.Time) *mailQueue {
	if size <= 0 {
		size = DefaultMailQueueSize
	}
	if now == nil {
		now = time.Now
	}
	return &mailQueue{mailer: m, jobs: make(chan mail.Message, size), now: now}
}

// send queues msg and returns at once. A full queue, or a sender that was
// closed, drops msg.
func (q *mailQueue) send(msg mail.Message) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		q.noteDroppedLocked(&q.stoppedLog, msg, "mail sender stopped")
		return
	}
	q.start.Do(func() {
		q.workers.Add(mailWorkers)
		for i := 0; i < mailWorkers; i++ {
			go q.work()
		}
	})
	q.pending.Add(1)
	select {
	case q.jobs <- msg:
		q.inflight++
	default:
		q.pending.Done()
		q.noteDroppedLocked(&q.fullLog, msg, "mail queue full")
	}
}

func (q *mailQueue) work() {
	defer q.workers.Done()
	for msg := range q.jobs {
		q.deliver(msg)
	}
}

// close stops the sender: no new mail is taken, the workers deliver what is
// queued and exit. It waits for that until ctx ends and then returns
// ctx.Err(); the workers go on with the queued mail in the background. When
// no mail is queued or being sent it returns nil at once, whatever the state
// of ctx: there is nothing ctx could cut short, and idle workers exit as soon
// as they see the closed queue. It may be called more than once.
func (q *mailQueue) close(ctx context.Context) error {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.jobs)
	}
	idle := q.inflight == 0
	q.mu.Unlock()
	if idle {
		return nil
	}

	done := make(chan struct{})
	go func() {
		q.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops the background mail sender of the handler: it takes no new
// mail, delivers what is already queued until ctx ends, and lets its
// workers exit. It returns ctx.Err() when ctx ended before the queue was
// empty, and nil when no mail was waiting or being sent, also with a ctx
// that has already ended. Mail that handlers queue after Close is dropped
// and logged. Close may be called more than once; without a Mailer it does
// nothing for mail. It also ends the background check of the audit budget
// (UnauthenticatedAuditRowsPerMinute) and writes the summary row of the
// minute in progress if rows were dropped in it.
//
// A server calls it at shutdown, after the HTTP server stopped taking
// requests. New returns an http.Handler; the method is reached with
//
//	if c, ok := h.(interface{ Close(context.Context) error }); ok {
//		err = c.Close(ctx)
//	}
func (h *frontendHandler) Close(ctx context.Context) error {
	if h.audits != nil {
		h.audits.close()
	}
	if h.mails == nil {
		return nil
	}
	return h.mails.close(ctx)
}

// deliver sends one mail. A panic in the mailer is recovered and logged:
// the worker runs outside any request, so an unrecovered panic would end
// the whole process. The mail counts as done either way.
func (q *mailQueue) deliver(msg mail.Message) {
	defer q.pending.Done()
	// Before pending is released: once wait returns, close sees no mail in
	// flight.
	defer func() {
		q.mu.Lock()
		q.inflight--
		q.mu.Unlock()
	}()
	defer func() {
		if v := recover(); v != nil {
			log.Printf("frontend: mail: panic while sending %q to %q: %v", msg.Subject, msg.To, v)
		}
	}()
	if err := q.mailer.Send(context.Background(), msg); err != nil {
		log.Printf("frontend: mail: send %q to %q: %v", msg.Subject, msg.To, err)
	}
}

// noteDroppedLocked logs a mail dropped for reason, whose log limit is l: at
// most once per minute, with the number dropped since the last line. q.mu
// is held.
func (q *mailQueue) noteDroppedLocked(l *dropLog, msg mail.Message, reason string) {
	l.dropped++
	now := q.now()
	if !l.lastWarn.IsZero() && now.Sub(l.lastWarn) < time.Minute {
		return
	}
	log.Printf("frontend: %s (queue size %d): dropped %d mail(s), the last %q to %q",
		reason, cap(q.jobs), l.dropped, msg.Subject, msg.To)
	l.lastWarn = now
	l.dropped = 0
}

// wait returns when every mail queued so far has been sent or dropped. It is
// for tests, which must not look at the mailer before.
func (q *mailQueue) wait() { q.pending.Wait() }
