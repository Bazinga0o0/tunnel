package frontend

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/mail"
)

// waitLimit is how long a test waits for something that is expected to
// happen at once. It only bounds a test that went wrong.
const waitLimit = 10 * time.Second

// blockingMailer holds every Send until the test releases it. Each Send
// announces its message on entered first.
type blockingMailer struct {
	entered chan mail.Message
	release chan struct{}
	once    sync.Once

	mu   sync.Mutex
	sent []mail.Message
}

// newBlockingMailer returns a mailer that holds every Send until unblock.
// A test that builds a handler with it releases it at a cleanup registered
// after the handler's own (see newBlockingStack), so that the release runs
// first.
func newBlockingMailer() *blockingMailer {
	return &blockingMailer{entered: make(chan mail.Message, 64), release: make(chan struct{})}
}

// newBlockingStack builds a stack with mail whose mailer is a
// blockingMailer; mutate changes the options after that. The release of the
// mailer is registered after the stack's cleanup, which closes the mail
// sender, and therefore runs before it: a test that fails while the mailer
// holds mail does not make that Close wait for its deadline.
func newBlockingStack(t *testing.T, mutate ...func(*Options, *stack)) (*stack, *blockingMailer) {
	t.Helper()
	m := newBlockingMailer()
	all := append([]func(*Options, *stack){withMail, func(o *Options, _ *stack) { o.Mailer = m }}, mutate...)
	s := newStack(t, all...)
	t.Cleanup(m.unblock)
	return s, m
}

func (m *blockingMailer) unblock() { m.once.Do(func() { close(m.release) }) }

func (m *blockingMailer) Send(_ context.Context, msg mail.Message) error {
	m.entered <- msg
	<-m.release
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *blockingMailer) sentTo() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var to []string
	for _, msg := range m.sent {
		to = append(to, msg.To)
	}
	return to
}

// waitEntered returns the next message that reached Send.
func (m *blockingMailer) waitEntered(t *testing.T) mail.Message {
	t.Helper()
	select {
	case msg := <-m.entered:
		return msg
	case <-time.After(waitLimit):
		t.Fatalf("no mail reached the mailer within %v", waitLimit)
		return mail.Message{}
	}
}

// lockedBuffer is a log destination that goroutines may share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	b := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return b
}

// serveWithin serves req in a goroutine and fails the test when no answer
// comes within waitLimit: a handler that waits for the (blocked) mailer
// never answers.
func serveWithin(t *testing.T, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		done <- w
	}()
	select {
	case w := <-done:
		return w
	case <-time.After(waitLimit):
		t.Fatalf("no answer within %v: the handler waits for the mailer", waitLimit)
		return nil
	}
}

func TestHandlersDoNotWaitForTheMailer(t *testing.T) {
	s, m := newBlockingStack(t)
	s.createUser(t, "waiting@example.com", "pw12345678")

	// Password reset for an existing account.
	req := newFormPost(t, s.h, nil, "/forgot-password", url.Values{"email": {"Waiting@Example.com"}}, "198.51.100.140:1")
	w := serveWithin(t, s.h, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "If an account with that email exists")
	msg := m.waitEntered(t)
	assert.Equal(t, "waiting@example.com", msg.To, "to the stored address")
	assert.Contains(t, msg.Subject, "Reset")

	// Sign-up of a new address (verification mail) and of a taken one
	// (notice to the owner). The first mail occupies the second worker; the
	// notice waits in the queue while both workers are held.
	for _, email := range []string{"fresh@example.com", "waiting@example.com"} {
		req = newFormPost(t, s.h, nil, "/signup", url.Values{"email": {email}, "password": {"pw12345678"}}, "198.51.100.141:1")
		w = serveWithin(t, s.h, req)
		require.Equal(t, http.StatusSeeOther, w.Code, email)
	}
	assert.Equal(t, "fresh@example.com", m.waitEntered(t).To)

	m.unblock()
	drainMail(t, s.h)
	assert.ElementsMatch(t, []string{"waiting@example.com", "fresh@example.com", "waiting@example.com"}, m.sentTo())
}

func TestMailQueueDropsMailWhenFull(t *testing.T) {
	s, m := newBlockingStack(t, func(o *Options, _ *stack) { o.MailQueueSize = 1 })
	logged := captureLog(t)
	n := mailWorkers + 2 // one per worker, one in the queue, one too many
	for i := 0; i < n; i++ {
		s.createUser(t, fmt.Sprintf("queued%d@example.com", i), "pw12345678")
	}
	forgot := func(i int) {
		t.Helper()
		req := newFormPost(t, s.h, nil, "/forgot-password",
			url.Values{"email": {fmt.Sprintf("queued%d@example.com", i)}}, fmt.Sprintf("198.51.100.%d:1", 150+i))
		w := serveWithin(t, s.h, req)
		require.Equal(t, http.StatusOK, w.Code, "request %d", i)
	}
	// Occupy every worker; each holds one mail in the blocked mailer.
	for i := 0; i < mailWorkers; i++ {
		forgot(i)
		m.waitEntered(t)
	}
	forgot(mailWorkers)     // waits in the queue
	forgot(mailWorkers + 1) // finds the queue full
	assert.Contains(t, logged.String(), "mail queue full")
	assert.Contains(t, logged.String(), fmt.Sprintf("%q", fmt.Sprintf("queued%d@example.com", mailWorkers+1)))

	m.unblock()
	drainMail(t, s.h)
	sent := m.sentTo()
	assert.Len(t, sent, n-1)
	assert.NotContains(t, sent, fmt.Sprintf("queued%d@example.com", mailWorkers+1), "the dropped mail is not sent later")
}

// panickyMailer panics on its first panics messages and records the later
// ones.
type panickyMailer struct {
	panics int

	mu    sync.Mutex
	calls int
	sent  []mail.Message
}

func (m *panickyMailer) Send(_ context.Context, msg mail.Message) error {
	m.mu.Lock()
	m.calls++
	panicNow := m.calls <= m.panics
	if !panicNow {
		m.sent = append(m.sent, msg)
	}
	m.mu.Unlock()
	if panicNow {
		panic("smtp library blew up")
	}
	return nil
}

func TestMailerPanicDoesNotStopTheSender(t *testing.T) {
	// One panic more than there are workers: the mail after them goes out
	// only if a worker serves on after a panic of its own.
	panics := mailWorkers + 1
	m := &panickyMailer{panics: panics}
	s := newStack(t, withMail, func(o *Options, _ *stack) { o.Mailer = m })
	logged := captureLog(t)
	email := func(i int) string { return fmt.Sprintf("panic%d@example.com", i) }
	forgot := func(i int) {
		t.Helper()
		w := postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {email(i)}}, fmt.Sprintf("198.51.100.%d:1", 180+i))
		require.Equal(t, http.StatusOK, w.Code, "request %d", i)
	}
	for i := 0; i <= panics; i++ {
		s.createUser(t, email(i), "pw12345678")
	}

	// Each of these mails makes the mailer panic. The process survives, the
	// mail counts as done (the drain in postFormFrom returns), and it is
	// logged.
	for i := 0; i < panics; i++ {
		forgot(i)
	}
	assert.Equal(t, panics, strings.Count(logged.String(), "smtp library blew up"))
	assert.Contains(t, logged.String(), "panic while sending")
	assert.Contains(t, logged.String(), fmt.Sprintf("%q", email(0)))

	// The sender keeps serving.
	forgot(panics)
	m.mu.Lock()
	defer m.mu.Unlock()
	require.Len(t, m.sent, 1)
	assert.Equal(t, email(panics), m.sent[0].To)
}

func TestCloseDeliversQueuedMailAndStopsTheSender(t *testing.T) {
	s, m := newBlockingStack(t)
	fh := s.h.(*frontendHandler)
	n := mailWorkers + 1 // one per worker and one in the queue
	for i := 0; i <= n; i++ {
		s.createUser(t, fmt.Sprintf("closing%d@example.com", i), "pw12345678")
	}
	forgot := func(i int) {
		t.Helper()
		req := newFormPost(t, s.h, nil, "/forgot-password",
			url.Values{"email": {fmt.Sprintf("closing%d@example.com", i)}}, fmt.Sprintf("198.51.100.%d:1", 190+i))
		require.Equal(t, http.StatusOK, serveWithin(t, s.h, req).Code, "request %d", i)
	}
	for i := 0; i < mailWorkers; i++ {
		forgot(i)
		m.waitEntered(t)
	}
	forgot(mailWorkers) // waits in the queue

	// With a context that has ended, Close stops the intake and reports
	// that the queue is not empty yet.
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, fh.Close(ended), context.Canceled)

	// Mail queued after Close is dropped, without a panic.
	logged := captureLog(t)
	forgot(n)
	assert.Contains(t, logged.String(), "mail sender stopped")

	// Once the mailer works again, Close returns when the queue is empty and
	// the workers have exited.
	m.unblock()
	ctx, cancelWait := context.WithTimeout(context.Background(), waitLimit)
	defer cancelWait()
	require.NoError(t, fh.Close(ctx))
	sent := m.sentTo()
	assert.Len(t, sent, n, "everything queued before Close was delivered")
	assert.NotContains(t, sent, fmt.Sprintf("closing%d@example.com", n))
}

func TestCloseBeforeAnyMail(t *testing.T) {
	s := newStack(t, withMail)
	s.createUser(t, "late@example.com", "pw12345678")
	require.NoError(t, s.h.(*frontendHandler).Close(context.Background()))
	logged := captureLog(t)
	w := postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"late@example.com"}}, "198.51.100.199:1")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, s.mailer.Sent())
	assert.Contains(t, logged.String(), "mail sender stopped")
	require.NoError(t, s.h.(*frontendHandler).Close(context.Background()), "a second Close is fine")
	require.NoError(t, New(Options{CSRFKey: testCSRFKey}).(*frontendHandler).Close(context.Background()),
		"nothing to close without a mailer")
}

// Close with a context that has already ended reports an error only while
// mail is waiting or being sent. An idle sender, whose workers were never
// started or have delivered everything, closes without error. (The answer
// must not depend on which of two ready channels a select picks, so each
// case runs many times.)
func TestCloseOfAnIdleSenderSucceedsWithAnEndedContext(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	const attempts = 50

	t.Run("no mail was ever queued", func(t *testing.T) {
		for i := 0; i < attempts; i++ {
			h := New(Options{CSRFKey: testCSRFKey, Mailer: mail.NewTestMailer()})
			require.NoError(t, h.(*frontendHandler).Close(ended), "attempt %d", i)
		}
	})

	t.Run("everything queued was delivered", func(t *testing.T) {
		for i := 0; i < attempts; i++ {
			m := mail.NewTestMailer()
			fh := New(Options{CSRFKey: testCSRFKey, Mailer: m}).(*frontendHandler)
			fh.mails.send(mail.Message{To: "idle@example.com", Subject: "s", TextBody: "t"})
			fh.mails.wait()
			require.Len(t, m.Sent(), 1)
			require.NoError(t, fh.Close(ended), "attempt %d", i)
		}
	})
}

// The two reasons for dropping a mail are logged under limits of their own:
// a full queue does not hide that the sender has stopped, or the reverse.
func TestDropReasonsAreLoggedSeparately(t *testing.T) {
	m := newBlockingMailer()
	clock := newFakeClock()
	q := newMailQueue(m, 1, clock.Now)
	logged := captureLog(t)
	defer func() {
		m.unblock()
		require.NoError(t, q.close(context.Background()))
	}()

	for i := 0; i < mailWorkers; i++ {
		q.send(mail.Message{To: fmt.Sprintf("held%d@example.com", i)})
		m.waitEntered(t)
	}
	q.send(mail.Message{To: "queued@example.com"})
	q.send(mail.Message{To: "full@example.com"})
	assert.Equal(t, 1, strings.Count(logged.String(), "mail queue full"))

	ended, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, q.close(ended), context.Canceled, "mail is still waiting")
	q.send(mail.Message{To: "late@example.com"})
	assert.Equal(t, 1, strings.Count(logged.String(), "mail sender stopped"), "logged within the minute of the other reason")
	assert.Contains(t, logged.String(), `"late@example.com"`)

	// Within the minute each reason stays quiet, after it each logs again
	// with the number dropped in between.
	q.send(mail.Message{To: "late2@example.com"})
	assert.Equal(t, 1, strings.Count(logged.String(), "mail sender stopped"))
	clock.Advance(time.Minute)
	q.send(mail.Message{To: "late3@example.com"})
	assert.Equal(t, 2, strings.Count(logged.String(), "mail sender stopped"))
	assert.Contains(t, logged.String(), "dropped 2 mail(s)")
}

func TestMailQueueSizeFromOptions(t *testing.T) {
	queueCap := func(o Options) int {
		o.CSRFKey = testCSRFKey
		o.Mailer = mail.NewTestMailer()
		h := New(o)
		closeAtCleanup(t, h)
		fh := h.(*frontendHandler)
		require.NotNil(t, fh.mails)
		return cap(fh.mails.jobs)
	}
	assert.Equal(t, 256, queueCap(Options{}))
	assert.Equal(t, 256, queueCap(Options{MailQueueSize: -5}))
	assert.Equal(t, 7, queueCap(Options{MailQueueSize: 7}))
	assert.Nil(t, New(Options{CSRFKey: testCSRFKey}).(*frontendHandler).mails, "no queue without a mailer")
}

func TestStoredAddressBudgetIsSilent(t *testing.T) {
	// The key function of this test keeps the letter case, so the spellings
	// below get keys of their own while the database matches all of them to
	// one account (citext). In production that takes letters which Go and
	// the database lower-case differently.
	s := newStack(t, withMail, func(o *Options, _ *stack) {
		o.accountKeyOf = func(email string) string { return strings.TrimSpace(email) }
	})
	s.createUser(t, "victim@example.com", "pw12345678")
	forgot := func(i int, email string) *httptest.ResponseRecorder {
		return postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {email}}, fmt.Sprintf("198.51.100.%d:1", 170+i))
	}
	resetRows := func() int {
		var n int
		require.NoError(t, s.pool.QueryRow(context.Background(), `SELECT count(*) FROM password_resets`).Scan(&n))
		return n
	}

	// Each spelling is within its own (typed) budget; the account's budget
	// of 3 is used up by the first three.
	for i, variant := range []string{"Victim@example.com", "vIctim@example.com", "viCtim@example.com", "vicTim@example.com"} {
		w := forgot(i, variant)
		require.Equal(t, http.StatusOK, w.Code, variant)
	}
	require.Len(t, s.mailer.Sent(), 3)
	assert.Equal(t, 3, resetRows(), "no token over the account's budget")

	// The stored spelling has used none of its own typed budget: the answer
	// is the usual one, not a 429 that only an existing account would get.
	w := forgot(10, "victim@example.com")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Retry-After"))
	assert.Equal(t, withoutNonce(forgot(11, "ghost@example.com").Body.String()), withoutNonce(w.Body.String()),
		"same page as for an unknown address")
	assert.Len(t, s.mailer.Sent(), 3, "still no mail")
	assert.Equal(t, 3, resetRows(), "still no token")
}

func TestResetIssueFailureIsAuditedAndGivesTheBudgetBack(t *testing.T) {
	s := newStack(t, withMail, withAudit)
	s.createUser(t, "unlucky@example.com", "pw12345678")
	ctx := context.Background()
	// Make the insert of the reset token fail. The trigger name carries the
	// prefix dbtest.Pool removes, should this test be killed before its
	// cleanup runs.
	const name = "dbtest_fail_delete_frontend_reset_insert"
	_, err := s.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'injected failure'; END $$`)
	require.NoError(t, err)
	_, err = s.pool.Exec(ctx, `CREATE TRIGGER `+name+` BEFORE INSERT ON password_resets
		FOR EACH STATEMENT EXECUTE FUNCTION `+name+`()`)
	require.NoError(t, err)
	undo := func() {
		_, _ = s.pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+name+` ON password_resets`)
		_, _ = s.pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+name+`()`)
	}
	t.Cleanup(undo)
	logged := captureLog(t)

	w := postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"unlucky@example.com"}}, "198.51.100.200:1")
	assert.Contains(t, logged.String(), "frontend: forgot password: issue reset")
	require.Equal(t, http.StatusOK, w.Code)
	rows := s.auditRows(t)
	require.Len(t, rows, 1, "one row whatever happens")
	assert.Nil(t, rows[0].UserID)
	assert.Empty(t, rows[0].Metadata)
	assert.Zero(t, limitersOf(t, s.h).resetStored.count(accountKey("unlucky@example.com")), "the budget slot is given back")
	assert.Empty(t, s.mailer.Sent())

	// With the database working again the account gets its link.
	undo()
	w = postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"unlucky@example.com"}}, "198.51.100.201:1")
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, s.mailer.Sent(), 1)
}

// A disabled account gets no reset link, like an unknown address. The
// stored-address budget counts issued links, so its slot goes back, and the
// page cannot be told apart from the one for an address without an account.
func TestResetForADisabledAccountGivesTheBudgetBack(t *testing.T) {
	s := newStack(t, withMail)
	id := s.createUser(t, "disabled@example.com", "pw12345678")
	require.NoError(t, s.users.Disable(context.Background(), nil, id))

	w := postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"disabled@example.com"}}, "198.51.100.210:1")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Zero(t, limitersOf(t, s.h).resetStored.count(accountKey("disabled@example.com")), "the budget slot is given back")
	assert.Empty(t, s.mailer.Sent(), "no mail for a disabled account")

	unknown := postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"nobody-here@example.com"}}, "198.51.100.211:1")
	require.Equal(t, http.StatusOK, unknown.Code)
	assert.Equal(t, withoutNonce(unknown.Body.String()), withoutNonce(w.Body.String()), "same page as for an unknown address")
}

func TestResetRequestIsAuditedForUnknownAddressesToo(t *testing.T) {
	s := newStack(t, withMail, withAudit)
	w := postFormFrom(t, s.h, nil, "/forgot-password", url.Values{"email": {"nobody@example.com"}}, "198.51.100.160:1")
	require.Equal(t, http.StatusOK, w.Code)
	rows := s.auditRows(t)
	require.Len(t, rows, 1, "both paths write to the database")
	assert.Equal(t, "auth.password.reset.request", rows[0].Action)
	assert.Nil(t, rows[0].UserID)
	assert.NotContains(t, rows[0].Metadata, "target_user_id")
	assert.NotContains(t, fmt.Sprint(rows[0].Metadata), "nobody", "the typed address is not stored")
	assert.Empty(t, s.mailer.Sent())
}

// nonceAttr matches the per-request CSP nonce in a page.
var nonceAttr = regexp.MustCompile(`nonce="[^"]*"`)

// withoutNonce blanks the CSP nonce, the one part of a page that differs on
// every request.
func withoutNonce(page string) string { return nonceAttr.ReplaceAllString(page, `nonce=""`) }
