package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/audit"
	"github.com/Bazinga0o0/tunnel/internal/server/db/dbtest"
	"github.com/Bazinga0o0/tunnel/internal/server/registry"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

const (
	alphaSecret = "alpha-0123456789abcdef0123456789abcdef"
	betaSecret  = "beta-0123456789abcdef0123456789abcdef0"
	alphaPort   = 15000
	betaPort    = 15001
)

// holderSession is a tunnel session in the registry.
type holderSession struct {
	id     string
	userID int64
	closes atomic.Int32
}

func (s *holderSession) ID() string         { return s.id }
func (s *holderSession) UserIDValue() int64 { return s.userID }
func (s *holderSession) Close() error       { s.closes.Add(1); return nil }
func (s *holderSession) closed() bool       { return s.closes.Load() > 0 }

// holderEnv is the service API of two services, alpha and beta, on a
// test database.
type holderEnv struct {
	pool *pgxpool.Pool
	res  *reservations.Service
	reg  *registry.Registry
	url  string
}

func newHolderEnv(t *testing.T) *holderEnv {
	t.Helper()
	return newHolderEnvApproval(t, false)
}

// newHolderEnvApproval is newHolderEnv with requireApproved for the service
// API, as with auth.signup approval or closed.
func newHolderEnvApproval(t *testing.T, requireApproved bool) *holderEnv {
	t.Helper()
	pool := dbtest.Pool(t)
	t.Cleanup(pool.Close)
	e := &holderEnv{pool: pool, res: reservations.NewService(pool), reg: registry.New()}
	h := NewAPI([]APIService{
		{Name: "alpha", Secret: []byte(alphaSecret), Ports: map[int]bool{alphaPort: true}},
		{Name: "beta", Secret: []byte(betaSecret), Ports: map[int]bool{betaPort: true}},
	}, e.res, users.NewService(pool), requireApproved, e.reg, audit.NewService(pool), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	e.url = srv.URL
	return e
}

// holderAnswer is the body of an answer of the service API.
type holderAnswer struct {
	AccountID      *int64 `json:"account_id"`
	SessionsClosed *int   `json:"sessions_closed"`
	Error          string `json:"error"`
}

// call sends method to the holder of port with secret ("" sends no
// Authorization header) and the JSON body ("" for none).
func (e *holderEnv) call(t *testing.T, method, secret string, port int, body string) (*http.Response, holderAnswer) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.url+"/v1/tcp-ports/"+strconv.Itoa(port)+"/holder", r)
	require.NoError(t, err)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	var a holderAnswer
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &a), "body %q", raw)
	}
	return res, a
}

func (e *holderEnv) owner(t *testing.T, port int) (int64, bool) {
	t.Helper()
	owner, ok, err := e.res.OwnerTCPPort(context.Background(), port)
	require.NoError(t, err)
	return owner, ok
}

// auditRow is a row of the audit log.
type auditRow struct {
	userID   *int64
	action   string
	metadata string
}

func auditRows(t *testing.T, pool *pgxpool.Pool) []auditRow {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT user_id, action, metadata FROM audit_log ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var md []byte
		require.NoError(t, rows.Scan(&r.userID, &r.action, &md))
		r.metadata = string(md)
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func accountBody(id int64) string { return `{"account_id": ` + strconv.FormatInt(id, 10) + `}` }

func TestHolderAPIRejectsWrongSecretAndForeignPort(t *testing.T) {
	e := newHolderEnv(t)
	ctx := context.Background()
	owner := dbtest.InsertUser(t, e.pool, "owner@example.com")
	other := dbtest.InsertUser(t, e.pool, "other@example.com")
	disabled := dbtest.InsertUser(t, e.pool, "disabled@example.com")
	_, err := e.pool.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, disabled)
	require.NoError(t, err)
	require.NoError(t, e.res.GrantTCPPort(ctx, betaPort, owner))
	holder := &holderSession{id: "holder", userID: owner}
	require.NoError(t, e.reg.RegisterTCP(betaPort, holder))

	for _, secret := range []string{"", alphaSecret + "x", betaSecret[:len(betaSecret)-1], "beta"} {
		for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodGet} {
			res, _ := e.call(t, method, secret, betaPort, accountBody(other))
			assert.Equal(t, http.StatusUnauthorized, res.StatusCode, "%s with secret %q", method, secret)
			assert.Equal(t, "Bearer", res.Header.Get("WWW-Authenticate"))
		}
	}
	// alpha's secret is valid, but the port is beta's.
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodGet} {
		res, _ := e.call(t, method, alphaSecret, betaPort, accountBody(other))
		assert.Equal(t, http.StatusForbidden, res.StatusCode, method)
	}
	// An account that is unknown or disabled cannot become the holder.
	for _, id := range []int64{disabled, 999999} {
		res, _ := e.call(t, http.MethodPut, betaSecret, betaPort, accountBody(id))
		assert.Equal(t, http.StatusNotFound, res.StatusCode, "account %d", id)
	}

	got, ok := e.owner(t, betaPort)
	assert.True(t, ok)
	assert.Equal(t, owner, got, "the reservation is unchanged")
	assert.False(t, holder.closed(), "the holding session is left alone")
	_, ok = e.reg.LookupTCP(betaPort)
	assert.True(t, ok)
	assert.Empty(t, auditRows(t, e.pool))
}

// With auth.signup approval or closed, an account that waits for approval
// cannot become the holder: it gets 404 like an unknown or disabled account,
// and the reservation and the holding session stay as they are. A holder
// reservation would also count as "in use" and get the account approved at
// the next start (users.ApproveExisting). Once approved, it can become the
// holder. (In open mode approval does not matter: the other tests set
// accounts that were never approved as holders.)
func TestHolderPutForAWaitingAccountInApprovalMode(t *testing.T) {
	e := newHolderEnvApproval(t, true)
	ctx := context.Background()
	owner := dbtest.InsertUser(t, e.pool, "owner@example.com")
	waiting := dbtest.InsertUser(t, e.pool, "waiting@example.com")
	require.NoError(t, e.res.GrantTCPPort(ctx, alphaPort, owner))
	holder := &holderSession{id: "holder", userID: owner}
	require.NoError(t, e.reg.RegisterTCP(alphaPort, holder))

	res, ans := e.call(t, http.MethodPut, alphaSecret, alphaPort, accountBody(waiting))
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Equal(t, "unknown account", ans.Error)
	got, ok := e.owner(t, alphaPort)
	assert.True(t, ok)
	assert.Equal(t, owner, got, "the reservation is unchanged")
	assert.False(t, holder.closed(), "no session is closed")
	_, ok = e.reg.LookupTCP(alphaPort)
	assert.True(t, ok)
	assert.Empty(t, auditRows(t, e.pool))

	require.NoError(t, users.NewService(e.pool).Approve(ctx, waiting))
	res, ans = e.call(t, http.MethodPut, alphaSecret, alphaPort, accountBody(waiting))
	require.Equal(t, http.StatusOK, res.StatusCode, ans.Error)
	require.NotNil(t, ans.AccountID)
	assert.Equal(t, waiting, *ans.AccountID)
	got, ok = e.owner(t, alphaPort)
	assert.True(t, ok)
	assert.Equal(t, waiting, got)
	assert.True(t, holder.closed(), "the old holder's session is closed")
}

// A new holder closes the session that holds the port, also
// when it is a session of the new holder's own account (a second PC).
func TestHolderPutTransfersAndClosesSessions(t *testing.T) {
	e := newHolderEnv(t)
	ctx := context.Background()
	a := dbtest.InsertUser(t, e.pool, "a@example.com")
	b := dbtest.InsertUser(t, e.pool, "b@example.com")
	require.NoError(t, e.res.GrantTCPPort(ctx, alphaPort, a))
	idleA := &holderSession{id: "idle-a", userID: a}
	require.NoError(t, e.reg.AddSession(idleA, registry.SessionLimits{}))
	holderB := &holderSession{id: "holder-b", userID: b}
	require.NoError(t, e.reg.RegisterTCP(alphaPort, holderB))

	res, ans := e.call(t, http.MethodPut, alphaSecret, alphaPort, accountBody(b))
	require.Equal(t, http.StatusOK, res.StatusCode, ans.Error)
	require.NotNil(t, ans.AccountID)
	assert.Equal(t, b, *ans.AccountID)
	require.NotNil(t, ans.SessionsClosed)
	assert.Equal(t, 1, *ans.SessionsClosed)

	got, ok := e.owner(t, alphaPort)
	assert.True(t, ok)
	assert.Equal(t, b, got)
	assert.True(t, holderB.closed(), "the holding session is closed whoever's it is")
	assert.False(t, idleA.closed(), "a session that does not hold the port stays")
	_, ok = e.reg.LookupTCP(alphaPort)
	assert.False(t, ok)

	res, ans = e.call(t, http.MethodGet, alphaSecret, alphaPort, "")
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NotNil(t, ans.AccountID)
	assert.Equal(t, b, *ans.AccountID)

	rows := auditRows(t, e.pool)
	require.Len(t, rows, 1)
	assert.Nil(t, rows[0].userID)
	assert.Equal(t, "service.port.holder.set", rows[0].action)
	var md map[string]any
	require.NoError(t, json.Unmarshal([]byte(rows[0].metadata), &md))
	assert.Equal(t, map[string]any{
		"service": "alpha", "port": float64(alphaPort), "account_id": float64(b),
		"previous_account_id": float64(a), "sessions_closed": float64(1),
	}, md)
	assert.NotContains(t, rows[0].metadata, alphaSecret)
}

func TestHolderDeleteRevokesAndCloses(t *testing.T) {
	e := newHolderEnv(t)
	ctx := context.Background()
	a := dbtest.InsertUser(t, e.pool, "a@example.com")
	require.NoError(t, e.res.GrantTCPPort(ctx, alphaPort, a))
	holder := &holderSession{id: "holder", userID: a}
	require.NoError(t, e.reg.RegisterTCP(alphaPort, holder))

	res, ans := e.call(t, http.MethodDelete, alphaSecret, alphaPort, "")
	require.Equal(t, http.StatusOK, res.StatusCode, ans.Error)
	require.NotNil(t, ans.SessionsClosed)
	assert.Equal(t, 1, *ans.SessionsClosed)
	_, ok := e.owner(t, alphaPort)
	assert.False(t, ok)
	assert.True(t, holder.closed())
	_, ok = e.reg.LookupTCP(alphaPort)
	assert.False(t, ok)

	res, _ = e.call(t, http.MethodGet, alphaSecret, alphaPort, "")
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	// Nothing reserved: still 200.
	res, ans = e.call(t, http.MethodDelete, alphaSecret, alphaPort, "")
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NotNil(t, ans.SessionsClosed)
	assert.Zero(t, *ans.SessionsClosed)

	rows := auditRows(t, e.pool)
	require.Len(t, rows, 1, "the DELETE that changed nothing writes no row")
	assert.Equal(t, "service.port.holder.clear", rows[0].action)
	var md map[string]any
	require.NoError(t, json.Unmarshal([]byte(rows[0].metadata), &md))
	assert.Equal(t, float64(a), md["previous_account_id"])
	assert.Equal(t, float64(1), md["sessions_closed"])
}

// holderAPI is the service API of alpha on e's database, with res in place
// of the reservations, and its log.
func (e *holderEnv) holderAPI(res PortReservations) (http.Handler, *strings.Builder) {
	var log strings.Builder
	h := NewAPI([]APIService{
		{Name: "alpha", Secret: []byte(alphaSecret), Ports: map[int]bool{alphaPort: true}},
	}, res, users.NewService(e.pool), false, e.reg, audit.NewService(e.pool), slog.New(slog.NewTextHandler(&log, nil)))
	return h, &log
}

// serveWith calls h directly with method on alphaPort under ctx, so that the
// test decides when the request context ends.
func serveWith(ctx context.Context, h http.Handler, method, body string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(ctx, method, "/v1/tcp-ports/"+strconv.Itoa(alphaPort)+"/holder", r)
	req.Header.Set("Authorization", "Bearer "+alphaSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// goneDuringWrite ends the request when the write begins, as a client that
// goes away while the database works, and then writes with the context the
// handler passed.
type goneDuringWrite struct {
	*reservations.Service
	cancel context.CancelFunc
}

func (g goneDuringWrite) TransferTCPPort(ctx context.Context, port int, userID int64) (int64, error) {
	g.cancel()
	return g.Service.TransferTCPPort(ctx, port, userID)
}

func (g goneDuringWrite) RevokeTCPPortReturningOwner(ctx context.Context, port int) (int64, bool, error) {
	g.cancel()
	return g.Service.RevokeTCPPortReturningOwner(ctx, port)
}

// A change does not end with the request. A
// client that goes away during the write leaves a complete change behind:
// reservation, closed session and audit row.
func TestHolderChangeOutlivesTheRequest(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			e := newHolderEnv(t)
			a := dbtest.InsertUser(t, e.pool, "a@example.com")
			b := dbtest.InsertUser(t, e.pool, "b@example.com")
			require.NoError(t, e.res.GrantTCPPort(context.Background(), alphaPort, a))
			holder := &holderSession{id: "holder-a", userID: a}
			require.NoError(t, e.reg.RegisterTCP(alphaPort, holder))

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h, log := e.holderAPI(goneDuringWrite{Service: e.res, cancel: cancel})
			body := ""
			if method == http.MethodPut {
				body = accountBody(b)
			}
			rec := serveWith(ctx, h, method, body)
			require.Error(t, ctx.Err(), "the request ended during the write")

			assert.Equal(t, http.StatusOK, rec.Code, "body %s; log %s", rec.Body, log)
			owner, reserved := e.owner(t, alphaPort)
			if method == http.MethodPut {
				assert.True(t, reserved)
				assert.Equal(t, b, owner, "the transfer went through")
			} else {
				assert.False(t, reserved, "the revoke went through")
			}
			assert.True(t, holder.closed(), "the old holder lost the port with the reservation")
			_, held := e.reg.LookupTCP(alphaPort)
			assert.False(t, held)
			assert.Len(t, auditRows(t, e.pool), 1, "the change is in the audit log")
		})
	}
}

// errOutcomeUnknown is what a write returns when the connection breaks
// after COMMIT reached the database: the change may have been made.
var errOutcomeUnknown = errors.New("commit: connection reset")

// writeThenFail makes the change and then reports an error.
type writeThenFail struct{ *reservations.Service }

func (w writeThenFail) TransferTCPPort(ctx context.Context, port int, userID int64) (int64, error) {
	if _, err := w.Service.TransferTCPPort(ctx, port, userID); err != nil {
		return 0, err
	}
	return 0, errOutcomeUnknown
}

func (w writeThenFail) RevokeTCPPortReturningOwner(ctx context.Context, port int) (int64, bool, error) {
	if _, _, err := w.Service.RevokeTCPPortReturningOwner(ctx, port); err != nil {
		return 0, false, err
	}
	return 0, false, errOutcomeUnknown
}

// After a failed write the server cannot know
// whether the change was made, so the session that holds the port is closed
// all the same. Closing is safe: the right holder connects again.
func TestHolderWriteErrorClosesTheHoldingSession(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			e := newHolderEnv(t)
			a := dbtest.InsertUser(t, e.pool, "a@example.com")
			b := dbtest.InsertUser(t, e.pool, "b@example.com")
			require.NoError(t, e.res.GrantTCPPort(context.Background(), alphaPort, a))
			holder := &holderSession{id: "holder-a", userID: a}
			require.NoError(t, e.reg.RegisterTCP(alphaPort, holder))

			h, log := e.holderAPI(writeThenFail{e.res})
			body := ""
			if method == http.MethodPut {
				body = accountBody(b)
			}
			rec := serveWith(context.Background(), h, method, body)

			assert.Equal(t, http.StatusInternalServerError, rec.Code)
			assert.JSONEq(t, `{"error": "internal error"}`, rec.Body.String())
			assert.True(t, holder.closed(), "the holding session is closed although the write failed")
			_, held := e.reg.LookupTCP(alphaPort)
			assert.False(t, held)
			assert.Contains(t, log.String(), "sessions_closed=1", "the log says a session was closed")
			assert.Contains(t, log.String(), errOutcomeUnknown.Error())
		})
	}
}

// unknownAccount reports an account deleted between the lookup and the
// transfer; the transfer rolled back.
type unknownAccount struct{ *reservations.Service }

func (unknownAccount) TransferTCPPort(context.Context, int, int64) (int64, error) {
	return 0, reservations.ErrUnknownUser
}

// An account deleted since the lookup is the one write error that leaves
// the port as it was: the holder keeps it.
func TestHolderPutForADeletedAccountKeepsTheHolder(t *testing.T) {
	e := newHolderEnv(t)
	a := dbtest.InsertUser(t, e.pool, "a@example.com")
	b := dbtest.InsertUser(t, e.pool, "b@example.com")
	require.NoError(t, e.res.GrantTCPPort(context.Background(), alphaPort, a))
	holder := &holderSession{id: "holder-a", userID: a}
	require.NoError(t, e.reg.RegisterTCP(alphaPort, holder))

	h, _ := e.holderAPI(unknownAccount{e.res})
	rec := serveWith(context.Background(), h, http.MethodPut, accountBody(b))

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.False(t, holder.closed())
	owner, reserved := e.owner(t, alphaPort)
	assert.True(t, reserved)
	assert.Equal(t, a, owner)
	assert.Empty(t, auditRows(t, e.pool))
}
