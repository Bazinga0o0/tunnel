package frontend

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Bazinga0o0/tunnel/internal/server/auth"
)

// tryAgainAfter is the Retry-After hint sent with a 503: the time a password
// hash waits for a free slot by default (auth.DefaultHashWait).
const tryAgainAfter = auth.DefaultHashWait

// Texts for a failed request. They never contain the error itself; the
// error goes to the server log.
const (
	msgTryAgain = "The server is busy. Please try again in a moment."
	msgInternal = "Something went wrong. Please try again later."
)

// PostgreSQL error codes of failures that go away when the transaction is
// simply run again.
const (
	pgSerializationFailure = "40001"
	pgDeadlockDetected     = "40P01"
)

// isTryAgain reports whether err is a temporary condition that the same
// request may not meet when repeated: no free slot for a password hash
// (auth.ErrBusy), or a transaction that the database aborted because of a
// deadlock or a serialisation conflict.
func isTryAgain(err error) bool {
	if errors.Is(err, auth.ErrBusy) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == pgSerializationFailure || pgErr.Code == pgDeadlockDetected
	}
	return false
}

// setRetryAfter sets the Retry-After header to d, in whole seconds rounded
// up, at least 1.
func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	secs := int64((d + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
}

// serviceFailureLog limits the log lines of serviceFailure: such failures
// can come at request rate (a client that closes its connections makes every
// login undecided), so a burst writes its first line and the next line
// counts the ones held back; a failure because the client went away is not
// logged at all.
var serviceFailureLog = newLimitedErrorLog("request failures")

// serviceFailure logs err (prefixed with op, through serviceFailureLog) and
// returns the status and the text with which to answer it: 503 with a
// Retry-After header when the request may succeed if repeated (see
// isTryAgain), 500 otherwise. Callers render the text in their page or
// fragment.
func serviceFailure(w http.ResponseWriter, op string, err error) (status int, msg string) {
	serviceFailureLog.printf(err, "frontend: %s: %v", op, err)
	return failureAnswer(w, err)
}

// failureAnswer is serviceFailure without the log line, for callers that
// log err themselves (through a limited log).
func failureAnswer(w http.ResponseWriter, err error) (status int, msg string) {
	if isTryAgain(err) {
		setRetryAfter(w, tryAgainAfter)
		return http.StatusServiceUnavailable, msgTryAgain
	}
	return http.StatusInternalServerError, msgInternal
}

// serverError answers err as plain text, see serviceFailure.
func serverError(w http.ResponseWriter, op string, err error) {
	status, msg := serviceFailure(w, op, err)
	http.Error(w, msg, status)
}
