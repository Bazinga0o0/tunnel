package frontend

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flushAuditBudget runs the background check of the audit budget by hand:
// it writes the summary of a minute that has turned.
func flushAuditBudget(t *testing.T, h http.Handler) {
	t.Helper()
	fh, ok := h.(*frontendHandler)
	require.True(t, ok)
	require.NotNil(t, fh.audits, "the handler has an audit budget")
	fh.audits.flush()
}

// droppedSummaries returns the metadata of the summary rows.
func (s *stack) droppedSummaries(t *testing.T) []auditRow {
	t.Helper()
	var out []auditRow
	for _, r := range s.auditRows(t) {
		if r.Action == auditDroppedAction {
			out = append(out, r)
		}
	}
	return out
}

// The audit rows that requests without a login cause (failed logins, reset
// requests) share one budget per minute for the process. Beyond it a row is
// not written but counted, and once the minute has turned one summary row
// says how many were dropped. Rows of successful logins are never dropped.
func TestUnauthenticatedAuditRowsHaveABudget(t *testing.T) {
	const budget, extra = 3, 4
	s := newStack(t, withMail, withAudit, func(o *Options, _ *stack) { o.UnauthenticatedAuditRowsPerMinute = budget })
	s.createUser(t, "owner@example.com", "pw12345678")
	var logs bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prevLog) })
	cheap := strings.Repeat("x", 1025) // refused without a hash
	fail := func(i int) {
		t.Helper()
		w := s.login(t, fmt.Sprintf("198.51.100.%d:1", 10+i%200), fmt.Sprintf("someone-%d@example.com", i), cheap)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}

	// Minute 0: budget+extra failed logins from several addresses, and a
	// reset request: budget rows are written, extra+1 dropped.
	for i := 0; i < budget+extra; i++ {
		fail(i)
	}
	require.Equal(t, http.StatusOK, s.post(t, "198.51.100.250:1", "/forgot-password", url.Values{"email": {"owner@example.com"}}, nil).Code)
	assert.Equal(t, budget, s.auditCount(t, "auth.login.failure"))
	assert.Zero(t, s.auditCount(t, "auth.password.reset.request"), "the reset request is over the budget")
	// A successful login in the same minute still writes its row.
	require.Equal(t, http.StatusSeeOther, s.login(t, "198.51.100.251:1", "owner@example.com", "pw12345678").Code)
	assert.Equal(t, 1, s.auditCount(t, "auth.login.success"))
	assert.Empty(t, s.droppedSummaries(t), "no summary before the minute has turned")

	// Minute 1: the first row of the new minute brings the summary of the
	// last one; the budget is full again.
	s.clock.Advance(time.Minute)
	for i := 0; i < budget+2; i++ {
		fail(100 + i)
	}
	sums := s.droppedSummaries(t)
	require.Len(t, sums, 1)
	assert.Equal(t, float64(extra+1), sums[0].Metadata["dropped"])
	assert.Nil(t, sums[0].UserID)
	assert.Nil(t, sums[0].IP, "no address in the summary")
	assert.Equal(t, 2*budget, s.auditCount(t, "auth.login.failure"), "the budget refilled")

	// Minute 2 without any request: the background check writes the
	// summary of minute 1, once.
	s.clock.Advance(time.Minute)
	flushAuditBudget(t, s.h)
	flushAuditBudget(t, s.h)
	sums = s.droppedSummaries(t)
	require.Len(t, sums, 2)
	assert.Equal(t, float64(2), sums[1].Metadata["dropped"])
	assert.Equal(t, 2, strings.Count(logs.String(), "audit rows of requests without a login dropped"),
		"one log line per minute with drops:\n%s", logs.String())

	// A minute without drops writes no summary.
	s.clock.Advance(time.Minute)
	fail(300)
	s.clock.Advance(time.Minute)
	flushAuditBudget(t, s.h)
	assert.Len(t, s.droppedSummaries(t), 2)
}

// After the clock steps back (an NTP correction, a resumed VM), the budget
// starts a new minute too: whenever the minute differs from the one counted.
func TestUnauthenticatedAuditBudgetAfterAClockStepBack(t *testing.T) {
	clock := newFakeClock()
	var summaries []int
	b := newAuditBudget(2, clock.Now, func(dropped int, _ time.Time) { summaries = append(summaries, dropped) })
	require.True(t, b.take())
	require.True(t, b.take())
	require.False(t, b.take(), "the minute's budget is spent")
	clock.Advance(-time.Minute)
	assert.True(t, b.take(), "a new minute, a new budget")
	assert.Equal(t, []int{1}, summaries, "the minute that ended is summed up")
}

func TestUnauthenticatedAuditBudgetOptions(t *testing.T) {
	assert.Equal(t, 120, newAuditBudget(0, nil, nil).limit, "default")
	assert.Equal(t, 7, newAuditBudget(7, nil, nil).limit)
	assert.LessOrEqual(t, newAuditBudget(-1, nil, nil).limit, 0, "negative switches the budget off")
}
