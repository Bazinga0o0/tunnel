package edgehttp

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Bazinga0o0/tunnel/internal/server/edgeguard"
)

// With Options.TotalBudget the connections of this edge and the slots that
// other edges hold in the same budget stay within one total.
func TestTotalBudgetIsSharedWithOtherEdges(t *testing.T) {
	budget := edgeguard.NewBudget(2)
	f := newFixture(t, Options{TotalBudget: budget})
	sess := f.tunnel("abc")

	// Another edge holds one of the two slots.
	other := edgeguard.NewLimiter(0, 0, 0)
	other.SetBudget(budget)
	release, err := other.Acquire("other", netip.Addr{})
	require.NoError(t, err)

	before := requestCount(t, "limit_total")
	visitors, _ := hold(t, f, sess, "abc.localhost", 1)
	require.Equal(t, 2, budget.Used())
	refused(t, f, "abc.localhost")
	require.Equal(t, before+1, requestCount(t, "limit_total"))
	require.Equal(t, 2, budget.Used(), "a refused connection takes nothing from the budget")
	require.EqualValues(t, 1, sess.opens.Load(), "no stream is opened for a refused connection")

	// A slot that the other edge gives back is available here.
	release()
	hold(t, f, sess, "abc.localhost", 1)
	require.Equal(t, 2, budget.Used())

	// A connection that ends returns its slot to the budget.
	require.NoError(t, visitors[0].c.Close())
	require.Eventually(t, func() bool { return budget.Used() == 1 }, 6*time.Second, 5*time.Millisecond)
}

// The edge's own total keeps applying next to a budget.
func TestTotalBudgetDoesNotReplaceMaxConns(t *testing.T) {
	budget := edgeguard.NewBudget(100)
	f := newFixture(t, Options{MaxConns: 1, TotalBudget: budget})
	sess := f.tunnel("abc")

	hold(t, f, sess, "abc.localhost", 1)
	refused(t, f, "abc.localhost")
	require.Equal(t, 1, budget.Used())
}

// --- the log line for an ended connection ------------------------------------------

// attr returns the value of the attribute key of a record.
func attr(r slog.Record, key string) string {
	value := ""
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			value = a.Value.String()
			return false
		}
		return true
	})
	return value
}

func (c *logCapture) records(level slog.Level, msgPart string) []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []slog.Record
	for _, r := range c.recs {
		if r.Level == level && strings.Contains(r.Message, msgPart) {
			out = append(out, r)
		}
	}
	return out
}

// A visitor can end connections with a malformed request as often as it
// likes, and the parse error quotes the line it sent: the debug line for it
// is cut to 256 bytes and written once per interval.
func TestConnectionEndLogIsCutAndRateLimited(t *testing.T) {
	f := newFixture(t, Options{})
	sess := f.tunnel("abc")

	for i := 0; i < 3; i++ {
		v := f.visit()
		v.send(get("/first"))
		b := sess.accept(t)
		b.next()
		b.reply("ok")
		v.recvOK("ok")

		// A header line without a colon, 8000 bytes long.
		go func() {
			_, _ = v.c.Write([]byte("GET /x HTTP/1.1\r\nHost: abc.localhost\r\n" + strings.Repeat("A", 8000) + "\r\n\r\n"))
		}()
		v.expectClosed(6*time.Second, "connection after a malformed request")
	}
	require.Eventually(t, func() bool { return f.edge.limiter.Total() == 0 }, 6*time.Second, 5*time.Millisecond)

	recs := f.logs.records(slog.LevelDebug, "connection ended")
	require.Len(t, recs, 1, "three ended connections within one interval produce one line")
	text := attr(recs[0], "err")
	require.Contains(t, text, "malformed")
	require.Contains(t, text, "AAAA", "the error quotes the visitor's line")
	require.Len(t, text, 256, "the text is cut")
	require.Equal(t, "abc.localhost", attr(recs[0], "host"))
}

func TestErrTextIsCutOnARuneBoundary(t *testing.T) {
	require.Equal(t, "", errText(nil))
	require.Equal(t, "short", errText(errString("short")))
	require.Equal(t, strings.Repeat("a", 256), errText(errString(strings.Repeat("a", 256))))
	require.Equal(t, strings.Repeat("a", 256), errText(errString(strings.Repeat("a", 257))))
	// 255 bytes and then a two-byte character: the half character is dropped.
	require.Equal(t, strings.Repeat("a", 255), errText(errString(strings.Repeat("a", 255)+"étail")))
}

type errString string

func (e errString) Error() string { return string(e) }
