package dbtest

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingTB stands in for *testing.T in a call of openPool that is meant to
// fail: it records the failure instead of failing this test, and keeps the
// cleanups so that the test can run them as the testing package would.
type failingTB struct {
	cleanups []func()
	failed   bool
	messages []string
}

func (f *failingTB) Helper()           {}
func (f *failingTB) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *failingTB) Errorf(format string, args ...any) {
	f.failed = true
	f.messages = append(f.messages, fmt.Sprintf(format, args...))
}

// FailNow ends the goroutine, as testing.T.FailNow does.
func (f *failingTB) FailNow() {
	f.failed = true
	runtime.Goexit()
}

func (f *failingTB) runCleanups() {
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
}

// failingOpen calls openPool with url, expects it to fail, and then runs
// the cleanups it registered.
func failingOpen(t *testing.T, url string) *failingTB {
	t.Helper()
	f := &failingTB{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		openPool(f, url)
	}()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("openPool neither returned nor failed")
	}
	f.runCleanups()
	require.True(t, f.failed, "openPool was expected to fail for %s", url)
	return f
}

func TestPoolLeavesNoLockBehindWhenAStepFails(t *testing.T) {
	url := os.Getenv("TUNNELD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TUNNELD_TEST_DATABASE_URL not set")
	}

	// A lock that stays behind makes the Pool calls below wait for ever.
	// Fail loudly instead of running into the test timeout.
	watchdog := time.AfterFunc(60*time.Second, func() {
		panic("dbtest.Pool hangs after an earlier call failed: a lock was not released")
	})
	defer watchdog.Stop()

	// Pool keeps its locks until the test that called it ends, so every call
	// below has a subtest of its own.

	// The first step after the process lock fails: nothing listens on port 1.
	failingOpen(t, "postgres://nobody:wrong@127.0.0.1:1/none?sslmode=disable&connect_timeout=2")
	t.Run("after a failed connect the next call gets the locks", func(t *testing.T) {
		pool := Pool(t)
		pool.Close()
	})

	// A step after both locks fails: every transaction of this connection
	// is read-only, which the advisory lock and an up-to-date migration do
	// not mind, and TRUNCATE refuses.
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	f := failingOpen(t, url+sep+"options=-c%20default_transaction_read_only%3Don")
	assert.Contains(t, strings.Join(f.messages, "\n"), "read-only", "the step that failed is the TRUNCATE")

	t.Run("after a failed later step the next call gets the locks", func(t *testing.T) {
		// Free in this process ...
		pool := Pool(t)
		defer pool.Close()

		// ... and in this database, where no session holds the advisory
		// lock besides the one Pool has just taken for this subtest.
		var holders int
		require.NoError(t, pool.QueryRow(t.Context(),
			`SELECT count(*) FROM pg_locks
			 WHERE locktype = 'advisory' AND granted
			   AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
			   AND ((classid::bigint << 32) | objid::bigint) = $1`, advisoryLockID).Scan(&holders))
		assert.Equal(t, 1, holders, "sessions holding the advisory lock")
	})
}
