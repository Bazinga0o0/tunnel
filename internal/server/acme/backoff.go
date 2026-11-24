package acme

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Backoff between attempts that contact the CA.
const (
	BackoffMin = time.Minute
	BackoffMax = time.Hour
)

// clock is the time source of the manager; tests use a fake one.
type clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// backoffState is the marker kept in the cache directory. It is written
// before every attempt that contacts the CA (the time of the attempt and the
// wait that follows a failure) and removed once a new certificate is cached.
// Guaranteed: a process that dies during an attempt, and every process that
// starts later, waits for the recorded wait before it contacts the CA;
// waiting processes read the marker and the cache again before each attempt.
// Not guaranteed: two processes that read the marker at the same moment can
// both attempt, because nothing locks the directory; and after a power loss
// or an operating system crash the marker may be missing or empty, because
// it is written without fsync (an empty one counts as the shortest wait).
type backoffState struct {
	LastAttempt time.Time     `json:"last_attempt"`
	Step        time.Duration `json:"step"`
}

// next returns the earliest time of the next attempt; the zero time when
// there is no backoff.
func (b backoffState) next() time.Time {
	if b.Step <= 0 {
		return time.Time{}
	}
	return b.LastAttempt.Add(b.Step)
}

// nextStep returns the wait that follows a failure of the attempt after b:
// BackoffMin first, then doubled up to BackoffMax.
func (b backoffState) nextStep() time.Duration {
	if b.Step <= 0 {
		return BackoffMin
	}
	return min(b.Step*2, BackoffMax)
}

// readBackoff reads the marker. No marker: no backoff. A marker that cannot
// be read or parsed, or names no attempt, is replaced by one for an attempt
// just now with the shortest wait (so that it can neither block attempts
// for long nor remove the wait). What is read is clamped: an attempt in the
// future counts as now, and the step lies within [BackoffMin, BackoffMax].
func (m *Manager) readBackoff() backoffState {
	now := m.clk.Now()
	raw, err := readFile(filepath.Join(m.dir, backoffFile))
	if errors.Is(err, os.ErrNotExist) {
		return backoffState{}
	}
	var b backoffState
	if err == nil {
		err = json.Unmarshal(raw, &b)
	}
	if err == nil && (b.LastAttempt.IsZero() || b.Step <= 0) {
		err = errors.New("names no attempt")
	}
	if err != nil {
		repaired := backoffState{LastAttempt: now, Step: BackoffMin}
		m.logger.Warn("acme: the backoff marker is damaged; replacing it with the shortest wait",
			"file", filepath.Join(m.dir, backoffFile), "err", err)
		if werr := m.writeBackoff(repaired); werr != nil {
			m.logger.Error("acme: the backoff marker could not be replaced", "dir", m.dir, "err", werr)
		}
		return repaired
	}
	clamped := b
	if clamped.LastAttempt.After(now) {
		clamped.LastAttempt = now
	}
	clamped.Step = min(max(clamped.Step, BackoffMin), BackoffMax)
	if clamped != b {
		// Written back, so that the clamp happens once and the wait runs
		// from it.
		m.logger.Warn("acme: the backoff marker is out of range; correcting it",
			"file", filepath.Join(m.dir, backoffFile), "last_attempt", b.LastAttempt, "step", b.Step)
		if werr := m.writeBackoff(clamped); werr != nil {
			m.logger.Error("acme: the backoff marker could not be corrected", "dir", m.dir, "err", werr)
		}
	}
	return clamped
}

// writeBackoff stores the marker.
func (m *Manager) writeBackoff(b backoffState) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(m.dir, backoffFile), raw)
}

// clearBackoff removes the marker after a success.
func (m *Manager) clearBackoff() {
	if err := os.Remove(filepath.Join(m.dir, backoffFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		m.logger.Error("acme: the backoff marker could not be removed", "dir", m.dir, "err", err)
	}
}
