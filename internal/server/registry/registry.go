// Package registry is the in-memory table of the authenticated tunnel
// sessions and of the subdomains and ports they serve.
package registry

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/metrics"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
)

// ErrSubdomainTaken is returned when a subdomain is already registered.
var ErrSubdomainTaken = errors.New("subdomain taken")

// ErrSessionAlreadyRegistered is returned when a session attempts to register
// more than one subdomain. P1 supports exactly one HTTP tunnel per session.
// A session MAY hold one HTTP subdomain AND one TCP port concurrently — the
// TCP side has its own check (ErrSessionAlreadyRegisteredTCP).
var ErrSessionAlreadyRegistered = errors.New("session already has a subdomain")

// ErrSessionAlreadyRegisteredTCP is returned when a session attempts to
// register a second TCP port.
var ErrSessionAlreadyRegisteredTCP = errors.New("session already has a tcp port")

// ErrPortTaken is returned when a TCP port is already registered by another
// session.
var ErrPortTaken = errors.New("tcp port taken")

// ErrSessionAlreadyRegisteredUDP is returned when a session attempts to
// register a second UDP port.
var ErrSessionAlreadyRegisteredUDP = errors.New("session already has a udp port")

// ErrUDPPortTaken is returned when a UDP port is already registered by another
// session.
var ErrUDPPortTaken = errors.New("udp port taken")

// ErrSessionExists is returned by AddSession for a session ID that is already
// tracked.
var ErrSessionExists = errors.New("session already tracked")

// ErrSessionLimit is returned by AddSession when the registry already tracks
// SessionLimits.Total sessions.
var ErrSessionLimit = errors.New("session limit reached")

// ErrUserSessionLimit is returned by AddSession when the session's user
// already has SessionLimits.PerUser sessions.
var ErrUserSessionLimit = errors.New("session limit for this user reached")

// Session is the minimal interface the registry needs from a tunnel session.
// A session can tell the registry more about itself by also implementing
// UserIDer, TokenIDer and Closer.
type Session interface {
	ID() string
}

// tracked is the registry's record of one session. Owner and token are read
// once, when the session enters the registry.
type tracked struct {
	sess    Session
	userID  int64 // 0: no user (static-token session, or no UserIDer)
	tokenID int64 // 0: no token identity (static-token session, or no TokenIDer)
}

// Registry holds the tracked sessions and the subdomain→session and
// port→session mappings. Concurrency-safe.
type Registry struct {
	mu        sync.RWMutex
	sessions  map[string]*tracked // session ID → every tracked session
	perUser   map[int64]int       // user ID → number of tracked sessions
	bySub     map[string]Session
	bySession map[string]string // session ID → HTTP subdomain
	byTCPPort map[int]Session
	byTCPSess map[string]int // session ID → reserved TCP port
	byUDPPort map[int]Session
	byUDPSess map[string]int // session ID → reserved UDP port

	// candidate produces one random subdomain candidate. It is a field so
	// that tests can script the sequence.
	candidate func() (string, error)
}

// New creates an empty registry.
func New() *Registry {
	return &Registry{
		sessions:  map[string]*tracked{},
		perUser:   map[int64]int{},
		bySub:     map[string]Session{},
		bySession: map[string]string{},
		byTCPPort: map[int]Session{},
		byTCPSess: map[string]int{},
		byUDPPort: map[int]Session{},
		byUDPSess: map[string]int{},
		candidate: randomCandidate,
	}
}

// Defaults of SessionLimits.
const (
	DefaultMaxSessionsPerUser = 10
	DefaultMaxSessions        = 350 // sized by acceptor.SessionMemoryBytes and the ports of a session
)

// SessionLimits bounds AddSession. A zero value selects the default; a
// negative value disables the limit.
type SessionLimits struct {
	// PerUser is the number of sessions one user may have at a time. Sessions
	// without a user (user ID 0, static-token mode) are not subject to it.
	// Zero selects DefaultMaxSessionsPerUser, a negative value disables.
	PerUser int
	// Total is the number of sessions the registry tracks at a time. Zero
	// selects DefaultMaxSessions, a negative value disables.
	Total int
}

// resolved returns the limits with defaults applied; in the result a value
// of zero or less means "no limit".
func (l SessionLimits) resolved() (perUser, total int) {
	perUser, total = l.PerUser, l.Total
	if perUser == 0 {
		perUser = DefaultMaxSessionsPerUser
	}
	if total == 0 {
		total = DefaultMaxSessions
	}
	return perUser, total
}

// AddSession starts tracking an authenticated session that has no tunnel yet,
// so that it shows up in SnapshotAll and can be killed. The check against lim
// and the insertion happen under one lock.
//
// It returns ErrUserSessionLimit or ErrSessionLimit when a limit is reached
// (the per-user limit is checked first) and ErrSessionExists for a session
// ID that is already tracked. On error the session is not tracked.
func (r *Registry) AddSession(s Session, lim SessionLimits) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[s.ID()]; ok {
		return ErrSessionExists
	}
	uid := userIDOf(s)
	perUser, total := lim.resolved()
	if perUser > 0 && uid != 0 && r.perUser[uid] >= perUser {
		return ErrUserSessionLimit
	}
	if total > 0 && len(r.sessions) >= total {
		return ErrSessionLimit
	}
	r.trackLocked(s)
	return nil
}

// trackLocked records s as a tracked session unless it already is one.
// Register calls use it for sessions that never went through AddSession.
func (r *Registry) trackLocked(s Session) {
	id := s.ID()
	if _, ok := r.sessions[id]; ok {
		return
	}
	t := &tracked{sess: s, userID: userIDOf(s), tokenID: tokenIDOf(s)}
	r.sessions[id] = t
	r.perUser[t.userID]++
}

// removeLocked drops the session with the given ID from every table: its
// tunnels and the tracking record. It returns the session, or nil when the
// ID is not tracked.
func (r *Registry) removeLocked(id string) Session {
	t, ok := r.sessions[id]
	if !ok {
		return nil
	}
	if sub, ok := r.bySession[id]; ok {
		delete(r.bySub, sub)
		delete(r.bySession, id)
		metrics.ActiveSessions.WithLabelValues("http").Dec()
	}
	if port, ok := r.byTCPSess[id]; ok {
		delete(r.byTCPPort, port)
		delete(r.byTCPSess, id)
		metrics.ActiveSessions.WithLabelValues("tcp").Dec()
	}
	if port, ok := r.byUDPSess[id]; ok {
		delete(r.byUDPPort, port)
		delete(r.byUDPSess, id)
		metrics.ActiveSessions.WithLabelValues("udp").Dec()
	}
	delete(r.sessions, id)
	if r.perUser[t.userID]--; r.perUser[t.userID] <= 0 {
		delete(r.perUser, t.userID)
	}
	return t.sess
}

// RegisterHTTP associates subdomain with session. A session may only hold
// one subdomain at a time — subsequent calls return ErrSessionAlreadyRegistered.
//
// The name must already be in the normal form of
// reservations.NormalizeSubdomain. The acceptor normalises before it calls;
// this check is the second line of defence, so that no caller can make the
// registry route a malformed or system-reserved name. It returns
// reservations.ErrInvalidSubdomain or reservations.ErrSystemReserved.
func (r *Registry) RegisterHTTP(subdomain string, s Session) error {
	normal, err := reservations.NormalizeSubdomain(subdomain)
	if err != nil {
		return err
	}
	if normal != subdomain {
		// Lookups are exact: a name stored as "MyApp" would never be found.
		return reservations.ErrInvalidSubdomain
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.bySession[s.ID()]; ok {
		return ErrSessionAlreadyRegistered
	}
	if _, ok := r.bySub[subdomain]; ok {
		return ErrSubdomainTaken
	}
	r.trackLocked(s)
	r.bySub[subdomain] = s
	r.bySession[s.ID()] = subdomain
	metrics.ActiveSessions.WithLabelValues("http").Inc()
	return nil
}

// LookupHTTP returns the session registered for the subdomain, if any.
func (r *Registry) LookupHTTP(subdomain string) (Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.bySub[subdomain]
	return s, ok
}

// UnregisterHTTP removes the registration of subdomain, but only if it
// belongs to s. It reports whether an entry was removed. The session stays
// tracked.
func (r *Registry) UnregisterHTTP(subdomain string, s Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.bySub[subdomain]
	if !ok || cur.ID() != s.ID() {
		return false
	}
	delete(r.bySub, subdomain)
	delete(r.bySession, s.ID())
	metrics.ActiveSessions.WithLabelValues("http").Dec()
	return true
}

// RegisterTCP associates port with session. A session may only hold one TCP
// port at a time — subsequent calls return ErrSessionAlreadyRegisteredTCP.
// An HTTP subdomain + a TCP port on the same session is allowed.
func (r *Registry) RegisterTCP(port int, s Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byTCPSess[s.ID()]; ok {
		return ErrSessionAlreadyRegisteredTCP
	}
	if _, ok := r.byTCPPort[port]; ok {
		return ErrPortTaken
	}
	r.trackLocked(s)
	r.byTCPPort[port] = s
	r.byTCPSess[s.ID()] = port
	metrics.ActiveSessions.WithLabelValues("tcp").Inc()
	return nil
}

// LookupTCP returns the session registered for port, if any.
func (r *Registry) LookupTCP(port int) (Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byTCPPort[port]
	return s, ok
}

// UnregisterTCP removes the TCP registration of port, but only if it belongs
// to s. It reports whether an entry was removed. The session stays tracked.
func (r *Registry) UnregisterTCP(port int, s Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.byTCPPort[port]
	if !ok || cur.ID() != s.ID() {
		return false
	}
	delete(r.byTCPPort, port)
	delete(r.byTCPSess, s.ID())
	metrics.ActiveSessions.WithLabelValues("tcp").Dec()
	return true
}

// RegisterUDP associates port with session. A session may only hold one UDP
// port at a time — subsequent calls return ErrSessionAlreadyRegisteredUDP.
// A UDP port can coexist with an HTTP subdomain or TCP port on the same session.
func (r *Registry) RegisterUDP(port int, s Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byUDPSess[s.ID()]; ok {
		return ErrSessionAlreadyRegisteredUDP
	}
	if _, ok := r.byUDPPort[port]; ok {
		return ErrUDPPortTaken
	}
	r.trackLocked(s)
	r.byUDPPort[port] = s
	r.byUDPSess[s.ID()] = port
	metrics.ActiveSessions.WithLabelValues("udp").Inc()
	return nil
}

// LookupUDP returns the session registered for UDP port, if any.
func (r *Registry) LookupUDP(port int) (Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byUDPPort[port]
	return s, ok
}

// UnregisterUDP removes the UDP registration of port, but only if it belongs
// to s: a session that is torn down late must not delete the entry of the
// session that got the port after it. It reports whether an entry was
// removed. The session stays tracked.
func (r *Registry) UnregisterUDP(port int, s Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.byUDPPort[port]
	if !ok || cur.ID() != s.ID() {
		return false
	}
	delete(r.byUDPPort, port)
	delete(r.byUDPSess, s.ID())
	metrics.ActiveSessions.WithLabelValues("udp").Dec()
	return true
}

// Unregister stops tracking the session and removes its HTTP subdomain, TCP
// port and UDP port. Entries of other sessions are never touched. It does not
// close the session.
func (r *Registry) Unregister(s Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(s.ID())
}

// SnapshotTypeSession is the SnapshotEntry.Type of a session that has no
// tunnel registered.
const SnapshotTypeSession = "session"

// SnapshotEntry captures one active tunnel of a session, or (in SnapshotAll)
// a session without any tunnel.
type SnapshotEntry struct {
	SessionID string
	Type      string // "http", "tcp", "udp", or SnapshotTypeSession
	Subdomain string // set for Type=="http"
	Port      int    // set for Type=="tcp" or Type=="udp"
	Session   Session
}

// Snapshot returns a consistent slice of all current HTTP-registered sessions.
// The slice is newly allocated; callers may retain and mutate it freely.
func (r *Registry) Snapshot() []SnapshotEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SnapshotEntry, 0, len(r.bySub))
	for sub, sess := range r.bySub {
		out = append(out, SnapshotEntry{
			SessionID: sess.ID(),
			Type:      "http",
			Subdomain: sub,
			Session:   sess,
		})
	}
	return out
}

// SnapshotAll returns every tracked session. A session appears once per
// tunnel it holds (HTTP, TCP, UDP); a session without a tunnel appears once
// with Type SnapshotTypeSession.
// The slice is newly allocated; callers may retain and mutate it freely.
func (r *Registry) SnapshotAll() []SnapshotEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SnapshotEntry, 0, len(r.sessions)+len(r.byTCPPort)+len(r.byUDPPort))
	for sub, sess := range r.bySub {
		out = append(out, SnapshotEntry{
			SessionID: sess.ID(),
			Type:      "http",
			Subdomain: sub,
			Session:   sess,
		})
	}
	for port, sess := range r.byTCPPort {
		out = append(out, SnapshotEntry{
			SessionID: sess.ID(),
			Type:      "tcp",
			Port:      port,
			Session:   sess,
		})
	}
	for port, sess := range r.byUDPPort {
		out = append(out, SnapshotEntry{
			SessionID: sess.ID(),
			Type:      "udp",
			Port:      port,
			Session:   sess,
		})
	}
	for id, t := range r.sessions {
		_, hasHTTP := r.bySession[id]
		_, hasTCP := r.byTCPSess[id]
		_, hasUDP := r.byUDPSess[id]
		if hasHTTP || hasTCP || hasUDP {
			continue
		}
		out = append(out, SnapshotEntry{
			SessionID: id,
			Type:      SnapshotTypeSession,
			Session:   t.sess,
		})
	}
	return out
}

// Closer is implemented by sessions that can be forcefully terminated.
// The registry uses this to implement the Kill and Evict methods.
type Closer interface {
	Close() error
}

// closeAll closes the given sessions. It must be called without r.mu held:
// closing can take a while and may call back into the registry.
func closeAll(sessions []Session) {
	for _, s := range sessions {
		if c, ok := s.(Closer); ok {
			_ = c.Close()
		}
	}
}

// KillSession removes the session whose ID matches sessionID from the
// registry, with all its tunnels, and closes it. It finds every tracked
// session, with or without a tunnel. Returns true if a session was found,
// false if no session with that ID exists.
func (r *Registry) KillSession(sessionID string) bool {
	r.mu.Lock()
	found := r.removeLocked(sessionID)
	r.mu.Unlock()

	if found == nil {
		return false
	}
	closeAll([]Session{found})
	return true
}

// killWhere removes and closes every tracked session that match selects, and
// returns how many that were.
func (r *Registry) killWhere(match func(*tracked) bool) int {
	r.mu.Lock()
	var victims []Session
	for id, t := range r.sessions {
		if match(t) {
			victims = append(victims, t.sess)
			r.removeLocked(id)
		}
	}
	r.mu.Unlock()

	closeAll(victims)
	return len(victims)
}

// KillByUser removes and closes every session of the given user, with or
// without a tunnel, and returns how many it closed. Use it when an account is
// disabled.
//
// A userID of zero or less selects nothing: 0 is the ID of sessions that have
// no user (static-token mode), not the ID of a user.
func (r *Registry) KillByUser(userID int64) int {
	if userID <= 0 {
		return 0
	}
	return r.killWhere(func(t *tracked) bool { return t.userID == userID })
}

// KillByToken removes and closes every session that authenticated with the
// given API token and returns how many it closed. Use it when a token is
// revoked.
//
// A tokenID of zero or less selects nothing: 0 is what sessions without a
// token identity carry (static-token mode), not the ID of a token.
func (r *Registry) KillByToken(tokenID int64) int {
	if tokenID <= 0 {
		return 0
	}
	return r.killWhere(func(t *tracked) bool { return t.tokenID == tokenID })
}

// TokenIDs returns the IDs of the API tokens the tracked sessions logged in
// with, each once and in ascending order. Sessions without a token identity
// (token ID 0, static-token mode) are not represented. The server's session
// revalidation checks these IDs and closes the sessions of the invalid ones
// with KillByToken.
func (r *Registry) TokenIDs() []int64 {
	r.mu.RLock()
	seen := make(map[int64]struct{}, len(r.sessions))
	for _, t := range r.sessions {
		if t.tokenID > 0 {
			seen[t.tokenID] = struct{}{}
		}
	}
	r.mu.RUnlock()

	out := make([]int64, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// evict removes and closes the session that lookup returns, unless keep
// spares it. lookup and keep run with r.mu held.
func (r *Registry) evict(lookup func() (Session, bool), keep func(*tracked) bool) int {
	r.mu.Lock()
	holder, ok := lookup()
	if !ok {
		r.mu.Unlock()
		return 0
	}
	t, ok := r.sessions[holder.ID()]
	if !ok || keep(t) {
		r.mu.Unlock()
		return 0
	}
	r.removeLocked(holder.ID())
	r.mu.Unlock()

	closeAll([]Session{holder})
	return 1
}

// EvictSubdomain closes the session that currently serves subdomain, unless
// that session belongs to keepUserID, and returns how many sessions it closed
// (0 or 1). The whole session ends, including its other tunnels. Use it when
// the subdomain is reserved for keepUserID.
//
// The name is normalised with reservations.NormalizeSubdomain before the
// lookup, like at every other entry point. A name that is not a valid
// subdomain names no tunnel: the call returns 0. A session without a user
// (static-token mode) is foreign to every keepUserID other than 0.
func (r *Registry) EvictSubdomain(subdomain string, keepUserID int64) int {
	name, err := reservations.NormalizeSubdomain(subdomain)
	if err != nil {
		return 0
	}
	return r.evict(func() (Session, bool) {
		s, ok := r.bySub[name]
		return s, ok
	}, keepUser(keepUserID))
}

// EvictTCPPort closes the session that currently holds the TCP port, unless
// that session belongs to keepUserID, and returns how many sessions it closed
// (0 or 1). See EvictSubdomain.
func (r *Registry) EvictTCPPort(port int, keepUserID int64) int {
	return r.evict(r.tcpHolder(port), keepUser(keepUserID))
}

// CloseTCPPortHolder closes the session that currently holds the TCP port,
// whoever's it is, and returns how many sessions it closed (0 or 1). The
// whole session ends, including its other tunnels. Use it when the holder of
// a registered service's port changes. Unlike EvictTCPPort it spares no
// account, not even the new holder's: the service decides who holds the
// port, and a session of that account on another computer gives it up too.
func (r *Registry) CloseTCPPortHolder(port int) int {
	return r.evict(r.tcpHolder(port), func(*tracked) bool { return false })
}

// tcpHolder returns the lookup of evict for the TCP port.
func (r *Registry) tcpHolder(port int) func() (Session, bool) {
	return func() (Session, bool) {
		s, ok := r.byTCPPort[port]
		return s, ok
	}
}

// keepUser returns the keep function of evict that spares the sessions of
// userID.
func keepUser(userID int64) func(*tracked) bool {
	return func(t *tracked) bool { return t.userID == userID }
}

// EvictUDPPort closes the session that currently holds the UDP port, unless
// that session belongs to keepUserID, and returns how many sessions it closed
// (0 or 1). See EvictSubdomain.
func (r *Registry) EvictUDPPort(port int, keepUserID int64) int {
	return r.evict(func() (Session, bool) {
		s, ok := r.byUDPPort[port]
		return s, ok
	}, keepUser(keepUserID))
}

// UserIDer is implemented by sessions that are owned by a user; the registry
// exposes this narrow interface so callers can filter the snapshot by user
// without importing the concrete session type.
type UserIDer interface {
	UserIDValue() int64
}

// TokenIDer is implemented by sessions that know which API token
// authenticated them. 0 means "no token identity" (static-token mode).
type TokenIDer interface {
	TokenIDValue() int64
}

// ConnectedAter is implemented by sessions that track handshake time; the
// registry exposes this narrow interface so callers can display uptime
// without importing the concrete session type.
type ConnectedAter interface {
	ConnectedAtValue() time.Time
}

func userIDOf(s Session) int64 {
	if u, ok := s.(UserIDer); ok {
		return u.UserIDValue()
	}
	return 0
}

func tokenIDOf(s Session) int64 {
	if t, ok := s.(TokenIDer); ok {
		return t.TokenIDValue()
	}
	return 0
}

// maxRandomAttempts bounds GenerateRandomSubdomain.
const maxRandomAttempts = 100

// GenerateRandomSubdomain returns a 6-char base36 subdomain that is neither
// taken nor on the system-reserved list (six-letter names such as "status"
// are on it).
func (r *Registry) GenerateRandomSubdomain() (string, error) {
	for attempt := 0; attempt < maxRandomAttempts; attempt++ {
		candidate, err := r.candidate()
		if err != nil {
			return "", err
		}
		if reservations.IsSystemReserved(candidate) {
			continue
		}
		r.mu.RLock()
		_, taken := r.bySub[candidate]
		r.mu.RUnlock()
		if !taken {
			return candidate, nil
		}
	}
	return "", errors.New("failed to generate unique subdomain after 100 attempts")
}

// randomCandidate draws six base36 characters from the system's random source.
func randomCandidate() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	const length = 6
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("rand: %w", err)
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}
