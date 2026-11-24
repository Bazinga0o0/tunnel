// Package sessions manages browser session cookies backed by Postgres.
// Cookies store a random 24-byte value (base64-url encoded ~32 chars) and
// the database stores only sha256(raw).
package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
)

// ErrInvalidSession is returned when a session cannot be found, is expired,
// was revoked, or belongs to a disabled account.
var ErrInvalidSession = errors.New("invalid or expired session")

const rawBytes = 24

// DefaultMaxUserAgentBytes is the default for Options.MaxUserAgentBytes.
const DefaultMaxUserAgentBytes = 256

// Options sets the limits of the service.
type Options struct {
	// MaxUserAgentBytes is the longest User-Agent value stored with a
	// session, in bytes; longer values are cut at a character boundary.
	// Zero selects DefaultMaxUserAgentBytes (256); a negative value stores
	// the value uncut.
	MaxUserAgentBytes int
}

type Service struct {
	q                 *sqlcgen.Queries
	maxUserAgentBytes int // <= 0: no cut
}

// NewService builds the service with the default limits.
func NewService(pool *pgxpool.Pool) *Service {
	return NewServiceWithOptions(pool, Options{})
}

// NewServiceWithOptions builds the service with the given limits.
func NewServiceWithOptions(pool *pgxpool.Pool, opts Options) *Service {
	if opts.MaxUserAgentBytes == 0 {
		opts.MaxUserAgentBytes = DefaultMaxUserAgentBytes
	}
	return &Service{q: sqlcgen.New(pool), maxUserAgentBytes: opts.MaxUserAgentBytes}
}

// storableUserAgent returns ua in a form the text column takes: bytes that
// are not UTF-8 and NUL are dropped, and the rest is cut to max bytes
// without splitting a character. max <= 0 means no cut.
func storableUserAgent(ua string, max int) string {
	ua = strings.ToValidUTF8(ua, "")
	ua = strings.ReplaceAll(ua, "\x00", "")
	if max <= 0 || len(ua) <= max {
		return ua
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(ua[cut]) {
		cut--
	}
	return ua[:cut]
}

// Create mints a new session for userID. Returns (raw-cookie-value, stored-row).
// The raw value is what goes into the Set-Cookie header; the DB only stores
// sha256(raw). The User-Agent is stored cut to Options.MaxUserAgentBytes.
func (s *Service) Create(ctx context.Context, userID int64, userAgent string, ip netip.Addr, ttl time.Duration) (string, *sqlcgen.Session, error) {
	buf := make([]byte, rawBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))

	userAgent = storableUserAgent(userAgent, s.maxUserAgentBytes)
	uaParam := pgtype.Text{String: userAgent, Valid: userAgent != ""}

	var ipParam *netip.Addr
	if ip.IsValid() {
		ipCopy := ip
		ipParam = &ipCopy
	}

	// The database adds the lifetime to its own clock, the one the lookup
	// compares with; the row that comes back carries the resulting expiry.
	row, err := s.q.CreateSession(ctx, sqlcgen.CreateSessionParams{
		ID:         sum[:],
		UserID:     userID,
		TtlSeconds: ttl.Seconds(),
		UserAgent:  uaParam,
		Ip:         ipParam,
	})
	if err != nil {
		return "", nil, err
	}
	return raw, &row, nil
}

// Lookup returns the session owning a raw cookie value. A session of a
// disabled account is not returned: it is ErrInvalidSession like an expired
// one. Opportunistically updates last_seen_at.
func (s *Service) Lookup(ctx context.Context, raw string) (*sqlcgen.Session, error) {
	if raw == "" {
		return nil, ErrInvalidSession
	}
	sum := sha256.Sum256([]byte(raw))
	row, err := s.q.GetSessionByID(ctx, sum[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidSession
		}
		return nil, err
	}
	_ = s.q.TouchSession(ctx, sum[:])
	return &row, nil
}

// Delete revokes a single session by its stored ID (sha256-hash of raw).
func (s *Service) Delete(ctx context.Context, id []byte) error {
	return s.q.DeleteSession(ctx, id)
}

// DeleteAllForUser revokes every session for a user.
// Use this on password change to force re-login everywhere.
func (s *Service) DeleteAllForUser(ctx context.Context, userID int64) error {
	return s.q.DeleteSessionsByUser(ctx, userID)
}

// CountActiveByUser returns the number of non-expired sessions for userID.
func (s *Service) CountActiveByUser(ctx context.Context, userID int64) (int64, error) {
	return s.q.CountActiveSessionsByUser(ctx, userID)
}
