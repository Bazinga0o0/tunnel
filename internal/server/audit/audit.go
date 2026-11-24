// Package audit writes append-only audit log entries.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
)

type Service struct {
	q *sqlcgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{q: sqlcgen.New(pool)}
}

// Entry is the user-facing representation of a stored audit row.
type Entry struct {
	ID        int64
	UserID    *int64
	Action    string
	Metadata  map[string]any
	IP        netip.Addr
	CreatedAt pgtype.Timestamptz
}

// Log writes an audit entry. userID may be nil for pre-auth events
// (e.g. failed signup attempts).
func (s *Service) Log(ctx context.Context, userID *int64, action string, metadata map[string]any, ip netip.Addr) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	var uid pgtype.Int8
	if userID != nil {
		uid = pgtype.Int8{Int64: *userID, Valid: true}
	}

	var ipPtr *netip.Addr
	if ip.IsValid() {
		ipCopy := ip
		ipPtr = &ipCopy
	}

	return s.q.InsertAuditEntry(ctx, sqlcgen.InsertAuditEntryParams{
		UserID:   uid,
		Action:   action,
		Metadata: raw,
		Ip:       ipPtr,
	})
}

// ListByUser returns up to limit audit entries for a user, newest first.
func (s *Service) ListByUser(ctx context.Context, userID int64, limit int32) ([]Entry, error) {
	rows, err := s.q.ListAuditByUser(ctx, sqlcgen.ListAuditByUserParams{
		UserID: pgtype.Int8{Int64: userID, Valid: true},
		Limit:  limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(rows))
	for _, r := range rows {
		var md map[string]any
		if len(r.Metadata) > 0 {
			if err := json.Unmarshal(r.Metadata, &md); err != nil {
				return nil, fmt.Errorf("unmarshal metadata row %d: %w", r.ID, err)
			}
		}
		e := Entry{
			ID:        r.ID,
			Action:    r.Action,
			Metadata:  md,
			CreatedAt: r.CreatedAt,
		}
		if r.Ip != nil {
			e.IP = *r.Ip
		}
		if r.UserID.Valid {
			uid := r.UserID.Int64
			e.UserID = &uid
		}
		out = append(out, e)
	}
	return out, nil
}
