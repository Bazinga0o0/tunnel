package services

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Bazinga0o0/tunnel/internal/server/db/sqlcgen"
	"github.com/Bazinga0o0/tunnel/internal/server/reservations"
	"github.com/Bazinga0o0/tunnel/internal/server/users"
)

// The audit actions of the service API. Their metadata name the service,
// the port, the new holder (account_id, set only), the previous holder and
// the number of sessions closed; never a secret.
const (
	ActionHolderSet   = "service.port.holder.set"
	ActionHolderClear = "service.port.holder.clear"
)

// maxHolderBody bounds the body of a PUT: {"account_id": N} is short.
const maxHolderBody = 4 << 10

// auditTimeout bounds the audit write after a change, which does not end
// with the request: the change is made, and the client that went away
// does not undo it.
const auditTimeout = 5 * time.Second

// writeTimeout bounds the change of a holder. The change does not end with
// the request: a client that goes away while the database commits would
// otherwise leave the reservation changed and the old holder's session open.
const writeTimeout = 10 * time.Second

// APIService is a registered service as the service API knows it. Each
// service needs a secret of its own.
type APIService struct {
	Name   string
	Secret []byte
	Ports  map[int]bool // the service's tcp_ports
}

// PortReservations changes the reservations of TCP ports; satisfied by
// *reservations.Service. Both changes return the owner they replaced or
// removed, read in the same transaction.
type PortReservations interface {
	OwnerTCPPort(ctx context.Context, port int) (int64, bool, error)
	TransferTCPPort(ctx context.Context, port int, userID int64) (prevUserID int64, err error)
	RevokeTCPPortReturningOwner(ctx context.Context, port int) (prevUserID int64, reserved bool, err error)
}

// UserLookup finds an account; satisfied by *users.Service, which returns
// users.ErrNotFound for an unknown one.
type UserLookup interface {
	FindByID(ctx context.Context, id int64) (*sqlcgen.User, error)
}

// PortCloser closes the tunnel session on a TCP port; satisfied by
// *registry.Registry.
type PortCloser interface {
	CloseTCPPortHolder(port int) int
}

// Auditor writes audit rows; satisfied by *audit.Service.
type Auditor interface {
	Log(ctx context.Context, userID *int64, action string, metadata map[string]any, ip netip.Addr) error
}

// api serves the service API.
type api struct {
	services        []apiService
	res             PortReservations
	users           UserLookup
	requireApproved bool // auth.signup approval or closed
	reg             PortCloser
	audit           Auditor
	logger          *slog.Logger

	mu    sync.RWMutex     // guards ports
	ports map[string][]int // service name -> its tcp_ports (SetPorts)
}

// apiService is an APIService with the digest of its secret: digests of
// equal length are compared, so the comparison tells nothing about the
// length of a secret either.
type apiService struct {
	name   string
	digest [sha256.Size]byte
}

type apiServiceKey struct{}

// NewAPI returns the handler of the service API, through which a service
// sets the holder of its TCP ports:
//
//	PUT    /v1/tcp-ports/{port}/holder  {"account_id": N}  200 {"account_id": N, "sessions_closed": k}
//	DELETE /v1/tcp-ports/{port}/holder                     200 {"sessions_closed": k}
//	GET    /v1/tcp-ports/{port}/holder                     200 {"account_id": N}, 404 without holder
//
// Every request carries "Authorization: Bearer <secret>" with the secret of
// a service, otherwise it is answered 401. A port that is not one of that
// service's is 403, an account that is unknown or disabled 404, and so is,
// with requireApproved (auth.signup approval or closed), an account that
// waits for an admin's approval. Setting and clearing close the tunnel
// session that holds the port, whoever's it is, and are written to the
// audit log. A change, once begun, is carried out
// even when the client goes away. When it fails (500) it may still have
// been made, so the holding session is closed then as well. Errors are
// {"error": "..."}.
func NewAPI(svcs []APIService, res PortReservations, users UserLookup, requireApproved bool, reg PortCloser, audit Auditor, logger *slog.Logger) http.Handler {
	a := &api{res: res, users: users, requireApproved: requireApproved, reg: reg, audit: audit, logger: logger,
		ports: map[string][]int{}}
	for _, s := range svcs {
		a.services = append(a.services, apiService{
			name:   s.Name,
			digest: sha256.Sum256(s.Secret),
		})
		for port, ok := range s.Ports {
			if ok {
				a.ports[s.Name] = append(a.ports[s.Name], port)
			}
		}
		if a.ports[s.Name] == nil {
			a.ports[s.Name] = []int{}
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/tcp-ports/{port}/holder", a.setHolder)
	mux.HandleFunc("DELETE /v1/tcp-ports/{port}/holder", a.clearHolder)
	mux.HandleFunc("GET /v1/tcp-ports/{port}/holder", a.getHolder)
	return &Handler{Handler: a.authenticate(mux), a: a}
}

// Handler is the service API as NewAPI returns it: an http.Handler whose
// ports can be replaced while it serves.
type Handler struct {
	http.Handler
	a *api
}

// SetPorts replaces the tcp_ports of the named services (service name to
// ports) for all later requests; a service that is not in ports keeps its
// ports, and a name that is not a service of the API is ignored. A request
// that is being served finishes with the ports it saw.
func (h *Handler) SetPorts(ports map[string][]int) {
	h.a.mu.Lock()
	defer h.a.mu.Unlock()
	for name, p := range ports {
		if _, ok := h.a.ports[name]; ok {
			h.a.ports[name] = slices.Clone(p)
		}
	}
}

// owns reports whether port is one of the service's tcp_ports.
func (a *api) owns(svc *apiService, port int) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return slices.Contains(a.ports[svc.name], port)
}

// authenticate lets through the requests that carry the secret of a
// service, and puts the service into their context.
func (a *api) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var svc *apiService
		if token, ok := bearerToken(r.Header); ok {
			svc = a.serviceFor(token)
		}
		if svc == nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiServiceKey{}, svc)))
	})
}

// serviceFor returns the service whose secret token is, or nil. Every
// service is compared, in constant time.
func (a *api) serviceFor(token string) *apiService {
	digest := sha256.Sum256([]byte(token))
	var found *apiService
	for i := range a.services {
		if subtle.ConstantTimeCompare(digest[:], a.services[i].digest[:]) == 1 {
			found = &a.services[i]
		}
	}
	return found
}

// servicePort returns the authenticated service and the port of the
// request, or answers it: 400 for a port that is not a number, 403 for one
// that is not the service's.
func (a *api) servicePort(w http.ResponseWriter, r *http.Request) (*apiService, int, bool) {
	svc := r.Context().Value(apiServiceKey{}).(*apiService)
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || port < 1 || port > 65535 {
		writeError(w, http.StatusBadRequest, "invalid port")
		return nil, 0, false
	}
	if !a.owns(svc, port) {
		writeError(w, http.StatusForbidden, "port does not belong to the service")
		return nil, 0, false
	}
	return svc, port, true
}

func (a *api) setHolder(w http.ResponseWriter, r *http.Request) {
	svc, port, ok := a.servicePort(w, r)
	if !ok {
		return
	}
	var body struct {
		AccountID int64 `json:"account_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHolderBody)).Decode(&body); err != nil || body.AccountID <= 0 {
		writeError(w, http.StatusBadRequest, `body must be {"account_id": N}`)
		return
	}
	ctx := r.Context()
	u, err := a.users.FindByID(ctx, body.AccountID) // a read: a failure changes nothing
	switch {
	case errors.Is(err, users.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown account")
		return
	case err != nil:
		a.fail(w, svc, port, "account lookup failed", err)
		return
	case u.DisabledAt.Valid:
		writeError(w, http.StatusNotFound, "unknown account")
		return
	case a.requireApproved && !users.IsApproved(u):
		// An account that waits for approval may not use the server, and a
		// reservation would make it look in use (users.ApproveExisting
		// approves such accounts at the next start).
		writeError(w, http.StatusNotFound, "unknown account")
		return
	}
	wctx, cancel := writeContext(ctx)
	defer cancel()
	prev, err := a.res.TransferTCPPort(wctx, port, body.AccountID)
	switch {
	case errors.Is(err, reservations.ErrUnknownUser): // deleted since the lookup; rolled back
		writeError(w, http.StatusNotFound, "unknown account")
		return
	case err != nil:
		a.failWrite(w, svc, port, "setting the holder failed", err)
		return
	}
	// The reservation is the new holder's: whoever holds the port now goes.
	closed := a.reg.CloseTCPPortHolder(port)
	a.record(ctx, ActionHolderSet, map[string]any{
		"service":             svc.name,
		"port":                port,
		"account_id":          body.AccountID,
		"previous_account_id": accountOrNil(prev, prev != 0),
		"sessions_closed":     closed,
	})
	writeJSON(w, http.StatusOK, map[string]any{"account_id": body.AccountID, "sessions_closed": closed})
}

func (a *api) clearHolder(w http.ResponseWriter, r *http.Request) {
	svc, port, ok := a.servicePort(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	wctx, cancel := writeContext(ctx)
	defer cancel()
	prev, reserved, err := a.res.RevokeTCPPortReturningOwner(wctx, port)
	if err != nil {
		a.failWrite(w, svc, port, "clearing the holder failed", err)
		return
	}
	closed := a.reg.CloseTCPPortHolder(port)
	if reserved || closed > 0 {
		a.record(ctx, ActionHolderClear, map[string]any{
			"service":             svc.name,
			"port":                port,
			"previous_account_id": accountOrNil(prev, reserved),
			"sessions_closed":     closed,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions_closed": closed})
}

func (a *api) getHolder(w http.ResponseWriter, r *http.Request) {
	svc, port, ok := a.servicePort(w, r)
	if !ok {
		return
	}
	owner, reserved, err := a.res.OwnerTCPPort(r.Context(), port)
	switch {
	case err != nil:
		a.fail(w, svc, port, "looking up the holder failed", err)
	case !reserved:
		writeError(w, http.StatusNotFound, "no holder")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"account_id": owner})
	}
}

// record writes the audit row of a change and logs it. The row has no
// actor: the service is named in the metadata. A failed write is logged; the
// change stands.
func (a *api) record(ctx context.Context, action string, metadata map[string]any) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	attrs := make([]any, 0, 2*len(metadata))
	for _, k := range slices.Sorted(maps.Keys(metadata)) {
		attrs = append(attrs, k, metadata[k])
	}
	a.logger.Info(action, attrs...)
	if err := a.audit.Log(ctx, nil, action, metadata, netip.Addr{}); err != nil {
		a.logger.Warn("service API: the audit log entry could not be written",
			append([]any{"action", action, "err", err}, attrs...)...)
	}
}

// writeContext is the context of a change: it outlives the request (see
// writeTimeout) and keeps its values.
func writeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
}

// fail answers a request whose lookup failed, and logs it.
func (a *api) fail(w http.ResponseWriter, svc *apiService, port int, msg string, err error) {
	a.logger.Error("service API: "+msg, "service", svc.name, "port", port, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// failWrite answers a request whose change failed. The error does not say
// whether the database made the change: a COMMIT can go through while the
// connection breaks. So the session that holds the port is closed all the
// same: if the change was made, the old holder must not keep the port; if
// not, the holder connects again. No audit row is written for a change
// that may not have happened; the log line names the closed session.
func (a *api) failWrite(w http.ResponseWriter, svc *apiService, port int, msg string, err error) {
	closed := a.reg.CloseTCPPortHolder(port)
	a.logger.Error("service API: "+msg, "service", svc.name, "port", port, "err", err, "sessions_closed", closed)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// accountOrNil is the account for the metadata: nil when there is none.
func accountOrNil(id int64, ok bool) any {
	if !ok {
		return nil
	}
	return id
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
