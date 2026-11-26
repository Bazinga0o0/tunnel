package main

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/Bazinga0o0/tunnel/internal/server/config"
)

// reloadFromFile re-reads the config file the server was started with and
// applies it (reload). A file that cannot be read or does not validate is
// logged and changes nothing.
func (a *app) reloadFromFile() {
	if a.cfg.Path == "" {
		a.logger.Error("config reload skipped: the config did not come from a file")
		return
	}
	a.logger.Info("config reload requested", "path", a.cfg.Path)
	cfg, err := config.Load(a.cfg.Path)
	if err != nil {
		a.logger.Error("config reload failed; the running config stays active", "err", err)
		return
	}
	a.reload(cfg)
}

// reload applies the live-reloadable parts of next, which must have passed
// config.Load, and leaves the rest of the running server alone. Live today:
// the tcp_ports of the registered services. A tcp_ports change touches
// nothing but two in-memory sets (the pool's random-draw exclusion and the
// service API's port check), so no listener, tunnel or connection is closed:
//
//   - A port added to a service stops being drawn at random and becomes one
//     the service may set a holder for.
//   - A port removed from a service becomes an ordinary pool port again. A
//     tunnel that holds it keeps running, and so does any holder reservation
//     in the database, which the log points out; the service just can no
//     longer change it (the service API answers 403).
//
// Everything else that differs from the running config (addresses, TLS, the
// database, limits, a service's other fields, services added or removed,
// tcp.port_range, ...) is ignored and logged as requiring a restart. A ports
// change is applied even then, as long as the service itself is unchanged
// and the port lies in the range the server runs with.
func (a *app) reload(next *config.Config) {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	cur := a.current

	for _, section := range restartSections(cur, next) {
		a.logger.Warn("config change requires a restart and is ignored", "section", section)
	}

	h, _ := a.serviceAPI.(interface{ SetPorts(map[string][]int) })
	if a.tcpPool == nil || h == nil {
		for _, s := range next.Services {
			if i := serviceIndex(cur.Services, s.Name); i >= 0 && !slices.Equal(sortedCopy(s.TCPPorts), sortedCopy(cur.Services[i].TCPPorts)) {
				a.logger.Warn("tcp_ports change requires a restart and is ignored: the TCP edge or the service API is not running",
					"service", s.Name)
			}
		}
		return
	}

	applied := make(map[string][]int, len(cur.Services))
	merged := *cur
	merged.Services = slices.Clone(cur.Services)
	changed := false
	for i, old := range cur.Services {
		j := serviceIndex(next.Services, old.Name)
		if j < 0 || !reflect.DeepEqual(withoutPorts(old), withoutPorts(next.Services[j])) {
			// Removed or changed otherwise: reported by restartSections.
			applied[old.Name] = old.TCPPorts
			continue
		}
		var inRange []int
		for _, p := range next.Services[j].TCPPorts {
			if p < cur.TCP.PortRange.Low || p > cur.TCP.PortRange.High {
				a.logger.Warn("tcp_ports entry outside the running tcp.port_range ignored; restart to apply",
					"service", old.Name, "port", p)
				continue
			}
			inRange = append(inRange, p)
		}
		if slices.Equal(sortedCopy(inRange), sortedCopy(old.TCPPorts)) {
			applied[old.Name] = old.TCPPorts
			continue
		}
		changed = true
		added, removed := diffPorts(old.TCPPorts, inRange)
		a.logger.Info("service tcp_ports reloaded", "service", old.Name, "added", added, "removed", removed)
		if len(removed) > 0 {
			a.logger.Warn("removed ports stay open to tunnels that hold them; a holder reservation of the port "+
				"stays in the database until it is released in the admin panel (Reservations)",
				"service", old.Name, "ports", removed)
		}
		applied[old.Name] = inRange
		merged.Services[i].TCPPorts = slices.Clone(inRange)
	}
	if !changed {
		a.logger.Info("config reloaded: no live-reloadable change")
		return
	}
	var all []int
	for _, s := range merged.Services {
		all = append(all, s.TCPPorts...)
	}
	h.SetPorts(applied)
	a.tcpPool.SetExcluded(all)
	a.current = &merged
}

// restartSections names the parts of next that differ from cur and cannot be
// applied while the server runs: every top-level section but services whose
// value differs, and "services" when a service was added or removed or one
// differs in anything but its tcp_ports.
func restartSections(cur, next *config.Config) []string {
	var out []string
	cv, nv := reflect.ValueOf(*cur), reflect.ValueOf(*next)
	t := cv.Type()
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if tag == "-" || tag == "" || tag == "services" {
			continue
		}
		if !reflect.DeepEqual(cv.Field(i).Interface(), nv.Field(i).Interface()) {
			out = append(out, tag)
		}
	}
	if len(cur.Services) != len(next.Services) {
		return append(out, "services")
	}
	for _, old := range cur.Services {
		j := serviceIndex(next.Services, old.Name)
		if j < 0 || !reflect.DeepEqual(withoutPorts(old), withoutPorts(next.Services[j])) {
			return append(out, fmt.Sprintf("services (%s)", old.Name))
		}
	}
	return out
}

func withoutPorts(s config.Service) config.Service {
	s.TCPPorts = nil
	return s
}

func serviceIndex(list []config.Service, name string) int {
	return slices.IndexFunc(list, func(s config.Service) bool { return s.Name == name })
}

func sortedCopy(p []int) []int {
	c := slices.Clone(p)
	slices.Sort(c)
	return c
}

func diffPorts(old, next []int) (added, removed []int) {
	for _, p := range next {
		if !slices.Contains(old, p) {
			added = append(added, p)
		}
	}
	for _, p := range old {
		if !slices.Contains(next, p) {
			removed = append(removed, p)
		}
	}
	return added, removed
}
