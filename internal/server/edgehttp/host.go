package edgehttp

import (
	"strconv"
	"strings"
)

// NormalizeHost turns the host of a request ("Host" header or the authority
// of an absolute request target) into the form that routing decisions are
// made on: one port is stripped, then one trailing dot, and the name is
// lower-cased.
//
// ok is false, and host empty, for anything that is not a host name: an
// empty name, a name longer than 253 or a label longer than 63 characters,
// characters other than ASCII letters, digits and hyphens, a label that
// starts or ends with a hyphen, a port that is not a number up to 65535, and
// IP literals: IPv6 in brackets, and names whose last label is a number in
// the sense of the URL standard, which reads such a name as an IPv4 address.
// A number is a label of digits only, or "0x" or "0X" followed by hex digits
// or by nothing ("0x7f000001", "1.0x7f").
func NormalizeHost(hostport string) (host string, ok bool) {
	host = hostport
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		if !validPort(host[i+1:]) {
			return "", false
		}
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	if !validHostName(host) {
		return "", false
	}
	// Only ASCII is left at this point, so lower-casing cannot fold another
	// character into a letter.
	return strings.ToLower(host), true
}

// validPort reports whether p is empty or a decimal number up to 65535.
func validPort(p string) bool {
	if len(p) > 5 {
		return false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		n = n*10 + int(p[i]-'0')
	}
	return n <= 65535
}

func validHostName(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	start := 0 // start of the current label
	numeric := true
	for i := 0; i <= len(h); i++ {
		if i < len(h) && h[i] != '.' {
			c := h[i]
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				numeric = false
			default:
				return false
			}
			continue
		}
		label := h[start:i]
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if i == len(h) {
			// numeric: the last label consists of digits only
			return !numeric && !isHexNumber(label)
		}
		start = i + 1
		numeric = true
	}
	return false
}

// isHexNumber reports whether label is "0x" or "0X" followed by hex digits
// or by nothing.
func isHexNumber(label string) bool {
	if len(label) < 2 || label[0] != '0' || (label[1] != 'x' && label[1] != 'X') {
		return false
	}
	for i := 2; i < len(label); i++ {
		c := label[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// portOf returns the port of a host that NormalizeHost accepts. ok is false
// when the host names none.
func portOf(hostport string) (port int, ok bool) {
	i := strings.LastIndexByte(hostport, ':')
	if i < 0 || i == len(hostport)-1 {
		return 0, false
	}
	port, err := strconv.Atoi(hostport[i+1:])
	return port, err == nil
}

// extractSubdomain returns the tunnel name of a normalised host: the single
// label in front of the edge's domain. It returns "" for the domain itself,
// for names with more than one label in front of it and for other domains.
func (e *Edge) extractSubdomain(host string) string {
	sub, ok := strings.CutSuffix(host, "."+e.domain)
	if !ok || strings.Contains(sub, ".") {
		return ""
	}
	return sub // empty when nothing stands in front of the domain
}
