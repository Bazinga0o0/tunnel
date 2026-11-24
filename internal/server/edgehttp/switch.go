package edgehttp

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
)

// A connection stops being HTTP only when the backend says so: 101 in answer
// to an Upgrade request (WebSocket), 2xx in answer to CONNECT. The request
// alone decides nothing. A visitor could otherwise send an Upgrade request
// that the backend answers like any other request, and then have the bytes
// behind it copied to the backend unseen, forwarding headers of its own
// choosing included.
//
// Only the first request of a connection can ask. The first bytes on the
// stream are then the answer to that request and to no other, so the edge
// can read the answer's status without having to follow the backend's
// responses for the rest of the connection.

// answerBufferSize is the size of the reader that the backend's answer to a
// request to switch protocols is read through. The copy to the visitor goes
// on through the same reader afterwards.
const answerBufferSize = 32 << 10

// asksForUpgrade reports whether req asks the backend to switch protocols by
// way of Upgrade: the header itself and its announcement in Connection.
func asksForUpgrade(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range req.Header["Connection"] {
		for _, token := range strings.Split(v, ",") {
			if isUpgradeToken(token) {
				return true
			}
		}
	}
	return false
}

func isUpgradeToken(token string) bool {
	return strings.EqualFold(strings.TrimSpace(token), "upgrade")
}

// dropUpgrade takes the request to switch protocols out of a request that is
// not the first of its connection: the Upgrade header and the token that
// announces it in Connection. Both are hop-by-hop, and the edge does not
// pass this hop on.
func dropUpgrade(h http.Header) {
	for key := range h {
		if strings.EqualFold(key, "Upgrade") {
			delete(h, key)
		}
	}
	if values, ok := h["Connection"]; ok {
		if values = withoutTokens(values, isUpgradeToken); len(values) > 0 {
			h["Connection"] = values
		} else {
			delete(h, "Connection")
		}
	}
}

// dropH2C takes the request to go on in HTTP/2 on the same connection (h2c)
// out of a request. The edge never passes it on, on any request: a backend
// that accepted it would answer 101, the connection would become a raw copy,
// and the visitor's HTTP/2 requests would carry forwarding headers that the
// edge never sees.
//
// The h2c token is removed from Upgrade, and the HTTP2-Settings header with
// its token in Connection. When no protocol is left to upgrade to, the
// Upgrade header and its token in Connection go as well and the request is
// an ordinary one. Other protocols (websocket) stay.
func dropH2C(h http.Header) {
	for key := range h {
		if strings.EqualFold(key, "HTTP2-Settings") {
			delete(h, key)
		}
	}
	if values, ok := h["Connection"]; ok {
		isSettings := func(token string) bool { return strings.EqualFold(token, "HTTP2-Settings") }
		if values = withoutTokens(values, isSettings); len(values) > 0 {
			h["Connection"] = values
		} else {
			delete(h, "Connection")
		}
	}
	if values, ok := h["Upgrade"]; ok {
		// An empty token is no protocol either.
		isH2C := func(token string) bool {
			name, _, _ := strings.Cut(token, "/") // "h2c", also with a version behind it
			return token == "" || strings.EqualFold(strings.TrimSpace(name), "h2c")
		}
		if values = withoutTokens(values, isH2C); len(values) > 0 {
			h["Upgrade"] = values
		} else {
			dropUpgrade(h)
		}
	}
}

// copyAnswers copies the backend's bytes to the visitor, unchanged, until the
// stream ends; it returns nil when the stream ended cleanly.
//
// With a decision channel the first request asked to switch protocols. The
// head of the answer is then read on its way to the visitor and the outcome
// is sent on the channel: true when the connection is no longer HTTP. Nothing
// is sent when the stream ends or fails before the answer has arrived; the
// caller closes the channel in every case.
func copyAnswers(visitor io.Writer, stream io.Reader, decision chan<- bool, upgrade, connect bool) error {
	if decision != nil {
		answer := bufio.NewReaderSize(stream, answerBufferSize)
		raw, err := awaitSwitch(answer, visitor, upgrade, connect)
		if err == io.EOF {
			return nil // the backend ended the stream instead of answering
		}
		if err != nil {
			return err
		}
		decision <- raw
		stream = answer // holds what was read beyond the status line
	}
	_, err := io.Copy(visitor, stream)
	return err
}

// awaitSwitch reads the beginning of the backend's answer to a request that
// asked to switch protocols and reports whether the backend agreed: 101 to a
// request with Upgrade, 2xx to CONNECT. Interim responses other than 101 (100
// Continue, 103 Early Hints) are stepped over. Any other answer, including
// one that is not an HTTP/1 status line, means that the connection stays
// HTTP.
//
// Every byte it reads is written to w as it is. What follows the status line
// that settled the matter stays in br.
func awaitSwitch(br *bufio.Reader, w io.Writer, upgrade, connect bool) (bool, error) {
	for {
		status, err := copyStatusLine(br, w)
		if err != nil {
			return false, err
		}
		switch {
		case status == http.StatusSwitchingProtocols:
			return upgrade, nil
		case status >= 100 && status < 200:
			if err := copyHeaderBlock(br, w); err != nil {
				return false, err
			}
		case status >= 200 && status < 300:
			return connect, nil
		default:
			return false, nil
		}
	}
}

// copyStatusLine copies one line from br to w and returns the status code if
// the line is an HTTP/1 status line, and 0 if it is not.
func copyStatusLine(br *bufio.Reader, w io.Writer) (int, error) {
	line, err := br.ReadSlice('\n')
	status := parseStatus(line) // before the next read from br, which reuses the line
	if err := copyRestOfLine(br, w, line, err); err != nil {
		return 0, err
	}
	return status, nil
}

// copyHeaderBlock copies header lines from br to w, up to and including the
// empty line that ends the block.
func copyHeaderBlock(br *bufio.Reader, w io.Writer) error {
	for {
		line, err := br.ReadSlice('\n')
		end := err == nil && (len(line) == 1 || (len(line) == 2 && line[0] == '\r'))
		if err := copyRestOfLine(br, w, line, err); err != nil {
			return err
		}
		if end {
			return nil
		}
	}
}

// copyRestOfLine writes the result of a ReadSlice('\n') to w and, when the
// line was longer than the buffer of br, the rest of the line after it.
func copyRestOfLine(br *bufio.Reader, w io.Writer, line []byte, err error) error {
	for {
		if len(line) > 0 {
			if _, werr := w.Write(line); werr != nil {
				return werr
			}
		}
		if err != bufio.ErrBufferFull {
			return err // nil at the end of the line
		}
		line, err = br.ReadSlice('\n')
	}
}

// parseStatus returns the status code of an HTTP/1 status line such as
// "HTTP/1.1 101 Switching Protocols", and 0 for anything else. It is strict
// on purpose: a line it does not recognise never switches protocols.
func parseStatus(line []byte) int {
	const prefix = "HTTP/1."
	if len(line) < len(prefix)+5 || !bytes.HasPrefix(line, []byte(prefix)) {
		return 0
	}
	rest := line[len(prefix):] // "1 101 Switching Protocols\r\n"
	if (rest[0] != '0' && rest[0] != '1') || rest[1] != ' ' {
		return 0
	}
	code := 0
	for _, c := range rest[2:5] {
		if c < '0' || c > '9' {
			return 0
		}
		code = code*10 + int(c-'0')
	}
	if len(rest) > 5 && rest[5] != ' ' && rest[5] != '\r' && rest[5] != '\n' {
		return 0
	}
	return code
}
