package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrintVersion(t *testing.T) {
	prevV, prevC, prevD := version, commit, date
	defer func() { version, commit, date = prevV, prevC, prevD }()

	var out bytes.Buffer
	printVersion(&out)
	assert.Equal(t, "tunneld dev (commit none, built unknown)\n", out.String(), "a plain go build")

	version, commit, date = "1.4.0", "abc1234", "2026-11-14T10:00:00Z"
	out.Reset()
	printVersion(&out)
	assert.Equal(t, "tunneld 1.4.0 (commit abc1234, built 2026-11-14T10:00:00Z)\n", out.String())
}
