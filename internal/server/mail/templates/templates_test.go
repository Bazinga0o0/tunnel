package templates

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyEmailRendersLink(t *testing.T) {
	text, html, err := VerifyEmail("https://app.example.com/verify?token=abc")
	require.NoError(t, err)
	assert.Contains(t, text, "https://app.example.com/verify?token=abc")
	assert.Contains(t, html, `href="https://app.example.com/verify?token=abc"`)
	assert.True(t, strings.HasPrefix(html, "<!doctype html>"))
}

func TestPasswordResetRendersLink(t *testing.T) {
	text, html, err := PasswordReset("https://app.example.com/reset?token=xyz")
	require.NoError(t, err)
	assert.Contains(t, text, "https://app.example.com/reset?token=xyz")
	assert.Contains(t, html, "Reset password")
}

func TestVerifyEmailEscapesLink(t *testing.T) {
	// html/template auto-escapes, so a raw `<script>` in the link would
	// become `%3Cscript%3E` after URL-encoding or HTML-escaping.
	_, html, err := VerifyEmail("https://evil/?x=<script>")
	require.NoError(t, err)
	assert.NotContains(t, html, "<script>")
}
