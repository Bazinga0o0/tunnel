package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// appendConfig adds YAML to the CLI test's config file.
func (c *adminCLITest) appendConfig(t *testing.T, yaml string) {
	t.Helper()
	f, err := os.OpenFile(c.cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = f.WriteString(yaml)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

// The admin CLI builds its account services from the config like the server
// does: limits.* apply to `tunneld admin` too.
func TestAdminCLIUsesTheConfiguredAccountLimits(t *testing.T) {
	c := newAdminCLITest(t)
	c.appendConfig(t, "limits:\n  min_admin_password_length: 20\n  max_tokens_per_user: 1\n  max_token_name_length: 5\n")

	// 12 characters pass the default rule, not the configured one.
	r := c.run(t, cliOptions{stdin: "twelve-chars\n"}, "create-user", "--email", "short@example.com", "--password-stdin")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "20")
	assert.False(t, c.userExists(t, "short@example.com"))

	c.mustRun(t, cliOptions{stdin: "a-password-of-twenty-chars\n"}, "create-user", "--email", "long@example.com", "--password-stdin")

	r = c.run(t, cliOptions{}, "issue-token", "--email", "long@example.com", "--name", "laptop-name")
	require.Error(t, r.err, "the name is longer than the configured 5 characters")

	c.mustRun(t, cliOptions{}, "issue-token", "--email", "long@example.com", "--name", "lap")
	r = c.run(t, cliOptions{}, "issue-token", "--email", "long@example.com", "--name", "desk")
	require.Error(t, r.err, "one active token per user is configured")
}

func TestAdminCLIPrintsTheConfigWarnings(t *testing.T) {
	c := newAdminCLITest(t)
	// The CLI test config uses a self-signed certificate with a database:
	// that is a start-up warning.
	r := c.mustRun(t, cliOptions{}, "list-users")
	assert.Contains(t, r.errOut, "warning: tls: the self-signed certificate")
	assert.Equal(t, 1, strings.Count(r.errOut, "self-signed"))
}
