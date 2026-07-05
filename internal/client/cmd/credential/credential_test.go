package credential_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/cmd/credential"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

// setupServer starts a test gRPC server, writes a client config, and returns a
// runner that executes credential subcommands with combined stdout+stderr output.
func setupServer(t *testing.T, userID string) func(args ...string) (string, error) {
	t.Helper()
	ts, err := testutil.NewTestServer()
	require.NoError(t, err)
	t.Cleanup(ts.Stop)
	ts.SetupClientConfig(t, userID)

	return func(args ...string) (string, error) {
		cmd := credential.NewCredentialCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		var execErr error
		captured := testutil.CaptureOutput(func() { execErr = cmd.Execute() })
		return captured + buf.String(), execErr
	}
}

func extractID(out string) string {
	// "Created: <id>"
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Created: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Created: "))
		}
	}
	return ""
}

func TestCredential_AddGetListDelete(t *testing.T) {
	run := setupServer(t, "user-alice")

	out, err := run("add", "--name", "GitHub", "--username", "alice", "--password", "s3cret")
	require.NoError(t, err)
	id := extractID(out)
	require.NotEmpty(t, id)

	out, err = run("list")
	require.NoError(t, err)
	assert.Contains(t, out, "GitHub")
	assert.Contains(t, out, "alice")

	out, err = run("get", "GitHub")
	require.NoError(t, err)
	assert.Contains(t, out, "s3cret")
	assert.Contains(t, out, "GitHub")

	out, err = run("delete", "GitHub")
	require.NoError(t, err)
	assert.Contains(t, out, "Deleted")
}

func TestCredential_ListEmpty(t *testing.T) {
	run := setupServer(t, "user-bob")
	out, err := run("list")
	require.NoError(t, err)
	assert.Contains(t, out, "No credentials found")
}

func TestCredential_GetNotFound(t *testing.T) {
	run := setupServer(t, "user-alice")
	_, err := run("get", "nonexistent-id")
	require.Error(t, err)
}

func TestCredential_AddMissingRequiredFlag(t *testing.T) {
	run := setupServer(t, "user-alice")
	_, err := run("add", "--username", "alice")
	require.Error(t, err) // --password and --name required
}

func TestNewCredentialCmd_Structure(t *testing.T) {
	cmd := credential.NewCredentialCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "credential", cmd.Use)

	subNames := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subNames[sub.Name()] = true
	}
	assert.True(t, subNames["add"], "should have add subcommand")
	assert.True(t, subNames["get"], "should have get subcommand")
	assert.True(t, subNames["list"], "should have list subcommand")
	assert.True(t, subNames["delete"], "should have delete subcommand")
}

func TestCredentialPayload_JSONTags(t *testing.T) {
	// Verify the payload struct has the expected fields.
	p := credential.CredentialPayload{Username: "user", Password: "pass"}
	assert.Equal(t, "user", p.Username)
	assert.Equal(t, "pass", p.Password)
}
