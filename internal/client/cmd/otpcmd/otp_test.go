package otpcmd_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/cmd/otpcmd"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

func setupOTP(t *testing.T, userID string) func(args ...string) (string, error) {
	t.Helper()
	ts, err := testutil.NewTestServer()
	require.NoError(t, err)
	t.Cleanup(ts.Stop)
	ts.SetupClientConfig(t, userID)

	return func(args ...string) (string, error) {
		cmd := otpcmd.NewOTPCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		var execErr error
		captured := testutil.CaptureOutput(func() { execErr = cmd.Execute() })
		return captured + buf.String(), execErr
	}
}

func otpAddedID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "OTP secret added: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "OTP secret added: "))
		}
	}
	return ""
}

func TestOTP_AddListCode(t *testing.T) {
	run := setupOTP(t, "user-alice")

	out, err := run("add", "--secret", "JBSWY3DPEHPK3PXP", "--label", "alice@example.com", "--issuer", "GitHub")
	require.NoError(t, err)
	id := otpAddedID(out)
	require.NotEmpty(t, id)

	out, err = run("list")
	require.NoError(t, err)
	assert.Contains(t, out, "alice@example.com")
	assert.Contains(t, out, "GitHub")

	out, err = run("code", id)
	require.NoError(t, err)
	assert.Contains(t, out, "remaining")
}

func TestOTP_AddMissingSecret(t *testing.T) {
	run := setupOTP(t, "user-alice")
	_, err := run("add", "--label", "x")
	require.Error(t, err)
}

func TestOTP_CodeNotFound(t *testing.T) {
	run := setupOTP(t, "user-alice")
	_, err := run("code", "missing-id")
	require.Error(t, err)
}

func TestOTP_CodeRequiresArg(t *testing.T) {
	run := setupOTP(t, "user-alice")
	_, err := run("code")
	require.Error(t, err)
}

func TestNewOTPCmd_Structure(t *testing.T) {
	cmd := otpcmd.NewOTPCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "otp", cmd.Use)

	subNames := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subNames[sub.Use] = true
	}
	assert.True(t, len(subNames) >= 2, "should have at least add and list subcommands")
}

func TestOTPPayload_Fields(t *testing.T) {
	p := otpcmd.OTPPayload{
		Secret: "JBSWY3DPEHPK3PXP",
		Label:  "alice@example.com",
		Issuer: "GitHub",
	}
	assert.Equal(t, "JBSWY3DPEHPK3PXP", p.Secret)
	assert.Equal(t, "alice@example.com", p.Label)
	assert.Equal(t, "GitHub", p.Issuer)
}
