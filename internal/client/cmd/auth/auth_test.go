package auth_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/cmd/auth"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

func TestNewAuthCmd_Structure(t *testing.T) {
	cmd := auth.NewAuthCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "auth", cmd.Use)

	subNames := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subNames[sub.Name()] = true
	}
	assert.True(t, subNames["register"], "should have register subcommand")
	assert.True(t, subNames["login"], "should have login subcommand")
	assert.True(t, subNames["mfa"], "should have mfa subcommand")
}

func TestAuth_RegisterMissingFlags(t *testing.T) {
	cmd := auth.NewAuthCmd()
	cmd.SetArgs([]string{"register"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err) // --username/--email required
}

func TestAuth_LoginMissingFlags(t *testing.T) {
	cmd := auth.NewAuthCmd()
	cmd.SetArgs([]string{"login"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err) // --username required
}

func TestAuth_TOTPSetup_Success(t *testing.T) {
	ts, err := testutil.NewTestServer()
	require.NoError(t, err)
	t.Cleanup(ts.Stop)
	ts.SetupClientConfig(t, "user-alice")

	// Return a known-valid base32 secret; the command will enroll its own secret so
	// the code won't match, but we only assert the EnrollTOTP RPC ran (otpauth:// printed).
	code, err := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	require.NoError(t, err)

	cmd := auth.NewAuthCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"mfa", "totp-setup"})

	testutil.WithStdin(t, code+"\n", func() {
		captured := testutil.CaptureOutput(func() { _ = cmd.Execute() })
		out.WriteString(captured)
	})

	// The EnrollTOTP RPC must have produced an otpauth URL in the output.
	assert.Contains(t, out.String(), "otpauth://")
}
