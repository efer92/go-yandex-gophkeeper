package auth

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clientcfg "github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

// stubPassword replaces readPassword for the duration of the test.
func stubPassword(t *testing.T, pw string) {
	t.Helper()
	orig := readPassword
	readPassword = func(string) ([]byte, error) { return []byte(pw), nil }
	t.Cleanup(func() { readPassword = orig })
}

func runAuth(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewAuthCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	var err error
	captured := testutil.CaptureOutput(func() { err = cmd.Execute() })
	return captured + buf.String(), err
}

func setupAuthServer(t *testing.T) *testutil.TestServer {
	t.Helper()
	ts, err := testutil.NewTestServer()
	require.NoError(t, err)
	t.Cleanup(ts.Stop)
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Auth tests start unauthenticated (no token); they register/login themselves.
	require.NoError(t, clientcfg.Save(&clientcfg.Config{ServerAddr: ts.Addr}))
	return ts
}

func TestRegister_Success(t *testing.T) {
	setupAuthServer(t)
	stubPassword(t, "masterpass123")

	out, err := runAuth(t, "register", "--username", "alice", "--email", "alice@example.com")
	require.NoError(t, err)
	assert.Contains(t, out, "Registered successfully")
}

func TestRegister_PasswordMismatch(t *testing.T) {
	setupAuthServer(t)
	// Return alternating passwords so the two prompts differ.
	orig := readPassword
	calls := 0
	readPassword = func(string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("first"), nil
		}
		return []byte("second"), nil
	}
	t.Cleanup(func() { readPassword = orig })

	_, err := runAuth(t, "register", "--username", "bob", "--email", "bob@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "passwords do not match")
}

func TestLogin_Success(t *testing.T) {
	setupAuthServer(t)
	stubPassword(t, "masterpass123")

	_, err := runAuth(t, "register", "--username", "carol", "--email", "carol@example.com")
	require.NoError(t, err)

	out, err := runAuth(t, "login", "--username", "carol")
	require.NoError(t, err)
	assert.Contains(t, out, "Logged in as carol")
}

func TestLogin_WrongPassword(t *testing.T) {
	setupAuthServer(t)
	stubPassword(t, "rightpass")
	_, err := runAuth(t, "register", "--username", "dave", "--email", "dave@example.com")
	require.NoError(t, err)

	stubPassword(t, "wrongpass")
	_, err = runAuth(t, "login", "--username", "dave")
	require.Error(t, err)
}
