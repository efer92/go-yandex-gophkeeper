package generate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/cmd/generate"
	"github.com/efer92/go-yandex-gophkeeper/internal/testutil"
)

func TestNewGenerateCmd_Structure(t *testing.T) {
	cmd := generate.NewGenerateCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "generate", cmd.Use)
	assert.GreaterOrEqual(t, len(cmd.Commands()), 2, "should have password and key subcommands")
}

// runGen executes the generate command with the given args, capturing stdout.
func runGen(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := generate.NewGenerateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	var err error
	// Capture os.Stdout because RunE uses fmt.Println directly.
	captured := testutil.CaptureOutput(func() { err = cmd.Execute() })
	return captured + out.String(), err
}

func TestGeneratePassword_Default(t *testing.T) {
	out, err := runGen(t, "password", "--length", "24")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(strings.TrimSpace(out)), 20)
}

func TestGeneratePassword_NoSymbols(t *testing.T) {
	out, err := runGen(t, "password", "--length", "16", "--symbols=false")
	require.NoError(t, err)
	assert.NotEmpty(t, strings.TrimSpace(out))
}

func TestGenerateDerive_RealmRequired(t *testing.T) {
	_, err := runGen(t, "derive")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "realm")
}

func TestGenerateKey_RawToFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "key.txt")
	_, err := runGen(t, "key", "--type", "raw", "--out", out)
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.NotEmpty(t, strings.TrimSpace(string(data)))
}

func TestGenerateKey_Ed25519ToFile(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "id")
	pub := filepath.Join(dir, "id.pub")
	_, err := runGen(t, "key", "--type", "ed25519", "--out", priv, "--pub", pub)
	require.NoError(t, err)
	pd, _ := os.ReadFile(priv)
	pb, _ := os.ReadFile(pub)
	assert.NotEmpty(t, pd)
	assert.NotEmpty(t, pb)
}

func TestGenerateKey_RawToStdout(t *testing.T) {
	out, err := runGen(t, "key", "--type", "raw")
	require.NoError(t, err)
	assert.NotEmpty(t, strings.TrimSpace(out))
}

func TestGenerateKey_DeriveRealmRequired(t *testing.T) {
	_, err := runGen(t, "key", "--type", "raw", "--derive")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "realm")
}

func TestGenerateKey_InvalidType(t *testing.T) {
	_, err := runGen(t, "key", "--type", "bogus")
	require.Error(t, err)
}
