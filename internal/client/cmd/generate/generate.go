// Package generate implements CLI commands for password and key generation.
package generate

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
)

// NewGenerateCmd creates the generate parent command.
func NewGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate random passwords and cryptographic keys",
	}
	cmd.AddCommand(newPasswordCmd(), newDetermPasswordCmd(), newKeyCmd())
	return cmd
}

func newPasswordCmd() *cobra.Command {
	opts := crypto.DefaultPasswordOpts()
	var copyOut bool

	cmd := &cobra.Command{
		Use:   "password",
		Short: "Generate a random password",
		Example: `  gophkeeper generate password
  gophkeeper generate password --length 32 --no-symbols
  gophkeeper generate password --length 24 --no-ambiguous --copy`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pwd, err := crypto.GeneratePassword(opts)
			if err != nil {
				return fmt.Errorf("generate password: %w", err)
			}
			fmt.Println(pwd)
			if copyOut {
				if err := clipboard.WriteAll(pwd); err != nil {
					return fmt.Errorf("copy to clipboard: %w", err)
				}
				fmt.Fprintln(os.Stderr, "Password copied to clipboard.")
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&opts.Length, "length", "l", opts.Length, "password length")
	cmd.Flags().BoolVar(&opts.Upper, "upper", opts.Upper, "include uppercase letters")
	cmd.Flags().BoolVar(&opts.Digits, "digits", opts.Digits, "include digits")
	cmd.Flags().BoolVar(&opts.Symbols, "symbols", opts.Symbols, "include symbols")
	cmd.Flags().BoolVar(&opts.NoAmbiguous, "no-ambiguous", opts.NoAmbiguous, "exclude ambiguous characters (l,1,I,O,0)")
	cmd.Flags().BoolVar(&copyOut, "copy", false, "copy to clipboard")
	return cmd
}

func newDetermPasswordCmd() *cobra.Command {
	opts := crypto.DeterministicOpts{
		Length:       20,
		PasswordOpts: crypto.DefaultPasswordOpts(),
	}
	var copyOut bool

	cmd := &cobra.Command{
		Use:   "derive",
		Short: "Derive a deterministic password from master password + realm (no storage needed)",
		Long: `Derives a unique, reproducible password from your master password and a realm
identifier (e.g. a website domain). The same inputs always produce the same
password — no need to store the result.

This is inspired by cloudflare/gokey's vaultless design.`,
		Example: `  gophkeeper generate derive --realm github.com
  gophkeeper generate derive --realm aws-prod --length 32 --no-symbols`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Realm == "" {
				return fmt.Errorf("--realm is required")
			}
			fmt.Fprint(os.Stderr, "Master password: ")
			password, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return fmt.Errorf("read password: %w", err)
			}

			// Derive master key from password (using a fixed KDF for CLI convenience).
			kdfParams := crypto.KDFParams{
				Algo:    "argon2id",
				Memory:  64 * 1024,
				Time:    3,
				Threads: 4,
				Salt:    []byte("gophkeeper-cli-derive-v1"), // realm provides the per-site diversity
			}
			masterKey := crypto.DeriveKey(password, kdfParams)

			pwd, err := crypto.DerivePassword(masterKey, opts)
			if err != nil {
				return fmt.Errorf("derive password: %w", err)
			}
			fmt.Println(pwd)
			if copyOut {
				_ = clipboard.WriteAll(pwd)
				fmt.Fprintln(os.Stderr, "Password copied to clipboard.")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.Realm, "realm", "r", "", "realm identifier, e.g. github.com (required)")
	cmd.Flags().IntVarP(&opts.Length, "length", "l", opts.Length, "password length")
	cmd.Flags().BoolVar(&opts.Upper, "upper", opts.Upper, "include uppercase letters")
	cmd.Flags().BoolVar(&opts.Digits, "digits", opts.Digits, "include digits")
	cmd.Flags().BoolVar(&opts.Symbols, "symbols", opts.Symbols, "include symbols")
	cmd.Flags().BoolVar(&opts.NoAmbiguous, "no-ambiguous", opts.NoAmbiguous, "exclude ambiguous characters")
	cmd.Flags().BoolVar(&copyOut, "copy", false, "copy to clipboard")
	return cmd
}

func newKeyCmd() *cobra.Command {
	var (
		keyType  string
		realm    string
		outFile  string
		pubFile  string
		determin bool
	)

	cmd := &cobra.Command{
		Use:   "key",
		Short: "Generate a cryptographic key pair",
		Long: `Generates cryptographic key pairs. Supported types:
  raw      — 32-byte symmetric key (hex encoded)
  ed25519  — Ed25519 SSH key pair (OpenSSH format)
  rsa2048  — RSA 2048-bit key pair (PKCS#8 PEM)
  rsa4096  — RSA 4096-bit key pair (PKCS#8 PEM)
  p256     — ECDSA P-256 key pair (PKCS#8 PEM)
  p384     — ECDSA P-384 key pair (PKCS#8 PEM)
  x25519   — X25519 Diffie-Hellman key pair (PKCS#8 PEM)

With --derive, generates a deterministic key from master password + realm.`,
		Example: `  gophkeeper generate key --type ed25519 --out ~/.ssh/id_ed25519
  gophkeeper generate key --type rsa4096 --out server.key --pub server.pub
  gophkeeper generate key --type raw
  gophkeeper generate key --type ed25519 --derive --realm deploy-server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			kt := crypto.KeyType(keyType)
			var (
				key crypto.GeneratedKey
				err error
			)

			if determin {
				if realm == "" {
					return fmt.Errorf("--realm is required with --derive")
				}
				fmt.Fprint(os.Stderr, "Master password: ")
				password, rerr := term.ReadPassword(int(syscall.Stdin))
				fmt.Fprintln(os.Stderr)
				if rerr != nil {
					return rerr
				}
				kdfParams := crypto.KDFParams{
					Algo: "argon2id", Memory: 64 * 1024, Time: 3, Threads: 4,
					Salt: []byte("gophkeeper-cli-keygen-v1"),
				}
				masterKey := crypto.DeriveKey(password, kdfParams)
				key, err = crypto.DeriveKeyFromMaster(masterKey, realm, kt)
			} else {
				key, err = crypto.GenerateKey(kt)
			}
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}

			privData := key.PrivateKey
			if kt == crypto.KeyTypeRaw {
				privData = []byte(hex.EncodeToString(privData) + "\n")
			}

			if outFile != "" {
				if err := os.WriteFile(outFile, privData, 0600); err != nil {
					return fmt.Errorf("write private key: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Private key written to %s\n", outFile)
			} else {
				fmt.Print(string(privData))
			}

			if len(key.PublicKey) > 0 {
				if pubFile != "" {
					if err := os.WriteFile(pubFile, key.PublicKey, 0600); err != nil {
						return fmt.Errorf("write public key: %w", err)
					}
					fmt.Fprintf(os.Stderr, "Public key written to %s\n", pubFile)
				} else if outFile == "" {
					fmt.Println("--- PUBLIC KEY ---")
					fmt.Print(string(key.PublicKey))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&keyType, "type", "t", "ed25519", "key type: raw|ed25519|rsa2048|rsa4096|p256|p384|x25519")
	cmd.Flags().StringVarP(&realm, "realm", "r", "", "realm for deterministic derivation")
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write private key to file (default: stdout)")
	cmd.Flags().StringVar(&pubFile, "pub", "", "write public key to file (default: stdout)")
	cmd.Flags().BoolVar(&determin, "derive", false, "derive key deterministically from master password + realm")
	return cmd
}
