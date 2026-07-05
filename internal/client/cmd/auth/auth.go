// Package auth implements the auth sub-commands (register, login, mfa).
package auth

import (
	"context"
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	authpb "github.com/efer92/go-yandex-gophkeeper/gen/auth"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/grpcclient"
	"github.com/efer92/go-yandex-gophkeeper/internal/shared/crypto"
)

// NewAuthCmd creates the auth parent command.
func NewAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Register, login, and manage MFA",
	}
	cmd.AddCommand(newRegisterCmd(), newLoginCmd(), newMFACmd())
	return cmd
}

func newRegisterCmd() *cobra.Command {
	var username, email string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create a new GophKeeper account",
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := readPassword("Master password: ")
			if err != nil {
				return err
			}
			confirm, err := readPassword("Confirm password: ")
			if err != nil {
				return err
			}
			if string(password) != string(confirm) {
				return fmt.Errorf("passwords do not match")
			}

			kdfParams := crypto.DefaultKDFParams()
			masterKey := crypto.DeriveKey(password, kdfParams)
			encKey, _ := crypto.StretchKey(masterKey)
			vaultKey, err := crypto.GenerateVaultSymKey()
			if err != nil {
				return err
			}
			sealedKey, err := crypto.SealVaultSymKey(vaultKey, encKey)
			if err != nil {
				return err
			}
			kdfJSON, err := crypto.MarshalKDFParams(kdfParams)
			if err != nil {
				return err
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			client, err := grpcclient.New(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer client.Close()

			resp, err := client.AuthSvc.Register(context.Background(), &authpb.RegisterRequest{
				Username:      username,
				Email:         email,
				Password:      string(password),
				VaultSymKey:   sealedKey,
				KdfParamsJson: kdfJSON,
			})
			if err != nil {
				return fmt.Errorf("register: %w", err)
			}
			fmt.Printf("Registered successfully. User ID: %s\n", resp.UserId)
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "username (required)")
	cmd.Flags().StringVar(&email, "email", "", "email address (required)")
	cmd.MarkFlagRequired("username") //nolint:errcheck
	cmd.MarkFlagRequired("email")    //nolint:errcheck
	return cmd
}

func newLoginCmd() *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to your GophKeeper account",
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := readPassword("Master password: ")
			if err != nil {
				return err
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			client, err := grpcclient.New(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer client.Close()

			resp, err := client.AuthSvc.Login(context.Background(), &authpb.LoginRequest{
				Username: username,
				Password: string(password),
			})
			if err != nil {
				return fmt.Errorf("login: %w", err)
			}

			if resp.NeedsMfa {
				var code string
				fmt.Print("MFA code: ")
				fmt.Scanln(&code) //nolint:errcheck
				mfaResp, err := client.AuthSvc.VerifyMFA(context.Background(), &authpb.VerifyMFARequest{
					SessionId: resp.SessionId,
					TotpCode:  code,
				})
				if err != nil {
					return fmt.Errorf("mfa verify: %w", err)
				}
				cfg.AccessToken = mfaResp.AccessToken
				cfg.RefreshToken = mfaResp.RefreshToken
			} else {
				cfg.AccessToken = resp.AccessToken
				cfg.RefreshToken = resp.RefreshToken
			}

			cfg.Username = username
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Printf("Logged in as %s\n", username)
			if resp.NeedsMfa {
				fmt.Println("MFA verified.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "username (required)")
	cmd.MarkFlagRequired("username") //nolint:errcheck
	return cmd
}

func newMFACmd() *cobra.Command {
	mfa := &cobra.Command{
		Use:   "mfa",
		Short: "Manage MFA settings",
	}

	setup := &cobra.Command{
		Use:   "totp-setup",
		Short: "Enroll a TOTP authenticator",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			client, err := grpcclient.New(cfg)
			if err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer client.Close()

			ctx := client.WithAuth(context.Background())
			resp, err := client.AuthSvc.EnrollTOTP(ctx, &authpb.EnrollTOTPRequest{
				Label: cfg.Username + "@GophKeeper",
			})
			if err != nil {
				return fmt.Errorf("enroll totp: %w", err)
			}

			fmt.Printf("\nScan this URL in your authenticator app:\n%s\n\n", resp.OtpauthUrl)
			fmt.Printf("Or enter manually: %s\n\n", resp.Secret)

			var code string
			fmt.Print("Enter the 6-digit code to confirm: ")
			fmt.Scanln(&code) //nolint:errcheck

			confirm, err := client.AuthSvc.ConfirmTOTP(ctx, &authpb.ConfirmTOTPRequest{
				TotpId: resp.TotpId,
				Code:   code,
			})
			if err != nil || !confirm.Ok {
				return fmt.Errorf("TOTP confirmation failed — wrong code?")
			}
			fmt.Println("TOTP MFA enabled successfully.")
			return nil
		},
	}
	mfa.AddCommand(setup)
	return mfa
}

// readPassword prompts for and reads a password without echoing. It is a package
// variable so tests can substitute a deterministic reader.
var readPassword = func(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	p, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return p, err
}
