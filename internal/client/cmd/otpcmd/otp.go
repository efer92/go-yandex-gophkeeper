// Package otpcmd implements TOTP code generation CLI commands.
package otpcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/atotto/clipboard"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	vaultpb "github.com/efer92/go-yandex-gophkeeper/gen/vault"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/grpcclient"
)

// OTPPayload is the JSON stored inside an OTP vault item.
type OTPPayload struct {
	Secret string `json:"secret"`
	Label  string `json:"label"`
	Issuer string `json:"issuer"`
}

// NewOTPCmd creates the otp sub-command tree.
func NewOTPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "otp",
		Short: "Manage TOTP secrets and generate codes",
	}
	cmd.AddCommand(newOTPAddCmd(), newOTPListCmd(), newOTPCodeCmd())
	return cmd
}

func newOTPAddCmd() *cobra.Command {
	var secret, label, issuer string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a TOTP secret to the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := json.Marshal(OTPPayload{Secret: secret, Label: label, Issuer: issuer}) // #nosec G117 -- payload is ChaCha20-encrypted before the gRPC call
			if err != nil {
				return err
			}
			client, vaultSvc, err := vaultClient()
			if err != nil {
				return err
			}
			defer client.Close()

			resp, err := vaultSvc.CreateItem(client.WithAuth(context.Background()), vaultpb.CreateItemRequest_builder{
				Type:     commonpb.ItemType_OTP,
				Payload:  payload,
				Metadata: label,
			}.Build())
			if err != nil {
				return fmt.Errorf("add otp: %w", err)
			}
			fmt.Printf("OTP secret added: %s\n", resp.GetItem().GetId())
			return nil
		},
	}
	cmd.Flags().StringVar(&secret, "secret", "", "base32 TOTP secret (required)")
	cmd.Flags().StringVar(&label, "label", "", "account label (required)")
	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer name")
	cmd.MarkFlagRequired("secret") //nolint:errcheck
	cmd.MarkFlagRequired("label")  //nolint:errcheck
	return cmd
}

func newOTPListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored TOTP entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, vaultSvc, err := vaultClient()
			if err != nil {
				return err
			}
			defer client.Close()

			resp, err := vaultSvc.ListItems(client.WithAuth(context.Background()), vaultpb.ListItemsRequest_builder{
				TypeFilter: commonpb.ItemType_OTP,
			}.Build())
			if err != nil {
				return fmt.Errorf("list otp: %w", err)
			}
			for _, item := range resp.GetItems() {
				var p OTPPayload
				_ = json.Unmarshal(item.GetPayload(), &p)
				fmt.Printf("%-36s  %s (%s)\n", item.GetId(), p.Label, p.Issuer)
			}
			return nil
		},
	}
}

func newOTPCodeCmd() *cobra.Command {
	var copyCode bool
	cmd := &cobra.Command{
		Use:   "code <id>",
		Short: "Generate a current TOTP code for a vault entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, vaultSvc, err := vaultClient()
			if err != nil {
				return err
			}
			defer client.Close()

			resp, err := vaultSvc.GetItem(client.WithAuth(context.Background()), vaultpb.GetItemRequest_builder{Id: args[0]}.Build())
			if err != nil {
				return fmt.Errorf("get otp: %w", err)
			}
			var p OTPPayload
			if err := json.Unmarshal(resp.GetItem().GetPayload(), &p); err != nil {
				return fmt.Errorf("decode otp payload: %w", err)
			}
			code, err := totp.GenerateCodeCustom(p.Secret, time.Now(), totp.ValidateOpts{
				Period:    30,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if err != nil {
				return fmt.Errorf("generate code: %w", err)
			}
			remaining := 30 - (time.Now().Unix() % 30)
			fmt.Printf("%s  (%ds remaining)\n", code, remaining)

			if copyCode {
				if err := clipboard.WriteAll(code); err != nil {
					return fmt.Errorf("copy to clipboard: %w", err)
				}
				fmt.Println("Code copied to clipboard.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&copyCode, "copy", false, "copy code to clipboard")
	return cmd
}

func vaultClient() (*grpcclient.Client, vaultpb.VaultServiceClient, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	c, err := grpcclient.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	return c, vaultpb.NewVaultServiceClient(c.Conn()), nil
}
