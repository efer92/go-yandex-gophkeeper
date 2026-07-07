// Package credential implements CRUD CLI commands for login/password vault items.
package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"

	commonpb "github.com/efer92/go-yandex-gophkeeper/gen/common"
	vaultpb "github.com/efer92/go-yandex-gophkeeper/gen/vault"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/grpcclient"
)

// CredentialPayload is the JSON structure stored inside an encrypted vault item of type credential.
// Field names match tui.LoginPayload so CLI and TUI share the same vault format.
type CredentialPayload struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// NewCredentialCmd creates the credential sub-command tree.
func NewCredentialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credential",
		Short: "Manage login/password credentials",
	}
	cmd.AddCommand(newAddCmd(), newGetCmd(), newListCmd(), newDeleteCmd())
	return cmd
}

func newAddCmd() *cobra.Command {
	var username, password, name, url string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := json.Marshal(CredentialPayload{
				Name:     name,
				Username: username,
				Password: password,
				URL:      url,
			})
			if err != nil {
				return err
			}
			client, vaultSvc, err := vaultClient()
			if err != nil {
				return err
			}
			defer client.Close()

			resp, err := vaultSvc.CreateItem(client.WithAuth(context.Background()), vaultpb.CreateItemRequest_builder{
				Type:     commonpb.ItemType_CREDENTIAL,
				Payload:  payload,
				Metadata: name,
			}.Build())
			if err != nil {
				return fmt.Errorf("add credential: %w", err)
			}
			fmt.Printf("Created: %s\n", resp.GetItem().GetId())
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "name / label (required)")
	cmd.Flags().StringVar(&username, "username", "", "username or login (required)")
	cmd.Flags().StringVar(&password, "password", "", "password (required)")
	cmd.Flags().StringVar(&url, "url", "", "website URL (optional)")
	cmd.MarkFlagRequired("name")     //nolint:errcheck
	cmd.MarkFlagRequired("username") //nolint:errcheck
	cmd.MarkFlagRequired("password") //nolint:errcheck
	return cmd
}

func newGetCmd() *cobra.Command {
	var copyPwd bool
	var field string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Get a credential by name or ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, vaultSvc, err := vaultClient()
			if err != nil {
				return err
			}
			defer client.Close()

			ctx := client.WithAuth(context.Background())
			item, err := findCredential(ctx, vaultSvc, args[0])
			if err != nil {
				return err
			}

			p := parsePayload(item.GetPayload(), item.GetMetadata())

			// --field: print a single value, no label
			if field != "" {
				fields := map[string]string{
					"name":     p.Name,
					"username": p.Username, "login": p.Username, "user": p.Username,
					"password": p.Password, "pass": p.Password, "pwd": p.Password,
					"url":   p.URL,
					"notes": p.Notes,
					"id":    item.GetId(),
				}
				v, ok := fields[strings.ToLower(field)]
				if !ok {
					return fmt.Errorf("unknown field %q (name|username|password|url|notes|id)", field)
				}
				fmt.Println(v)
				return nil
			}

			// --json: machine-readable output
			if asJSON {
				out := map[string]string{
					"id":       item.GetId(),
					"name":     p.Name,
					"username": p.Username,
					"password": p.Password,
					"url":      p.URL,
					"notes":    p.Notes,
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}

			fmt.Printf("Name:     %s\n", p.Name)
			fmt.Printf("Username: %s\n", p.Username)
			fmt.Printf("Password: %s\n", p.Password)
			if p.URL != "" {
				fmt.Printf("URL:      %s\n", p.URL)
			}
			if p.Notes != "" {
				fmt.Printf("Notes:    %s\n", p.Notes)
			}
			fmt.Printf("ID:       %s\n", item.GetId())

			if copyPwd {
				if err := clipboard.WriteAll(p.Password); err != nil {
					return fmt.Errorf("copy to clipboard: %w", err)
				}
				fmt.Println("Password copied to clipboard.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&copyPwd, "copy", false, "copy password to clipboard")
	cmd.Flags().StringVar(&field, "field", "", "print a single field value: name|username|password|url|notes|id")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON (pipe to jq)")
	return cmd
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, vaultSvc, err := vaultClient()
			if err != nil {
				return err
			}
			defer client.Close()

			resp, err := vaultSvc.ListItems(client.WithAuth(context.Background()), vaultpb.ListItemsRequest_builder{
				TypeFilter: commonpb.ItemType_CREDENTIAL,
			}.Build())
			if err != nil {
				return fmt.Errorf("list credentials: %w", err)
			}

			if len(resp.GetItems()) == 0 {
				fmt.Println("No credentials found.")
				return nil
			}

			fmt.Printf("%-30s  %-30s  %s\n", "Name", "Username", "URL")
			fmt.Println(strings.Repeat("-", 75))
			for _, item := range resp.GetItems() {
				p := parsePayload(item.GetPayload(), item.GetMetadata())
				fmt.Printf("%-30s  %-30s  %s\n", p.Name, p.Username, p.URL)
			}
			return nil
		},
	}
}

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name|id>",
		Short: "Delete a credential by name or ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, vaultSvc, err := vaultClient()
			if err != nil {
				return err
			}
			defer client.Close()

			ctx := client.WithAuth(context.Background())
			item, err := findCredential(ctx, vaultSvc, args[0])
			if err != nil {
				return err
			}

			_, err = vaultSvc.DeleteItem(ctx, vaultpb.DeleteItemRequest_builder{Id: item.GetId()}.Build())
			if err != nil {
				return fmt.Errorf("delete credential: %w", err)
			}
			fmt.Printf("Deleted: %s\n", item.GetMetadata())
			return nil
		},
	}
}

// looksLikeUUID reports whether s has UUID format (36 chars, hyphens at positions 8/13/18/23).
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// findCredential resolves a credential by UUID or by name (case-insensitive substring).
func findCredential(ctx context.Context, svc vaultpb.VaultServiceClient, query string) (*commonpb.VaultItem, error) {
	if looksLikeUUID(query) {
		resp, err := svc.GetItem(ctx, vaultpb.GetItemRequest_builder{Id: query}.Build())
		if err != nil {
			return nil, fmt.Errorf("get credential: %w", err)
		}
		return resp.GetItem(), nil
	}

	list, lerr := svc.ListItems(ctx, vaultpb.ListItemsRequest_builder{TypeFilter: commonpb.ItemType_CREDENTIAL}.Build())
	if lerr != nil {
		return nil, fmt.Errorf("list credentials: %w", lerr)
	}

	queryLow := strings.ToLower(query)
	var matches []*commonpb.VaultItem
	for _, it := range list.GetItems() {
		if strings.Contains(strings.ToLower(it.GetMetadata()), queryLow) {
			matches = append(matches, it)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("credential %q not found", query)
	case 1:
		return matches[0], nil
	default:
		fmt.Printf("Multiple matches for %q:\n", query)
		for _, m := range matches {
			fmt.Printf("  %s  %s\n", m.GetId(), m.GetMetadata())
		}
		return nil, fmt.Errorf("refine your query to match exactly one credential")
	}
}

// parsePayload decodes a credential payload, handling both old {"login":...}
// and new {"username":...} field names.
func parsePayload(raw []byte, meta string) CredentialPayload {
	var p CredentialPayload
	_ = json.Unmarshal(raw, &p)
	if p.Name == "" {
		p.Name = meta
	}
	// backward-compat: old format used "login" field
	if p.Username == "" {
		var old struct {
			Login string `json:"login"`
		}
		if json.Unmarshal(raw, &old) == nil && old.Login != "" {
			p.Username = old.Login
		}
	}
	return p
}

// vaultClient creates a gRPC client and vault service stub from the loaded config.
func vaultClient() (*grpcclient.Client, vaultpb.VaultServiceClient, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	client, err := grpcclient.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	return client, vaultpb.NewVaultServiceClient(client.Conn()), nil
}
