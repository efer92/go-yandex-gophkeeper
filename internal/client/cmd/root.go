// Package cmd implements the GophKeeper CLI commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/cmd/auth"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/cmd/credential"
)

var rootCmd = &cobra.Command{
	Use:          "gophkeeper",
	Short:        "GophKeeper — secure password manager",
	SilenceUsage: true,
	RunE:         tuiRunE, // default: launch TUI
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(auth.NewAuthCmd())
	rootCmd.AddCommand(credential.NewCredentialCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newTUICmd())
	rootCmd.AddCommand(newSyncCmd())

	rootCmd.PersistentFlags().String("vault", "", "path to .gkdb vault file (overrides config)")
	rootCmd.PersistentFlags().String("server", "", "server address (overrides config)")
}
