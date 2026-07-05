package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/efer92/go-yandex-gophkeeper/internal/shared/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version and build date",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("GophKeeper %s (built %s)\n", version.Version, version.BuildDate)
		},
	}
}
