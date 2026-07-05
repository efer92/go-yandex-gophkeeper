package cmd

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/tui"
)

// tuiRunE is the shared RunE for both the root command and the `tui` subcommand.
var tuiRunE = func(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if srv, _ := cmd.Root().PersistentFlags().GetString("server"); srv != "" {
		cfg.ServerAddr = srv
	}
	launcher, err := tui.NewLauncher(cfg)
	if err != nil {
		return err
	}
	p := tea.NewProgram(launcher, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive terminal UI",
		RunE:  tuiRunE,
	}
}
