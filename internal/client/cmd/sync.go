package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	syncpb "github.com/efer92/go-yandex-gophkeeper/gen/sync"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/client/grpcclient"
)

func newSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Stream live vault updates from the server",
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

			ctx, cancel := context.WithCancel(client.WithAuth(context.Background()))
			defer cancel()

			quit := make(chan os.Signal, 1)
			signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-quit
				cancel()
			}()

			syncClient := syncpb.NewSyncServiceClient(client.Conn())
			stream, err := syncClient.Subscribe(ctx, &syncpb.SubscribeRequest{})
			if err != nil {
				return fmt.Errorf("subscribe: %w", err)
			}

			fmt.Println("Listening for vault updates (Ctrl-C to stop)...")
			for {
				evt, err := stream.Recv()
				if err == io.EOF {
					return nil
				}
				if err != nil {
					if ctx.Err() != nil {
						return nil
					}
					return fmt.Errorf("recv: %w", err)
				}
				switch evt.Type {
				case syncpb.SyncEvent_UPSERT:
					fmt.Printf("[UPSERT] %s (%s)\n", evt.Item.Id, evt.Item.Metadata)
				case syncpb.SyncEvent_DELETE:
					fmt.Printf("[DELETE] %s\n", evt.DeletedId)
				}
			}
		},
	}
}
