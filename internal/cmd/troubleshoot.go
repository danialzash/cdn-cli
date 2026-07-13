package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func newTroubleshootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "troubleshoot",
		Short: "Diagnostics and health checks",
	}
	cmd.AddCommand(newTroubleshootSmartCheckCmd())
	return cmd
}

func newTroubleshootSmartCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "smartcheck <domain-id>",
		Short:   "Run smart check diagnostics for a domain",
		Aliases: []string{"smart-check"},
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domainID := args[0]

			withContext(func(ctx context.Context) error {
				check, err := c.GetLatestSmartCheck(ctx, domainID)
				if err != nil {
					return fmt.Errorf("smart check for %q: %w", domainID, err)
				}
				return printer().PrintSmartCheck(check)
			})
		},
	}
}
