package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func newSmartCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "smartcheck <domain>",
		Short:   "Run smart check diagnostics for a domain",
		Aliases: []string{"smart-check"},
		Long: `Run smart check diagnostics for a domain.

Examples:
  verge smartcheck example.com
  verge smartcheck 11111111-1111-1111-1111-111111111111`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				check, err := c.GetLatestSmartCheck(ctx, domain)
				if err != nil {
					return fmt.Errorf("smart check for %q: %w", domain, err)
				}
				return printer().PrintSmartCheck(check)
			})
		},
	}
}
