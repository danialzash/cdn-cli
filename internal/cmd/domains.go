package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func newDomainsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "domains",
		Short:   "Manage CDN domains",
		Aliases: []string{"domain"},
	}

	cmd.AddCommand(newDomainsListCmd(), newDomainsGetCmd())
	return cmd
}

func newDomainsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all domains",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				domains, err := c.ListDomains(ctx)
				if err != nil {
					return err
				}
				if jsonOutput {
					return printer().PrintJSON(domains)
				}
				if len(domains) == 0 {
					printer().PrintMessage("No domains found.")
					return nil
				}
				return printer().PrintDomains(domains)
			})
		},
	}
}

func newDomainsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain-id-or-name>",
		Short: "Get domain details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domainID := args[0]

			withContext(func(ctx context.Context) error {
				if jsonOutput {
					raw, err := c.Raw(ctx, "GET", "/domains/"+domainID)
					if err != nil {
						return err
					}
					return printer().PrintRawJSON(raw)
				}

				domain, err := c.GetDomain(ctx, domainID)
				if err != nil {
					return fmt.Errorf("get domain %q: %w", domainID, err)
				}
				return printer().PrintDomain(domain)
			})
		},
	}
}
