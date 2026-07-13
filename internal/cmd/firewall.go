package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func newFirewallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firewall",
		Short: "Firewall rules",
	}
	cmd.AddCommand(newFirewallListCmd())
	return cmd
}

func newFirewallListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <domain-id>",
		Short: "List firewall rules for a domain",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domainID := args[0]

			withContext(func(ctx context.Context) error {
				rules, err := c.ListFirewallRules(ctx, domainID)
				if err != nil {
					return fmt.Errorf("list firewall rules for %q: %w", domainID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(rules)
				}
				if len(rules) == 0 {
					printer().PrintMessage("No firewall rules found.")
					return nil
				}
				return printer().PrintFirewallRules(rules)
			})
		},
	}
}
