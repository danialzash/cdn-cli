package cmd

import (
	"context"

	"github.com/spf13/cobra"
)

func newWafCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waf",
		Short: "Web Application Firewall resources",
	}
	cmd.AddCommand(newWafPackagesCmd())
	return cmd
}

func newWafPackagesCmd() *cobra.Command {
	var domain string

	cmd := &cobra.Command{
		Use:   "packages",
		Short: "List WAF packages",
		Long: `List WAF packages.

Without --domain, shows the global WAF package catalog.
With --domain, shows packages attached to a domain with mode and status.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				packages, err := c.ListWafPackages(ctx, domain)
				if err != nil {
					return err
				}
				if jsonOutput {
					return printer().PrintJSON(packages)
				}
				if len(packages) == 0 {
					printer().PrintMessage("No WAF packages found.")
					return nil
				}
				return printer().PrintWafPackages(packages)
			})
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "Domain ID or name for domain-specific packages")
	return cmd
}
