package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newWafCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waf <domain>",
		Short: "Web Application Firewall",
		Long: `Manage and inspect Web Application Firewall settings.

Examples:
  verge waf packages
  verge waf get crs
  verge waf example.com
  verge waf update example.com --mode protect`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				settings, err := c.GetWafSettings(ctx, domain)
				if err != nil {
					return err
				}
				return printer().PrintWafSettings(settings)
			})
		},
	}

	cmd.AddCommand(
		newWafPackagesCmd(),
		newWafGetPackageCmd(),
		newWafUpdateCmd(),
	)
	return cmd
}

func newWafPackagesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "packages",
		Short: "List global WAF packages",
		Long:  `List the global WAF package catalog (e.g. crs, comodo, default).`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				packages, err := c.ListWafPackages(ctx)
				if err != nil {
					return fmt.Errorf("list WAF packages: %w", err)
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
}

func newWafGetPackageCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <package-id>",
		Short: "Get WAF package details",
		Long: `Get details for a global WAF package by ID or name.

Examples:
  verge waf get crs
  verge waf get comodo
  verge waf get default`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			packageID := args[0]

			withContext(func(ctx context.Context) error {
				details, err := c.GetWafPackage(ctx, packageID)
				if err != nil {
					return err
				}
				return printer().PrintWafPackageDetails(details)
			})
		},
	}
}

func newWafUpdateCmd() *cobra.Command {
	var mode string

	cmd := &cobra.Command{
		Use:   "update <domain>",
		Short: "Update WAF mode for a domain",
		Long: `Update the WAF mode for a domain. Only --mode can be changed.

Examples:
  verge waf update example.com --mode protect
  verge waf update example.com --mode detect
  verge waf update example.com --mode off`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !cmd.Flags().Changed("mode") {
				exitOnError(fmt.Errorf("--mode is required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				settings, err := c.UpdateWafSettings(ctx, domain, client.UpdateWafSettingsInput{
					Mode: &mode,
				})
				if err != nil {
					return err
				}
				if jsonOutput {
					return printer().PrintJSON(settings)
				}
				printer().PrintMessage("WAF settings updated.")
				return printer().PrintWafSettings(settings)
			})
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "", "WAF mode: off, detect, protect")
	return cmd
}
