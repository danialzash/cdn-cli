package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/help"
	"github.com/vergecloud/cdn-cli/internal/update"
)

func newUpdateCmd() *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download and install the latest CLI release",
		Long: `Check for and install the latest verge release from GitHub.

Examples:
  verge update --check          Show whether a newer version is available
  verge update                  Download, verify checksum, and replace the binary`,
		Run: func(cmd *cobra.Command, args []string) {
			withContext(func(ctx context.Context) error {
				info, err := update.Check(ctx)
				if err != nil {
					return err
				}

				if checkOnly {
					if info.NeedsUpdate {
						fmt.Printf("Update available: %s → %s\n", info.Current, info.Latest)
						fmt.Printf("Run: verge update\n")
					} else {
						fmt.Printf("vergecloud-cli/%s (up to date)\n", info.Current)
					}
					return nil
				}

				if !info.NeedsUpdate {
					fmt.Printf("vergecloud-cli/%s (already up to date)\n", info.Current)
					return nil
				}

				fmt.Printf("Updating %s → %s ...\n", info.Current, info.Latest)
				if err := update.Apply(ctx); err != nil {
					return err
				}
				fmt.Printf("Updated to vergecloud-cli/%s\n", info.Latest)
				return nil
			})
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "Only check for updates; do not install")
	return cmd
}

func newGettingStartedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "getting-started",
		Short: "Install, authenticate, and first commands",
		Long: `Getting started with the VergeCloud CDN CLI

INSTALL

  curl -fsSL https://raw.githubusercontent.com/danialzash/cdn-cli/main/scripts/install.sh | sh

  Or download from: https://github.com/danialzash/cdn-cli/releases

UPDATE

  verge update --check
  verge update

AUTHENTICATE

  verge auth api-key          How to create an API key in the panel
  verge auth login --api-key <key>
  verge auth login --token <jwt>
  verge auth status

FIRST COMMANDS

  verge domains list
  verge dns list example.com
  verge reports traffic example.com --period 24h
  verge --help`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(help.GettingStartedGuide())
		},
	}
}
