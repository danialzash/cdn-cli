package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/config"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication",
	}

	cmd.AddCommand(newAuthLoginCmd(), newAuthStatusCmd(), newAuthLogoutCmd())
	return cmd
}

func newAuthLoginCmd() *cobra.Command {
	var loginAPIKey string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store API key in local config",
		Run: func(cmd *cobra.Command, args []string) {
			key := loginAPIKey
			if key == "" {
				key = apiKey
			}
			if key == "" {
				exitOnError(fmt.Errorf("API key is required: use --api-key"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			cfg.APIKey = key
			exitOnError(config.Save(cfg))

			c, err := clientFromConfig(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				if err := c.Ping(ctx); err != nil {
					_ = config.Clear()
					return fmt.Errorf("API key validation failed: %w", err)
				}
				printer().PrintMessage("Authentication saved successfully.")
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&loginAPIKey, "api-key", "", "VergeCloud API key")
	return cmd
}

func newAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			authenticated := cfg.APIKey != ""
			if authenticated {
				c, err := clientFromConfig(cfg)
				exitOnError(err)
				withContext(func(ctx context.Context) error {
					if err := c.Ping(ctx); err != nil {
						authenticated = false
					}
					return printer().PrintAuthStatus(authenticated, cfg.APIURL)
				})
				return
			}

			exitOnError(printer().PrintAuthStatus(false, cfg.APIURL))
		},
	}
}

func newAuthLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove stored API key",
		Run: func(cmd *cobra.Command, args []string) {
			exitOnError(config.Clear())
			printer().PrintMessage("Logged out. API key removed from local config.")
		},
	}
}

func clientFromConfig(cfg *config.Config) (*client.Client, error) {
	return newAPIClient(cfg)
}
