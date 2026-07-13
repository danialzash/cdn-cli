package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/config"
	"github.com/vergecloud/cdn-cli/internal/sdk"
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
	var (
		loginAPIKey    string
		loginBearer    string
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store credentials in local config",
		Long: `Authenticate using either an API key or a bearer token.

Provide exactly one credential type:
  verge auth login --api-key <key>
  verge auth login --token <jwt>`,
		Run: func(cmd *cobra.Command, args []string) {
			key := loginAPIKey
			if key == "" {
				key = apiKey
			}
			token := loginBearer
			if token == "" {
				token = bearerToken
			}

			if key != "" && token != "" {
				exitOnError(fmt.Errorf("provide only one credential: --api-key or --token"))
			}
			if key == "" && token == "" {
				exitOnError(fmt.Errorf("credential required: use --api-key <key> or --token <jwt>"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			if key != "" {
				cfg.SetAPIKey(key)
			} else {
				cfg.SetBearerToken(token)
			}
			exitOnError(config.Save(cfg))

			c, err := clientFromConfig(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				if err := c.Ping(ctx); err != nil {
					_ = config.Clear()
					return fmt.Errorf("%s validation failed: %w", cfg.AuthMethodLabel(), err)
				}
				printer().PrintMessage(fmt.Sprintf("Authentication saved successfully (%s).", cfg.AuthMethodLabel()))
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&loginAPIKey, "api-key", "", "VergeCloud API key (X-API-Key header)")
	cmd.Flags().StringVar(&loginBearer, "token", "", "Bearer token (Authorization header)")
	return cmd
}

func newAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			authenticated := cfg.IsAuthenticated()
			if authenticated {
				c, err := clientFromConfig(cfg)
				exitOnError(err)
				withContext(func(ctx context.Context) error {
					if err := c.Ping(ctx); err != nil {
						authenticated = false
					}
					return printer().PrintAuthStatus(authenticated, cfg.APIURL, cfg.AuthMethodLabel())
				})
				return
			}

			exitOnError(printer().PrintAuthStatus(false, cfg.APIURL, "none"))
		},
	}
}

func newAuthLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove stored credentials",
		Run: func(cmd *cobra.Command, args []string) {
			exitOnError(config.Clear())
			printer().PrintMessage("Logged out. Credentials removed from local config.")
		},
	}
}

func clientFromConfig(cfg *config.Config) (*client.Client, error) {
	return newAPIClient(cfg)
}

func authFromConfig(cfg *config.Config) sdk.Auth {
	cfg.NormalizeAuthMethod()
	switch cfg.AuthMethod {
	case config.AuthMethodBearer:
		return sdk.Auth{Method: sdk.AuthMethodBearer, Token: cfg.BearerToken}
	default:
		return sdk.Auth{Method: sdk.AuthMethodAPIKey, Token: cfg.APIKey}
	}
}
