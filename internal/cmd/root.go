package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/config"
	"github.com/vergecloud/cdn-cli/internal/output"
	"github.com/vergecloud/cdn-cli/internal/version"
)

var (
	jsonOutput  bool
	verbose     bool
	apiURL      string
	apiKey      string
	bearerToken string
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "verge",
		Short: "VergeCloud CDN CLI",
		Long: `verge is a command-line interface for the VergeCloud CDN API.

Manage domains, DNS records, firewall rules, page rules, cache settings, acceleration, lists, SSL/TLS, WAF packages, and diagnostics
from your terminal. Run "man verge" for full documentation after installation.

Configuration is stored in ~/.config/vergecloud/config.yaml.`,
	}

	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable request logging")
	root.PersistentFlags().StringVar(&apiURL, "api-url", "", "Override API base URL")
	root.PersistentFlags().StringVar(&apiKey, "api-key", "", "Override API key")
	root.PersistentFlags().StringVar(&bearerToken, "token", "", "Override bearer token")

	root.AddCommand(
		newAuthCmd(),
		newDomainsCmd(),
		newWafCmd(),
		newFirewallCmd(),
		newPageRulesCmd(),
		newTroubleshootCmd(),
		newDNSCmd(),
		newCacheCmd(),
		newAccelerationCmd(),
		newListsCmd(),
		newSslCmd(),
		newVersionCmd(),
	)

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vergecloud-cli/%s\n", version.Version)
		},
	}
}

func loadRuntimeConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if apiURL != "" {
		cfg.APIURL = apiURL
	}
	if apiKey != "" && bearerToken != "" {
		return nil, fmt.Errorf("use only one credential override: --api-key or --token")
	}
	if apiKey != "" {
		cfg.SetAPIKey(apiKey)
	}
	if bearerToken != "" {
		cfg.SetBearerToken(bearerToken)
	}
	if cfg.APIURL == "" {
		cfg.APIURL = config.DefaultAPIURL
	}
	return cfg, nil
}

func newAPIClient(cfg *config.Config) (*client.Client, error) {
	if !cfg.IsAuthenticated() {
		return nil, fmt.Errorf("not authenticated: run `verge auth login --api-key <key>` or `verge auth login --token <jwt>`")
	}
	return client.New(client.Options{
		BaseURL: cfg.APIURL,
		Auth:    authFromConfig(cfg),
		Verbose: verbose,
	}), nil
}

func printer() *output.Printer {
	return output.New(jsonOutput)
}

func exitOnError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
	os.Exit(1)
}

func withContext(fn func(context.Context) error) {
	exitOnError(fn(context.Background()))
}
