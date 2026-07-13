package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/config"
	"github.com/vergecloud/cdn-cli/internal/output"
)

const version = "0.1.0"

var (
	jsonOutput bool
	verbose    bool
	apiURL     string
	apiKey     string
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "verge",
		Short: "VergeCloud CDN CLI",
		Long:  "Manage VergeCloud CDN resources from the terminal.",
	}

	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable request logging")
	root.PersistentFlags().StringVar(&apiURL, "api-url", "", "Override API base URL")
	root.PersistentFlags().StringVar(&apiKey, "api-key", "", "Override API key")

	root.AddCommand(
		newAuthCmd(),
		newDomainsCmd(),
		newWafCmd(),
		newFirewallCmd(),
		newTroubleshootCmd(),
		newVersionCmd(),
	)

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vergecloud-cli/%s\n", version)
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
	if apiKey != "" {
		cfg.APIKey = apiKey
	}
	if cfg.APIURL == "" {
		cfg.APIURL = config.DefaultAPIURL
	}
	return cfg, nil
}

func newAPIClient(cfg *config.Config) (*client.Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("not authenticated: run `verge auth login --api-key <key>`")
	}
	return client.New(client.Options{
		BaseURL: cfg.APIURL,
		APIKey:  cfg.APIKey,
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
