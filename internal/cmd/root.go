package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/config"
	"github.com/vergecloud/cdn-cli/internal/output"
	"github.com/vergecloud/cdn-cli/internal/update"
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
		Use:           "verge",
		Short:         "VergeCloud CDN CLI",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `verge is a command-line interface for the VergeCloud CDN API.

Configuration is stored in ~/.config/vergecloud/config.yaml.

GETTING STARTED

  verge getting-started         Install, login, and first commands
  verge auth api-key            Create an API key at panel.vergecloud.dev
  verge auth login --api-key KEY
  verge auth login --token JWT
  verge update                  Install the latest release

COMMAND GROUPS

  auth              Login, logout, and check authentication status
  domains           List, get, inspect, and diagnose domains
  dns               List, add, update, delete, and verify DNS records
  firewall          Manage firewall rules (list, get, add, update, delete)
  page-rules        Manage page rules
  cache             View, update, and purge cache settings
  acceleration      View and update acceleration and image resize settings
  lists             Manage IP and value lists
  ssl               SSL/TLS settings, certificates, and managed orders
  reports           Analytics and traffic reports with terminal charts
  waf               WAF package catalog, domain settings, and mode updates
  smartcheck        Run smart check diagnostics for a domain
  update            Check for and install CLI updates
  getting-started   Install, authenticate, and first commands
  version           Print CLI version

Run verge reports --help or verge waf --help for subcommands.

GLOBAL FLAGS

  --json      Output raw JSON instead of formatted tables
  --verbose   Log HTTP requests to stderr
  --api-url   Override API base URL
  --api-key   Override API key for a single command
  --token     Override bearer token for a single command

ENVIRONMENT

  VERGECLOUD_API_KEY    API key (alternative to config file)
  VERGECLOUD_TOKEN      Bearer token (alternative to config file)
  VERGECLOUD_API_URL    API base URL override

See also: man verge-reports, man verge-waf, man verge-ssl, man verge-dns`,
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
		newSmartCheckCmd(),
		newDNSCmd(),
		newCacheCmd(),
		newAccelerationCmd(),
		newListsCmd(),
		newSslCmd(),
		newReportsCmd(),
		newUpdateCmd(),
		newGettingStartedCmd(),
		newVersionCmd(),
	)

	return root
}

func newVersionCmd() *cobra.Command {
	var checkUpdate bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vergecloud-cli/%s\n", version.Version)
			if !checkUpdate {
				return
			}
			withContext(func(ctx context.Context) error {
				info, err := update.Check(ctx)
				if err != nil {
					return err
				}
				if info.NeedsUpdate {
					fmt.Printf("Update available: %s → %s (run: verge update)\n", info.Current, info.Latest)
				} else {
					fmt.Println("Up to date.")
				}
				return nil
			})
		},
	}

	cmd.Flags().BoolVar(&checkUpdate, "check", false, "Check GitHub for a newer release")
	return cmd
}

func loadRuntimeConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if err := config.ApplyEnv(cfg); err != nil {
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
		return nil, fmt.Errorf("not authenticated: run `verge auth login`, set VERGECLOUD_API_KEY/VERGECLOUD_TOKEN, or see `verge auth api-key`")
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
