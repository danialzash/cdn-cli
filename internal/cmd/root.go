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

Configuration is stored in ~/.config/vergecloud/config.yaml.
Authenticate with: verge auth login --api-key KEY

COMMAND GROUPS

  auth              Login, logout, and check authentication status
  domains           List, get, and inspect domains
  dns               List, add, update, delete, and verify DNS records
  firewall          Manage firewall rules (list, get, add, update, delete)
  page-rules        Manage page rules
  cache             View, update, and purge cache settings
  acceleration      View and update acceleration and image resize settings
  lists             Manage IP and value lists
  ssl               SSL/TLS settings, certificates, and managed orders
  reports           Analytics and traffic reports with terminal charts
  waf               WAF package catalog, domain settings, and mode updates
  troubleshoot      Run smart check diagnostics
  version           Print CLI version

REPORTS

  verge reports list
  verge reports traffic DOMAIN [--period 24h|7d|30d]
  verge reports request-summary DOMAIN   Request saved/missed/bypassed breakdown
  verge reports traffic-summary DOMAIN   Traffic saved/missed/bypassed breakdown
  verge reports traffic-saved DOMAIN     Both request and traffic summaries
  verge reports status DOMAIN              HTTP status code reports
  verge reports visitors DOMAIN
  verge reports attacks DOMAIN
  verge reports aggregated details --domains a.com,b.com
  verge reports domains-download [--output file.csv]

WAF

  verge waf packages                       List global packages (crs, comodo, default)
  verge waf get PACKAGE-ID                 Package details and rulesets
  verge waf DOMAIN                         Domain WAF configuration
  verge waf update DOMAIN --mode MODE      Update mode (off, detect, protect)

GLOBAL FLAGS

  --json      Output raw JSON instead of formatted tables
  --verbose   Log HTTP requests to stderr
  --api-url   Override API base URL
  --api-key   Override API key for a single command
  --token     Override bearer token for a single command

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
		newTroubleshootCmd(),
		newDNSCmd(),
		newCacheCmd(),
		newAccelerationCmd(),
		newListsCmd(),
		newSslCmd(),
		newReportsCmd(),
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
