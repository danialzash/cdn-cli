package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache <domain>",
		Short: "Caching settings",
		Long: `Get caching settings for a domain.

Use subcommands to update settings or purge cache:
  verge cache update <domain> ...
  verge cache purge <domain> ...`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				settings, err := c.GetCacheSettings(ctx, domain)
				if err != nil {
					return fmt.Errorf("get cache settings for %q: %w", domain, err)
				}
				return printer().PrintCacheSettings(settings)
			})
		},
	}

	cmd.AddCommand(
		newCacheUpdateCmd(),
		newCachePurgeCmd(),
	)
	return cmd
}

func newCacheUpdateCmd() *cobra.Command {
	var (
		developerMode    bool
		consistentUptime bool
		maxSize          int64
		status           string
		maxAge           string
		pageAny          string
		browser          string
		scheme           bool
		bypassOnCookie   bool
		cookie           string
		queryArgs        bool
		arg              string
	)

	cmd := &cobra.Command{
		Use:   "update <domain>",
		Short: "Update caching settings",
		Long: `Update caching settings for a domain. Only pass flags you want to change.

Examples:
  verge cache update example.com --developer-mode
  verge cache update example.com --max-size 104857600 --status uri
  verge cache update example.com --max-age 1h --browser default`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !cacheUpdateFlagsChanged(cmd) {
				exitOnError(fmt.Errorf("at least one cache setting flag is required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			input := buildCacheUpdateInput(cmd, developerMode, consistentUptime, maxSize, status, maxAge, pageAny, browser, scheme, bypassOnCookie, cookie, queryArgs, arg)

			withContext(func(ctx context.Context) error {
				settings, err := c.UpdateCacheSettings(ctx, domain, input)
				if err != nil {
					return fmt.Errorf("update cache settings for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(settings)
				}
				printer().PrintMessage("Cache settings updated successfully.")
				return printer().PrintCacheSettings(settings)
			})
		},
	}

	cmd.Flags().BoolVar(&developerMode, "developer-mode", false, "Enable cache developer mode")
	cmd.Flags().BoolVar(&consistentUptime, "consistent-uptime", false, "Enable cache consistent uptime")
	cmd.Flags().Int64Var(&maxSize, "max-size", 0, "Maximum cacheable content size in bytes")
	cmd.Flags().StringVar(&status, "status", "", "Cache status: off, uri, query_string")
	cmd.Flags().StringVar(&maxAge, "max-age", "", "Cache max age (e.g. 30m, 1h, 24h)")
	cmd.Flags().StringVar(&pageAny, "page-any", "", "Cache page any duration")
	cmd.Flags().StringVar(&browser, "browser", "", "Browser cache duration (default or duration)")
	cmd.Flags().BoolVar(&scheme, "scheme", false, "Consider HTTP/HTTPS scheme in cache")
	cmd.Flags().BoolVar(&bypassOnCookie, "bypass-on-cookie", false, "Bypass cache on set-cookie header")
	cmd.Flags().StringVar(&cookie, "cookie", "", "Cookie variables to consider in cache")
	cmd.Flags().BoolVar(&queryArgs, "args", false, "Consider query string arguments in cache")
	cmd.Flags().StringVar(&arg, "arg", "", "Query string arguments to consider (& separated)")

	return cmd
}

func newCachePurgeCmd() *cobra.Command {
	var (
		purge     string
		purgeURLs []string
		purgeTags []string
	)

	cmd := &cobra.Command{
		Use:   "purge <domain>",
		Short: "Purge CDN cache",
		Long: `Purge CDN cache for a domain.

Examples:
  verge cache purge example.com
  verge cache purge example.com --purge all
  verge cache purge example.com --purge individual --purge-urls https://example.com/static/app.js
  verge cache purge example.com --purge individual --purge-urls https://a.example.com/x --purge-urls https://b.example.com/y`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			purge = strings.ToLower(purge)
			if purge == "" {
				purge = "all"
			}

			switch purge {
			case "all":
			case "individual":
				if len(purgeURLs) == 0 {
					exitOnError(fmt.Errorf("--purge-urls is required when --purge is individual"))
				}
			case "tags":
				if len(purgeTags) == 0 {
					exitOnError(fmt.Errorf("--purge-tags is required when --purge is tags"))
				}
			default:
				exitOnError(fmt.Errorf("--purge must be one of: all, individual, tags"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				if err := c.PurgeCache(ctx, domain, client.PurgeCacheInput{
					Purge:     purge,
					PurgeURLs: purgeURLs,
					PurgeTags: purgeTags,
				}); err != nil {
					return fmt.Errorf("purge cache for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(map[string]any{
						"purged": true,
						"purge":  purge,
						"domain": domain,
						"urls":   purgeURLs,
						"tags":   purgeTags,
					})
				}
				switch purge {
				case "all":
					printer().PrintMessage("Cache purge queued for entire site.")
				case "individual":
					printer().PrintMessage(fmt.Sprintf("Cache purge queued for %d URL(s).", len(purgeURLs)))
				case "tags":
					printer().PrintMessage(fmt.Sprintf("Cache purge queued for %d tag(s).", len(purgeTags)))
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&purge, "purge", "all", "Purge mode: all, individual, tags")
	cmd.Flags().StringSliceVar(&purgeURLs, "purge-urls", nil, "URLs to purge (repeatable, required for individual)")
	cmd.Flags().StringSliceVar(&purgeTags, "purge-tags", nil, "Tags to purge (repeatable, required for tags)")

	return cmd
}

func cacheUpdateFlagsChanged(cmd *cobra.Command) bool {
	flags := []string{
		"developer-mode", "consistent-uptime", "max-size", "status", "max-age",
		"page-any", "browser", "scheme", "bypass-on-cookie", "cookie", "args", "arg",
	}
	for _, flag := range flags {
		if cmd.Flags().Changed(flag) {
			return true
		}
	}
	return false
}

func buildCacheUpdateInput(
	cmd *cobra.Command,
	developerMode, consistentUptime bool,
	maxSize int64,
	status, maxAge, pageAny, browser string,
	scheme, bypassOnCookie bool,
	cookie string,
	queryArgs bool,
	arg string,
) client.UpdateCacheSettingsInput {
	input := client.UpdateCacheSettingsInput{}

	if cmd.Flags().Changed("developer-mode") {
		input.DeveloperMode = &developerMode
	}
	if cmd.Flags().Changed("consistent-uptime") {
		input.ConsistentUptime = &consistentUptime
	}
	if cmd.Flags().Changed("max-size") {
		input.MaxSize = &maxSize
	}
	if cmd.Flags().Changed("status") {
		status = strings.ToLower(status)
		input.Status = &status
	}
	if cmd.Flags().Changed("max-age") {
		input.MaxAge = &maxAge
	}
	if cmd.Flags().Changed("page-any") {
		input.PageAny = &pageAny
	}
	if cmd.Flags().Changed("browser") {
		input.Browser = &browser
	}
	if cmd.Flags().Changed("scheme") {
		input.Scheme = &scheme
	}
	if cmd.Flags().Changed("bypass-on-cookie") {
		input.BypassOnCookie = &bypassOnCookie
	}
	if cmd.Flags().Changed("cookie") {
		input.Cookie = &cookie
	}
	if cmd.Flags().Changed("args") {
		input.Args = &queryArgs
	}
	if cmd.Flags().Changed("arg") {
		input.Arg = &arg
	}

	return input
}
