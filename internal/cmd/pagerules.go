package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newPageRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "page-rules",
		Aliases: []string{"pagerules", "page-rule"},
		Short:   "Manage page rules",
	}

	cmd.AddCommand(
		newPageRulesListCmd(),
		newPageRulesGetCmd(),
		newPageRulesUpdateCmd(),
		newPageRulesDeleteCmd(),
	)
	return cmd
}

func newPageRulesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <domain>",
		Short: "List page rules for a domain",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				rules, err := c.ListPageRules(ctx, domain)
				if err != nil {
					return fmt.Errorf("list page rules for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(rules)
				}
				if len(rules) == 0 {
					printer().PrintMessage("No page rules found.")
					return nil
				}
				return printer().PrintPageRules(rules)
			})
		},
	}
}

func newPageRulesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain> <rule-id>",
		Short: "Get page rule details",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			ruleID := args[1]

			withContext(func(ctx context.Context) error {
				rule, err := c.GetPageRule(ctx, domain, ruleID)
				if err != nil {
					return fmt.Errorf("get page rule %q: %w", ruleID, err)
				}
				if jsonOutput {
					if len(rule.Raw) > 0 {
						return printer().PrintRawJSON(rule.Raw)
					}
					return printer().PrintJSON(rule)
				}
				return printer().PrintPageRule(rule)
			})
		},
	}
}

func newPageRulesUpdateCmd() *cobra.Command {
	var (
		url         string
		enabled     bool
		seq         int
		cacheLevel  string
		cacheMaxAge string
	)

	cmd := &cobra.Command{
		Use:   "update <domain> <rule-id>",
		Short: "Update a page rule",
		Long: `Update an existing page rule. Only pass flags you want to change.

Examples:
  verge page-rules update example.com <rule-id> --url "/api/*"
  verge page-rules update example.com <rule-id> --enabled=false
  verge page-rules update example.com <rule-id> --cache-level uri --cache-max-age 1h`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if !pageRuleUpdateFlagsChanged(cmd) {
				exitOnError(fmt.Errorf("at least one of --url, --enabled, --seq, --cache-level, or --cache-max-age is required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			ruleID := args[1]
			input := buildPageRuleUpdateInput(cmd, url, enabled, seq, cacheLevel, cacheMaxAge)

			withContext(func(ctx context.Context) error {
				rule, err := c.UpdatePageRule(ctx, domain, ruleID, input)
				if err != nil {
					return fmt.Errorf("update page rule %q: %w", ruleID, err)
				}
				if jsonOutput {
					if len(rule.Raw) > 0 {
						return printer().PrintRawJSON(rule.Raw)
					}
					return printer().PrintJSON(rule)
				}
				printer().PrintMessage("Page rule updated successfully.")
				return printer().PrintPageRule(rule)
			})
		},
	}

	cmd.Flags().StringVar(&url, "url", "", "URL pattern")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "Whether the page rule is enabled")
	cmd.Flags().IntVar(&seq, "seq", 0, "Rule sequence/order")
	cmd.Flags().StringVar(&cacheLevel, "cache-level", "", "Cache level: off, uri, query_string")
	cmd.Flags().StringVar(&cacheMaxAge, "cache-max-age", "", "Cache max age (e.g. 30m, 1h)")

	return cmd
}

func newPageRulesDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "delete <domain> <rule-id>",
		Aliases: []string{"rm"},
		Short:   "Delete a page rule",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			ruleID := args[1]

			if !force {
				ok, err := printer().Confirm(fmt.Sprintf("Delete page rule %q?", ruleID))
				exitOnError(err)
				if !ok {
					printer().PrintMessage("Aborted.")
					return
				}
			}

			withContext(func(ctx context.Context) error {
				if err := c.DeletePageRule(ctx, domain, ruleID); err != nil {
					return fmt.Errorf("delete page rule %q: %w", ruleID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(map[string]any{
						"deleted": true,
						"id":      ruleID,
					})
				}
				printer().PrintMessage("Page rule deleted successfully.")
				return nil
			})
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Delete without confirmation")
	return cmd
}

func pageRuleUpdateFlagsChanged(cmd *cobra.Command) bool {
	flags := []string{"url", "enabled", "seq", "cache-level", "cache-max-age"}
	for _, flag := range flags {
		if cmd.Flags().Changed(flag) {
			return true
		}
	}
	return false
}

func buildPageRuleUpdateInput(cmd *cobra.Command, url string, enabled bool, seq int, cacheLevel, cacheMaxAge string) client.UpdatePageRuleInput {
	input := client.UpdatePageRuleInput{}

	if cmd.Flags().Changed("url") {
		input.URL = &url
	}
	if cmd.Flags().Changed("enabled") {
		input.Enabled = &enabled
	}
	if cmd.Flags().Changed("seq") {
		input.Seq = &seq
	}
	if cmd.Flags().Changed("cache-level") {
		level := strings.ToLower(cacheLevel)
		input.CacheLevel = &level
	}
	if cmd.Flags().Changed("cache-max-age") {
		input.CacheMaxAge = &cacheMaxAge
	}

	return input
}
