package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newFirewallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firewall",
		Short: "Firewall rules",
	}
	cmd.AddCommand(
		newFirewallListCmd(),
		newFirewallGetCmd(),
		newFirewallAddCmd(),
		newFirewallUpdateCmd(),
		newFirewallDeleteCmd(),
	)
	return cmd
}

func newFirewallListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <domain>",
		Short: "List firewall rules for a domain",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				rules, err := c.ListFirewallRules(ctx, domain)
				if err != nil {
					return fmt.Errorf("list firewall rules for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(rules)
				}
				if len(rules) == 0 {
					printer().PrintMessage("No firewall rules found.")
					return nil
				}
				return printer().PrintFirewallRules(rules)
			})
		},
	}
}

func newFirewallGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain> <rule-id>",
		Short: "Get firewall rule details",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			ruleID := args[1]

			withContext(func(ctx context.Context) error {
				rule, err := c.GetFirewallRule(ctx, domain, ruleID)
				if err != nil {
					return fmt.Errorf("get firewall rule %q: %w", ruleID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(rule)
				}
				return printer().PrintFirewallRule(rule)
			})
		},
	}
}

func newFirewallAddCmd() *cobra.Command {
	var (
		name       string
		filterExpr string
		action     string
		priority   int
		enabled    bool
		note       string
	)

	cmd := &cobra.Command{
		Use:     "add <domain>",
		Aliases: []string{"create"},
		Short:   "Create a firewall rule",
		Long: `Create a firewall rule for a domain.

Examples:
  verge firewall add example.com --name "Block IR" --filter 'ip.geoip.country in {"IR"}' --action deny
  verge firewall add example.com --name "Allow office" --filter 'ip.src == 198.51.100.0/24' --action allow --priority 10`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if name == "" || filterExpr == "" || action == "" {
				exitOnError(fmt.Errorf("--name, --filter, and --action are required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				rule, err := c.CreateFirewallRule(ctx, domain, client.CreateFirewallRuleInput{
					Name:       name,
					FilterExpr: filterExpr,
					Action:     strings.ToLower(action),
					Priority:   priority,
					Enabled:    enabled,
					Note:       note,
				})
				if err != nil {
					return fmt.Errorf("create firewall rule: %w", err)
				}
				if jsonOutput {
					return printer().PrintJSON(rule)
				}
				printer().PrintMessage("Firewall rule created successfully.")
				return printer().PrintFirewallRule(rule)
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Rule name")
	cmd.Flags().StringVar(&filterExpr, "filter", "", "Wireshark-like filter expression")
	cmd.Flags().StringVar(&action, "action", "", "Action: allow, deny, bypass, challenge")
	cmd.Flags().IntVar(&priority, "priority", 0, "Rule priority")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "Whether the rule is enabled")
	cmd.Flags().StringVar(&note, "note", "", "Optional note")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("filter")
	_ = cmd.MarkFlagRequired("action")

	return cmd
}

func newFirewallUpdateCmd() *cobra.Command {
	var (
		name       string
		filterExpr string
		action     string
		priority   int
		enabled    bool
		note       string
	)

	cmd := &cobra.Command{
		Use:   "update <domain> <rule-id>",
		Short: "Update a firewall rule",
		Long: `Update an existing firewall rule. Only pass flags you want to change.

Examples:
  verge firewall update example.com <rule-id> --name "Block bad IPs"
  verge firewall update example.com <rule-id> --filter "ip.geoip.country in {\"IR\"}"
  verge firewall update example.com <rule-id> --action deny
  verge firewall update example.com <rule-id> --enabled=false`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if !firewallUpdateFlagsChanged(cmd) {
				exitOnError(fmt.Errorf("at least one of --name, --filter, --action, --priority, --enabled, or --note is required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			ruleID := args[1]
			input := buildFirewallUpdateInput(cmd, name, filterExpr, action, priority, enabled, note)

			withContext(func(ctx context.Context) error {
				rule, err := c.UpdateFirewallRule(ctx, domain, ruleID, input)
				if err != nil {
					return fmt.Errorf("update firewall rule %q: %w", ruleID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(rule)
				}
				printer().PrintMessage("Firewall rule updated successfully.")
				return printer().PrintFirewallRule(rule)
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Rule name")
	cmd.Flags().StringVar(&filterExpr, "filter", "", "Wireshark-like filter expression")
	cmd.Flags().StringVar(&action, "action", "", "Action: allow, deny, bypass, challenge")
	cmd.Flags().IntVar(&priority, "priority", 0, "Rule priority")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "Whether the rule is enabled")
	cmd.Flags().StringVar(&note, "note", "", "Optional note")

	return cmd
}

func newFirewallDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "delete <domain> <rule-id>",
		Aliases: []string{"rm"},
		Short:   "Delete a firewall rule",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			ruleID := args[1]

			if !force {
				ok, err := printer().Confirm(fmt.Sprintf("Delete firewall rule %q?", ruleID))
				exitOnError(err)
				if !ok {
					printer().PrintMessage("Aborted.")
					return
				}
			}

			withContext(func(ctx context.Context) error {
				if err := c.DeleteFirewallRule(ctx, domain, ruleID); err != nil {
					return fmt.Errorf("delete firewall rule %q: %w", ruleID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(map[string]any{
						"deleted": true,
						"id":      ruleID,
					})
				}
				printer().PrintMessage("Firewall rule deleted successfully.")
				return nil
			})
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Delete without confirmation")
	return cmd
}

func firewallUpdateFlagsChanged(cmd *cobra.Command) bool {
	flags := []string{"name", "filter", "action", "priority", "enabled", "note"}
	for _, flag := range flags {
		if cmd.Flags().Changed(flag) {
			return true
		}
	}
	return false
}

func buildFirewallUpdateInput(cmd *cobra.Command, name, filterExpr, action string, priority int, enabled bool, note string) client.UpdateFirewallRuleInput {
	input := client.UpdateFirewallRuleInput{}

	if cmd.Flags().Changed("name") {
		input.Name = &name
	}
	if cmd.Flags().Changed("filter") {
		input.FilterExpr = &filterExpr
	}
	if cmd.Flags().Changed("action") {
		action = strings.ToLower(action)
		input.Action = &action
	}
	if cmd.Flags().Changed("priority") {
		input.Priority = &priority
	}
	if cmd.Flags().Changed("enabled") {
		input.Enabled = &enabled
	}
	if cmd.Flags().Changed("note") {
		input.Note = &note
	}

	return input
}
