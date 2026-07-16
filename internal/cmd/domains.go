package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newDomainsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "domains",
		Short:   "Manage CDN domains",
		Aliases: []string{"domain"},
	}

	cmd.AddCommand(newDomainsListCmd(), newDomainsGetCmd(), newDomainsInspectCmd(), newDomainsCheckupCmd())
	return cmd
}

func newDomainsListCmd() *cobra.Command {
	var (
		status string
		sortBy string
		order  string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all domains",
		Long: `List all domains with optional filtering and sorting.

Filtering uses the API statuses parameter (active or inactive).
Sorting supports name, status, and updated_at in ascending or descending order.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := validateDomainListFlags(status, sortBy, order); err != nil {
				exitOnError(err)
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				domains, err := c.ListDomains(ctx, client.ListDomainsOptions{
					Status: status,
					SortBy: sortBy,
					Order:  order,
				})
				if err != nil {
					return err
				}
				if jsonOutput {
					return printer().PrintJSON(domains)
				}
				if len(domains) == 0 {
					printer().PrintMessage("No domains found.")
					return nil
				}
				return printer().PrintDomains(domains)
			})
		},
	}

	cmd.Flags().StringVar(&status, "status", "", "Filter by status: active or inactive")
	cmd.Flags().StringVar(&sortBy, "sort-by", "", "Sort by field: name, status, updated_at")
	cmd.Flags().StringVar(&order, "order", "", "Sort order: asc or desc")
	return cmd
}

func validateDomainListFlags(status, sortBy, order string) error {
	if status != "" {
		switch strings.ToLower(status) {
		case "active", "inactive":
		default:
			return fmt.Errorf("invalid --status %q: use active or inactive", status)
		}
	}

	if sortBy != "" {
		switch strings.ToLower(sortBy) {
		case "name", "status", "updated_at":
		default:
			return fmt.Errorf("invalid --sort-by %q: use name, status, or updated_at", sortBy)
		}
	}

	if order != "" {
		switch strings.ToLower(order) {
		case "asc", "desc":
		default:
			return fmt.Errorf("invalid --order %q: use asc or desc", order)
		}
	}

	if order != "" && sortBy == "" {
		return fmt.Errorf("--order requires --sort-by")
	}

	return nil
}

func newDomainsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain-id-or-name>",
		Short: "Get domain details",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domainID := args[0]

			withContext(func(ctx context.Context) error {
				if jsonOutput {
					raw, err := c.Raw(ctx, "GET", "/domains/"+domainID)
					if err != nil {
						return err
					}
					return printer().PrintRawJSON(raw)
				}

				domain, err := c.GetDomain(ctx, domainID)
				if err != nil {
					return fmt.Errorf("get domain %q: %w", domainID, err)
				}
				return printer().PrintDomain(domain)
			})
		},
	}
}

func newDomainsInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "inspect <domain>",
		Aliases: []string{"overview", "super"},
		Short:   "Fetch comprehensive domain details in parallel",
		Long: `Load domain configuration from all major API sections concurrently.

Fetches domain info, DNS records, firewall, WAF, DDoS, page rules, SSL, caching,
load balancing, rate limiting, acceleration, and smart-check status in parallel.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				result, err := c.InspectDomain(ctx, domain)
				if err != nil {
					return fmt.Errorf("inspect domain %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(result)
				}
				return printer().PrintDomainInspect(result)
			})
		},
	}
}
