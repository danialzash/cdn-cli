package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newDNSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Manage and verify DNS records",
	}

	cmd.AddCommand(
		newDNSListCmd(),
		newDNSGetCmd(),
		newDNSAddCmd(),
		newDNSVerifyCmd(),
	)
	return cmd
}

func newDNSListCmd() *cobra.Command {
	var recordType string

	cmd := &cobra.Command{
		Use:   "list <domain>",
		Short: "List DNS records with full values",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				records, err := c.ListDNSRecords(ctx, domain, recordType)
				if err != nil {
					return fmt.Errorf("list DNS records for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(records)
				}
				if len(records) == 0 {
					printer().PrintMessage("No DNS records found.")
					return nil
				}
				return printer().PrintDNSRecords(records)
			})
		},
	}

	cmd.Flags().StringVar(&recordType, "type", "", "Filter by record type (a, aaaa, cname, txt, mx, ns, ...)")
	return cmd
}

func newDNSGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain> <record-id>",
		Short: "Get DNS record details",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			recordID := args[1]

			withContext(func(ctx context.Context) error {
				record, err := c.GetDNSRecord(ctx, domain, recordID)
				if err != nil {
					return fmt.Errorf("get DNS record %q: %w", recordID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(record)
				}
				return printer().PrintDNSRecord(record)
			})
		},
	}
}

func newDNSAddCmd() *cobra.Command {
	var (
		recordType string
		name       string
		value      string
		ttl        int
		cloud      bool
		priority   int
	)

	cmd := &cobra.Command{
		Use:   "add <domain>",
		Short: "Create a DNS record",
		Long: `Create a DNS record for a domain.

Supported types: a, aaaa, cname, txt, mx, ns

Examples:
  verge dns add example.com --type a --name www --value 198.51.100.42 --ttl 300
  verge dns add example.com --type cname --name blog --value target.example.com
  verge dns add example.com --type txt --name _dmarc --value "v=DMARC1; p=none"
  verge dns add example.com --type mx --name @ --value mail.example.com --priority 10`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if recordType == "" || name == "" || value == "" {
				exitOnError(fmt.Errorf("--type, --name, and --value are required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				record, err := c.CreateDNSRecord(ctx, domain, client.CreateDNSRecordInput{
					Name:     name,
					Type:     strings.ToLower(recordType),
					Value:    value,
					TTL:      ttl,
					Cloud:    cloud,
					Priority: priority,
				})
				if err != nil {
					return fmt.Errorf("create DNS record: %w", err)
				}
				if jsonOutput {
					return printer().PrintJSON(record)
				}
				printer().PrintMessage("DNS record created successfully.")
				return printer().PrintDNSRecord(record)
			})
		},
	}

	cmd.Flags().StringVar(&recordType, "type", "", "Record type (a, aaaa, cname, txt, mx, ns)")
	cmd.Flags().StringVar(&name, "name", "", "Record name (@ for apex)")
	cmd.Flags().StringVar(&value, "value", "", "Record value")
	cmd.Flags().IntVar(&ttl, "ttl", 300, "TTL in seconds")
	cmd.Flags().BoolVar(&cloud, "cloud", false, "Enable CDN proxy (cloud)")
	cmd.Flags().IntVar(&priority, "priority", 10, "MX priority")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("value")

	return cmd
}

func newDNSVerifyCmd() *cobra.Command {
	var recordID string

	cmd := &cobra.Command{
		Use:   "verify <domain>",
		Short: "Verify DNS records resolve correctly using live DNS lookups",
		Long: `Check configured DNS records against live public DNS responses.

Uses Go's DNS resolver (similar to dig) to compare expected values from the API
with what is currently published on the internet.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				records, err := c.ListDNSRecords(ctx, domain, "")
				if err != nil {
					return fmt.Errorf("list DNS records for %q: %w", domain, err)
				}

				if recordID != "" {
					filtered := make([]client.DNSRecord, 0, 1)
					for _, record := range records {
						if record.ID == recordID {
							filtered = append(filtered, record)
							break
						}
					}
					if len(filtered) == 0 {
						return fmt.Errorf("record %q not found on domain %q", recordID, domain)
					}
					records = filtered
				}

				results := c.VerifyDNSRecords(ctx, domain, records)
				if jsonOutput {
					return printer().PrintJSON(results)
				}
				if len(results) == 0 {
					printer().PrintMessage("No DNS records to verify.")
					return nil
				}
				return printer().PrintDNSVerifyResults(results)
			})
		},
	}

	cmd.Flags().StringVar(&recordID, "record-id", "", "Verify a single record by ID")
	return cmd
}
