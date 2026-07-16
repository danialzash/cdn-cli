package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newReportsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "Analytics and traffic reports",
		Long: `Fetch CDN analytics reports for domains.

Each report type is a separate subcommand. Common flags:
  --period 5m|1h|3h|6h|12h|24h|7d|30d
  --since / --until for custom ISO8601 ranges
  --filter-subdomain for subdomain-scoped reports

Examples:
  verge reports list
  verge reports traffic example.com --period 24h
  verge reports request-summary example.com --period 30d
  verge reports traffic-summary example.com --period 30d
  verge reports status example.com --period 7d
  verge reports transport-layer-proxy DOMAIN PROXY-ID --period 24h
  verge reports aggregated details --domains a.com,b.com --period 24h
  verge reports domains-download --output domains.csv`,
	}

	cmd.AddCommand(newReportsListCmd())
	cmd.AddCommand(newReportsDomainsDownloadCmd())

	domainReports := []struct {
		name  string
		short string
	}{
		{"traffic", "Total traffic and requests over time"},
		{"traffic-saved", "Cache hit/miss/bypass breakdown"},
		{"request-summary", "Request cache hit/miss/bypass summary"},
		{"traffic-summary", "Traffic cache hit/miss/bypass summary"},
		{"traffic-geo", "Traffic by country geo-map"},
		{"visitors", "Unique visitors over time"},
		{"high-request-ips", "IPs with highest request counts"},
		{"response-time", "Average response time over time"},
		{"status", "HTTP status code time-series"},
		{"status-summary", "HTTP status code summary"},
		{"errors", "Error log list"},
		{"errors-chart", "Error log chart"},
		{"error-details", "Details for a specific error message"},
		{"dns-requests", "DNS request report"},
		{"dns-geo", "DNS requests by geography"},
		{"attacks", "Attack overview"},
		{"attacks-detail", "Detailed attack events"},
		{"attacks-attackers", "Attacker IP list"},
		{"attacks-geo", "Attack geo-map"},
		{"attacks-uri", "URLs under attack"},
	}

	for _, report := range domainReports {
		cmd.AddCommand(newDomainReportCmd(report.name, report.short, 0))
	}

	cmd.AddCommand(newDomainReportCmd("transport-layer-proxy", "Transport layer proxy traffic report", 1))

	aggregated := &cobra.Command{
		Use:   "aggregated",
		Short: "Aggregated multi-domain reports",
	}
	aggregated.AddCommand(newDomainReportCmd("aggregated-details", "Aggregated report details", 0))
	aggregated.AddCommand(newDomainReportCmd("aggregated-charts", "Aggregated report charts", 0))
	aggregated.AddCommand(newDomainReportCmd("aggregated-filters", "Aggregated report filters", 0))
	cmd.AddCommand(aggregated)

	return cmd
}

func newReportsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available report types",
		Run: func(cmd *cobra.Command, args []string) {
			exitOnError(printer().PrintReportTypes(client.ReportTypes()))
		},
	}
}

func newReportsDomainsDownloadCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "domains-download",
		Short: "Download domains CSV report",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				data, err := c.DownloadDomainsReport(ctx)
				if err != nil {
					return fmt.Errorf("download domains report: %w", err)
				}
				if output != "" {
					if err := os.WriteFile(output, data, 0o644); err != nil {
						return fmt.Errorf("write report file: %w", err)
					}
					if jsonOutput {
						return printer().PrintJSON(map[string]any{
							"downloaded": true,
							"file":       output,
							"bytes":      len(data),
						})
					}
					printer().PrintMessage(fmt.Sprintf("Domains report saved to %s", output))
					return nil
				}
				_, err = os.Stdout.Write(data)
				return err
			})
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Write CSV to file instead of stdout")
	return cmd
}

func newDomainReportCmd(name, short string, extraArgs int) *cobra.Command {
	params := newReportParams()

	use := fmt.Sprintf("%s <domain>", name)
	var argCheck func(cmd *cobra.Command, args []string) error
	argCheck = func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("accepts 1 arg(s), received %d", len(args))
		}
		return nil
	}

	switch {
	case name == "transport-layer-proxy":
		use = "transport-layer-proxy <domain> <transport-layer-proxy-id>"
		argCheck = cobra.ExactArgs(2)
	case strings.HasPrefix(name, "aggregated-"):
		use = strings.TrimPrefix(name, "aggregated-")
		argCheck = cobra.NoArgs
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  argCheck,
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := ""
			if len(args) > 0 {
				domain = args[0]
			}
			proxyID := ""
			if len(args) > 1 {
				proxyID = args[1]
			}

			path, err := client.ReportPath(name, domain, proxyID)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				report, err := c.FetchReport(ctx, path, params.toClient())
				if err != nil {
					return fmt.Errorf("fetch %s report: %w", name, err)
				}
				return printer().PrintReport(name, report)
			})
		},
	}

	bindReportFlags(cmd, params, name)
	return cmd
}

type reportParams struct {
	period       string
	since        string
	until        string
	subdomain    string
	page         int
	perPage      int
	errorMessage string
	domains      string
	reportType   string
	categoryType string
	pops         string
	asns         string
}

func newReportParams() *reportParams {
	return &reportParams{period: "24h"}
}

func (p *reportParams) toClient() client.ReportParams {
	return client.ReportParams{
		Period:       p.period,
		Since:        p.since,
		Until:        p.until,
		Subdomain:    p.subdomain,
		Page:         p.page,
		PerPage:      p.perPage,
		Error:        p.errorMessage,
		Domains:      p.domains,
		ReportType:   p.reportType,
		CategoryType: p.categoryType,
		Pops:         p.pops,
		Asns:         p.asns,
	}
}

func bindReportFlags(cmd *cobra.Command, params *reportParams, name string) {
	cmd.Flags().StringVar(&params.period, "period", params.period, "Report period: 5m, 1h, 3h, 6h, 12h, 24h, 7d, 30d")
	cmd.Flags().StringVar(&params.since, "since", "", "Start time in ISO8601 UTC")
	cmd.Flags().StringVar(&params.until, "until", "", "End time in ISO8601 UTC")

	if supportsSubdomainFilter(name) {
		cmd.Flags().StringVar(&params.subdomain, "filter-subdomain", "", "Filter by subdomain (@ for root)")
	}
	if supportsPagination(name) {
		cmd.Flags().IntVar(&params.page, "page", 0, "Page number")
		cmd.Flags().IntVar(&params.perPage, "per-page", 50, "Items per page")
	}
	if name == "error-details" {
		cmd.Flags().StringVar(&params.errorMessage, "error", "", "Error message to search for")
	}
	if strings.HasPrefix(name, "aggregated-") {
		cmd.Flags().StringVar(&params.domains, "domains", "", "Comma-separated domain names")
		_ = cmd.MarkFlagRequired("domains")
	}
	if name == "aggregated-charts" {
		cmd.Flags().StringVar(&params.reportType, "report-type", "traffic", "Report type: traffic, requests")
		cmd.Flags().StringVar(&params.categoryType, "category-type", "", "Category type: pop, asn")
		cmd.Flags().StringVar(&params.pops, "pops", "", "Comma-separated POP names")
		cmd.Flags().StringVar(&params.asns, "asns", "", "Comma-separated ASN numbers")
	}
	if name == "aggregated-details" {
		cmd.Flags().StringVar(&params.categoryType, "category-type", "", "Category type: pop, asn")
		cmd.Flags().StringVar(&params.pops, "pops", "", "Comma-separated POP names")
		cmd.Flags().StringVar(&params.asns, "asns", "", "Comma-separated ASN numbers")
	}
}

func supportsSubdomainFilter(name string) bool {
	switch name {
	case "traffic", "traffic-saved", "traffic-geo", "visitors", "response-time":
		return true
	default:
		return false
	}
}

func supportsPagination(name string) bool {
	switch name {
	case "high-request-ips", "attacks-detail", "aggregated-details":
		return true
	default:
		return false
	}
}
