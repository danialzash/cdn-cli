package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type ReportParams = sdk.ReportParams

func (c *Client) FetchReport(ctx context.Context, path string, params ReportParams) (json.RawMessage, error) {
	return c.sdk.FetchReport(ctx, path, params)
}

func (c *Client) DownloadDomainsReport(ctx context.Context) ([]byte, error) {
	return c.sdk.DownloadDomainsReport(ctx)
}

func ReportPath(name, domain, proxyID string) (string, error) {
	domain = url.PathEscape(domain)
	switch name {
	case "traffic":
		return fmt.Sprintf("/reports/%s/traffic", domain), nil
	case "traffic-saved", "request-summary", "traffic-summary":
		return fmt.Sprintf("/reports/%s/traffic/saved", domain), nil
	case "traffic-geo":
		return fmt.Sprintf("/reports/%s/traffic/geo-map", domain), nil
	case "visitors":
		return fmt.Sprintf("/reports/%s/visitors", domain), nil
	case "high-request-ips":
		return fmt.Sprintf("/reports/%s/high-request-ips", domain), nil
	case "response-time":
		return fmt.Sprintf("/reports/%s/response-time", domain), nil
	case "status":
		return fmt.Sprintf("/reports/%s/status", domain), nil
	case "status-summary":
		return fmt.Sprintf("/reports/%s/status/summary", domain), nil
	case "errors":
		return fmt.Sprintf("/reports/%s/errors", domain), nil
	case "errors-chart":
		return fmt.Sprintf("/reports/%s/errors/chart", domain), nil
	case "error-details":
		return fmt.Sprintf("/reports/%s/error-log-details", domain), nil
	case "dns-requests":
		return fmt.Sprintf("/reports/%s/dns-requests", domain), nil
	case "dns-geo":
		return fmt.Sprintf("/reports/%s/dns-geo", domain), nil
	case "attacks":
		return fmt.Sprintf("/reports/%s/attacks", domain), nil
	case "attacks-detail":
		return fmt.Sprintf("/reports/%s/attacks/detail", domain), nil
	case "attacks-attackers":
		return fmt.Sprintf("/reports/%s/attacks/attackers", domain), nil
	case "attacks-geo":
		return fmt.Sprintf("/reports/%s/attacks/geo-map", domain), nil
	case "attacks-uri":
		return fmt.Sprintf("/reports/%s/attacks/uri", domain), nil
	case "transport-layer-proxy":
		if proxyID == "" {
			return "", fmt.Errorf("transport-layer-proxy-id is required")
		}
		return fmt.Sprintf("/reports/%s/transport-layer-proxies/%s", domain, url.PathEscape(proxyID)), nil
	case "aggregated-details":
		return "/reports/aggregated/details", nil
	case "aggregated-charts":
		return "/reports/aggregated/charts", nil
	case "aggregated-filters":
		return "/reports/aggregated/filters", nil
	default:
		return "", fmt.Errorf("unknown report type %q", name)
	}
}

func ReportTypes() []string {
	return []string{
		"traffic",
		"traffic-saved",
		"request-summary",
		"traffic-summary",
		"traffic-geo",
		"visitors",
		"high-request-ips",
		"response-time",
		"status",
		"status-summary",
		"errors",
		"errors-chart",
		"error-details",
		"dns-requests",
		"dns-geo",
		"attacks",
		"attacks-detail",
		"attacks-attackers",
		"attacks-geo",
		"attacks-uri",
		"transport-layer-proxy",
		"domains-download",
		"aggregated-details",
		"aggregated-charts",
		"aggregated-filters",
	}
}
