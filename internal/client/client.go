package client

import (
	"context"
	"fmt"

	"github.com/vergecloud/cdn-cli/internal/sdk"
	"github.com/vergecloud/cdn-cli/internal/transport"
)

const defaultPerPage = 50

// Domain is the stable type used by CLI commands.
type Domain struct {
	ID     string
	Name   string
	Status string
	Type   string
	NSKeys []string
}

type FirewallRule struct {
	ID         string
	Name       string
	FilterExpr string
	Action     string
	Priority   int
	Enabled    bool
	Note       string
}

type WafPackage struct {
	ID      string
	Name    string
	Mode    string
	Status  string
	Enabled bool
}

type SmartCheckItem struct {
	ID      string
	Status  string
	Details string
}

type SmartCheck struct {
	ID        string
	CreatedAt string
	Items     []SmartCheckItem
	SafeCount int
	IssueCount int
}

type Client struct {
	sdk *sdk.Client
}

type Options struct {
	BaseURL string
	APIKey  string
	Verbose bool
}

func New(opts Options) *Client {
	return &Client{
		sdk: sdk.New(sdk.Options{
			BaseURL:    opts.BaseURL,
			APIKey:     opts.APIKey,
			HTTPClient: transport.NewHTTPClient(transport.Options{Verbose: opts.Verbose}),
			Verbose:    opts.Verbose,
		}),
	}
}

func (c *Client) Ping(ctx context.Context) error {
	return c.sdk.Ping(ctx)
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	var all []Domain
	page := 1

	for {
		resp, err := c.sdk.ListDomains(ctx, page, defaultPerPage)
		if err != nil {
			return nil, err
		}

		for _, d := range resp.Data {
			all = append(all, mapDomain(d))
		}

		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}

	return all, nil
}

func (c *Client) GetDomain(ctx context.Context, idOrName string) (*Domain, error) {
	d, err := c.sdk.GetDomain(ctx, idOrName)
	if err != nil {
		return nil, err
	}
	mapped := mapDomain(*d)
	return &mapped, nil
}

func (c *Client) ListFirewallRules(ctx context.Context, domainID string) ([]FirewallRule, error) {
	var all []FirewallRule
	page := 1

	for {
		resp, err := c.sdk.ListFirewallRules(ctx, domainID, page, defaultPerPage)
		if err != nil {
			return nil, err
		}

		for _, r := range resp.Data {
			all = append(all, mapFirewallRule(r))
		}

		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}

	return all, nil
}

func (c *Client) ListWafPackages(ctx context.Context, domain string) ([]WafPackage, error) {
	if domain != "" {
		return c.listDomainWafPackages(ctx, domain)
	}
	return c.listGlobalWafPackages(ctx)
}

func (c *Client) listGlobalWafPackages(ctx context.Context) ([]WafPackage, error) {
	resp, err := c.sdk.ListWafPresets(ctx)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var packages []WafPackage

	for _, preset := range resp.Data.Presets {
		for _, pkg := range preset.Packages {
			if _, ok := seen[pkg.ID]; ok {
				continue
			}
			seen[pkg.ID] = struct{}{}
			packages = append(packages, WafPackage{
				ID:     pkg.ID,
				Name:   pkg.Name,
				Mode:   "-",
				Status: "catalog",
			})
		}
	}

	return packages, nil
}

func (c *Client) listDomainWafPackages(ctx context.Context, domain string) ([]WafPackage, error) {
	settings, err := c.sdk.GetWafSettings(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("load WAF settings: %w", err)
	}

	resp, err := c.sdk.ListDomainWafPackages(ctx, domain)
	if err != nil {
		return nil, err
	}

	mode := settings.Mode
	if mode == "" {
		mode = "off"
	}

	var packages []WafPackage
	for _, pkg := range resp.Data {
		status := "disabled"
		enabled := false
		if pkg.IsEnabled != nil && *pkg.IsEnabled {
			status = "enabled"
			enabled = true
		}
		packages = append(packages, WafPackage{
			ID:      pkg.ID,
			Name:    pkg.Name,
			Mode:    mode,
			Status:  status,
			Enabled: enabled,
		})
	}

	return packages, nil
}

func (c *Client) GetLatestSmartCheck(ctx context.Context, domain string) (*SmartCheck, error) {
	result, err := c.sdk.GetLatestSmartCheck(ctx, domain)
	if err != nil {
		return nil, err
	}

	check := &SmartCheck{
		ID:        result.ID,
		CreatedAt: result.CreatedAt,
	}

	for _, item := range result.Details {
		check.Items = append(check.Items, SmartCheckItem{
			ID:      item.ID,
			Status:  item.Status,
			Details: item.Details,
		})
		if item.Status == "safe" {
			check.SafeCount++
		} else {
			check.IssueCount++
		}
	}

	return check, nil
}

func (c *Client) Raw(ctx context.Context, method, path string) ([]byte, error) {
	return c.sdk.RawRequest(ctx, method, path, nil)
}

func mapDomain(d sdk.Domain) Domain {
	return Domain{
		ID:     d.ID,
		Name:   d.Name,
		Status: d.Status,
		Type:   d.Type,
		NSKeys: d.NSKeys,
	}
}

func mapFirewallRule(r sdk.FirewallRule) FirewallRule {
	return FirewallRule{
		ID:         r.ID,
		Name:       r.Name,
		FilterExpr: r.FilterExpr,
		Action:     r.Action,
		Priority:   r.Priority,
		Enabled:    r.IsEnabled,
		Note:       r.Note,
	}
}
