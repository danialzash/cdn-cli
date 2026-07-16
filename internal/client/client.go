package client

import (
	"context"
	"time"

	"github.com/vergecloud/cdn-cli/internal/sdk"
	"github.com/vergecloud/cdn-cli/internal/transport"
)

const defaultPerPage = 50

// Domain is the stable type used by CLI commands.
type Domain struct {
	ID             string
	Name           string
	Status         string
	Type           string
	Plan           string
	NSKeys         []string
	OrganizationID string
	CreatedAt      time.Time
}

type ListDomainsOptions struct {
	Status string
	SortBy string
	Order  string
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
	ID         string
	CreatedAt  string
	Items      []SmartCheckItem
	SafeCount  int
	IssueCount int
}

type Client struct {
	sdk *sdk.Client
}

type Options struct {
	BaseURL string
	Auth    sdk.Auth
	Verbose bool
}

func New(opts Options) *Client {
	return &Client{
		sdk: sdk.New(sdk.Options{
			BaseURL:    opts.BaseURL,
			Auth:       opts.Auth,
			HTTPClient: transport.NewHTTPClient(transport.Options{Verbose: opts.Verbose}),
			Verbose:    opts.Verbose,
		}),
	}
}

func (c *Client) Ping(ctx context.Context) error {
	return c.sdk.Ping(ctx)
}

func (c *Client) ListDomains(ctx context.Context, opts ListDomainsOptions) ([]Domain, error) {
	var statuses []string
	if opts.Status != "" {
		statuses = []string{opts.Status}
	}

	var all []Domain
	page := 1

	for {
		resp, err := c.sdk.ListDomains(ctx, sdk.ListDomainsParams{
			Page:     page,
			PerPage:  defaultPerPage,
			Statuses: statuses,
			SortBy:   opts.SortBy,
			Order:    opts.Order,
		})
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
		ID:             d.ID,
		Name:           d.Name,
		Status:         d.Status,
		Type:           d.Type,
		Plan:           d.Plan.Name,
		NSKeys:         d.NSKeys,
		OrganizationID: d.OrganizationID,
		CreatedAt:      d.CreatedAt,
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
