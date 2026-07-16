package sdk

import (
	"context"
	"net/http"
	"net/url"
)

func (c *Client) CreateFirewallRule(ctx context.Context, domain string, req CreateFirewallRuleRequest) (*FirewallRule, error) {
	var resp FirewallRuleResponse
	path := "/firewall/" + url.PathEscape(domain) + "/rules"
	if err := c.request(ctx, http.MethodPost, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) GetFirewallRule(ctx context.Context, domain, id string) (*FirewallRule, error) {
	var resp FirewallRuleResponse
	path := "/firewall/" + url.PathEscape(domain) + "/rules/" + url.PathEscape(id)
	if err := c.get(ctx, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateFirewallRule(ctx context.Context, domain, id string, req UpdateFirewallRuleRequest) (*FirewallRule, error) {
	var resp FirewallRuleResponse
	path := "/firewall/" + url.PathEscape(domain) + "/rules/" + url.PathEscape(id)
	if err := c.request(ctx, http.MethodPatch, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DeleteFirewallRule(ctx context.Context, domain, id string) error {
	path := "/firewall/" + url.PathEscape(domain) + "/rules/" + url.PathEscape(id)
	return c.request(ctx, http.MethodDelete, path, nil, nil)
}
