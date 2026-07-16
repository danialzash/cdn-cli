package client

import (
	"context"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type UpdateFirewallRuleInput struct {
	Name       *string
	FilterExpr *string
	Action     *string
	Priority   *int
	Enabled    *bool
	Note       *string
}

type CreateFirewallRuleInput struct {
	Name       string
	FilterExpr string
	Action     string
	Priority   int
	Enabled    bool
	Note       string
}

func (c *Client) CreateFirewallRule(ctx context.Context, domain string, input CreateFirewallRuleInput) (*FirewallRule, error) {
	rule, err := c.sdk.CreateFirewallRule(ctx, domain, sdk.CreateFirewallRuleRequest{
		Name:       input.Name,
		FilterExpr: input.FilterExpr,
		Action:     input.Action,
		Priority:   input.Priority,
		IsEnabled:  input.Enabled,
		Note:       input.Note,
	})
	if err != nil {
		return nil, err
	}
	mapped := mapFirewallRule(*rule)
	return &mapped, nil
}

func (c *Client) GetFirewallRule(ctx context.Context, domain, id string) (*FirewallRule, error) {
	rule, err := c.sdk.GetFirewallRule(ctx, domain, id)
	if err != nil {
		return nil, err
	}
	mapped := mapFirewallRule(*rule)
	return &mapped, nil
}

func (c *Client) UpdateFirewallRule(ctx context.Context, domain, id string, input UpdateFirewallRuleInput) (*FirewallRule, error) {
	req := sdk.UpdateFirewallRuleRequest{
		Name:       input.Name,
		FilterExpr: input.FilterExpr,
		Action:     input.Action,
		Priority:   input.Priority,
		Note:       input.Note,
	}
	if input.Enabled != nil {
		req.IsEnabled = input.Enabled
	}

	rule, err := c.sdk.UpdateFirewallRule(ctx, domain, id, req)
	if err != nil {
		return nil, err
	}
	mapped := mapFirewallRule(*rule)
	return &mapped, nil
}

func (c *Client) DeleteFirewallRule(ctx context.Context, domain, id string) error {
	return c.sdk.DeleteFirewallRule(ctx, domain, id)
}
