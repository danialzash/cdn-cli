package sdk

import (
	"context"
	"net/url"
)

func (c *Client) GetFirewallSettings(ctx context.Context, domain string) (*FirewallSettings, error) {
	var resp FirewallSettingsResponse
	if err := c.get(ctx, "/firewall/"+url.PathEscape(domain)+"/settings", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) GetCacheSettings(ctx context.Context, domain string) (*CacheSettings, error) {
	var resp CacheSettingsResponse
	if err := c.get(ctx, "/caching/"+url.PathEscape(domain), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) GetSslSettings(ctx context.Context, domain string) (*SslSettings, error) {
	var resp SslSettingsResponse
	if err := c.get(ctx, "/ssl/"+url.PathEscape(domain), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) GetDdosSettings(ctx context.Context, domain string) (*DdosSettings, error) {
	var resp DdosSettingsResponse
	if err := c.get(ctx, "/ddos/"+url.PathEscape(domain)+"/settings", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListDdosRules(ctx context.Context, domain string, page, perPage int) (*DdosRulesResponse, error) {
	query := paginateQuery(page, perPage)
	var resp DdosRulesResponse
	if err := c.get(ctx, "/ddos/"+url.PathEscape(domain)+"/rules", query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetLoadBalancerSettings(ctx context.Context, domain string) (*LoadBalancerSetting, error) {
	var resp LoadBalancerSettingsResponse
	if err := c.get(ctx, "/load-balancers/"+url.PathEscape(domain)+"/settings", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListLoadBalancers(ctx context.Context, domain string, page, perPage int) (*LoadBalancersResponse, error) {
	query := paginateQuery(page, perPage)
	var resp LoadBalancersResponse
	if err := c.get(ctx, "/load-balancers/"+url.PathEscape(domain), query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetRateLimitSettings(ctx context.Context, domain string) (*RateLimitSettings, error) {
	var resp RateLimitSettingsResponse
	if err := c.get(ctx, "/rate-limit/"+url.PathEscape(domain)+"/settings", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListRateLimitRules(ctx context.Context, domain string, page, perPage int) (*RateLimitRulesResponse, error) {
	query := paginateQuery(page, perPage)
	var resp RateLimitRulesResponse
	if err := c.get(ctx, "/rate-limit/"+url.PathEscape(domain)+"/rules", query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetAcceleration(ctx context.Context, domain string) (*Acceleration, error) {
	var resp AccelerationResponse
	if err := c.get(ctx, "/acceleration/"+url.PathEscape(domain), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
