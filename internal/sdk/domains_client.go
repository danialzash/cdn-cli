package sdk

import (
	"context"
	"net/url"
)

type NsCheckData struct {
	Published []string `json:"ns_domain"`
	Expected  []string `json:"ns_keys"`
}

type NsCheckResponse struct {
	Data    NsCheckData `json:"data"`
	Message string      `json:"message,omitempty"`
}

func (c *Client) CheckNameservers(ctx context.Context, domain string) (*NsCheckData, error) {
	var resp NsCheckResponse
	if err := c.get(ctx, "/domains/"+url.PathEscape(domain)+"/ns-keys/check", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) CheckCnameSetup(ctx context.Context, domain string) (*Domain, error) {
	var resp DomainResponse
	if err := c.get(ctx, "/domains/"+url.PathEscape(domain)+"/cname-setup/check", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
