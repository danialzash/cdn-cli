package sdk

import (
	"context"
	"net/http"
	"net/url"
)

func (c *Client) GetCacheSettings(ctx context.Context, domain string) (*CacheSettings, error) {
	var resp CacheSettingsResponse
	if err := c.get(ctx, "/caching/"+url.PathEscape(domain), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateCacheSettings(ctx context.Context, domain string, req UpdateCacheSettingsRequest) error {
	path := "/caching/" + url.PathEscape(domain)
	return c.request(ctx, http.MethodPatch, path, req, nil)
}

func (c *Client) PurgeCache(ctx context.Context, domain string, req CachingPurgeRequest) error {
	path := "/caching/" + url.PathEscape(domain) + "/purge"
	return c.request(ctx, http.MethodPost, path, req, nil)
}
