package sdk

import (
	"context"
	"net/http"
	"net/url"
)

func (c *Client) GetWafPackage(ctx context.Context, packageID string) (*WafPackageDetails, error) {
	var resp WafPackageDetailsResponse
	path := "/waf/packages/" + url.PathEscape(packageID)
	if err := c.get(ctx, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateWafSettings(ctx context.Context, domain string, req UpdateWafSettingsRequest) (*WafSettings, error) {
	var resp WafSettingsResponse
	path := "/waf/" + url.PathEscape(domain) + "/settings"
	if err := c.request(ctx, http.MethodPatch, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
