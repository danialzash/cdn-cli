package sdk

import (
	"context"
	"net/http"
	"net/url"
)

func (c *Client) GetAcceleration(ctx context.Context, domain string) (*Acceleration, error) {
	var resp AccelerationResponse
	if err := c.get(ctx, "/acceleration/"+url.PathEscape(domain), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateAcceleration(ctx context.Context, domain string, req UpdateAccelerationRequest) (*Acceleration, error) {
	var resp AccelerationResponse
	path := "/acceleration/" + url.PathEscape(domain)
	if err := c.request(ctx, http.MethodPatch, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) GetImageResize(ctx context.Context, domain string) (*ImageResize, error) {
	var resp ImageResizeResponse
	path := "/acceleration/" + url.PathEscape(domain) + "/image-resize"
	if err := c.get(ctx, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateImageResize(ctx context.Context, domain string, req UpdateImageResizeRequest) (*ImageResize, error) {
	var resp ImageResizeResponse
	path := "/acceleration/" + url.PathEscape(domain) + "/image-resize"
	if err := c.request(ctx, http.MethodPatch, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
