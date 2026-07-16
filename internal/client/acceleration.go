package client

import (
	"context"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type AccelerationSettings struct {
	Status     string
	Extensions []string
}

type UpdateAccelerationInput struct {
	Status     *string
	Extensions []string
}

type ImageResizeSettings struct {
	Status    string
	HeightBy  string
	WidthBy   string
	Mode      string
	ModeBy    string
	QualityBy string
}

type UpdateImageResizeInput struct {
	Status    *string
	HeightBy  *string
	WidthBy   *string
	Mode      *string
	ModeBy    *string
	QualityBy *string
}

func (c *Client) GetAccelerationSettings(ctx context.Context, domain string) (*AccelerationSettings, error) {
	settings, err := c.sdk.GetAcceleration(ctx, domain)
	if err != nil {
		return nil, err
	}
	mapped := mapAccelerationSettings(*settings)
	return &mapped, nil
}

func (c *Client) UpdateAccelerationSettings(ctx context.Context, domain string, input UpdateAccelerationInput) (*AccelerationSettings, error) {
	req := sdk.UpdateAccelerationRequest{
		Status: input.Status,
	}
	if input.Extensions != nil {
		req.Extensions = input.Extensions
	}

	settings, err := c.sdk.UpdateAcceleration(ctx, domain, req)
	if err != nil {
		return nil, err
	}
	mapped := mapAccelerationSettings(*settings)
	return &mapped, nil
}

func (c *Client) GetImageResizeSettings(ctx context.Context, domain string) (*ImageResizeSettings, error) {
	settings, err := c.sdk.GetImageResize(ctx, domain)
	if err != nil {
		return nil, err
	}
	mapped := mapImageResizeSettings(*settings)
	return &mapped, nil
}

func (c *Client) UpdateImageResizeSettings(ctx context.Context, domain string, input UpdateImageResizeInput) (*ImageResizeSettings, error) {
	settings, err := c.sdk.UpdateImageResize(ctx, domain, sdk.UpdateImageResizeRequest{
		Status:    input.Status,
		HeightBy:  input.HeightBy,
		WidthBy:   input.WidthBy,
		Mode:      input.Mode,
		ModeBy:    input.ModeBy,
		QualityBy: input.QualityBy,
	})
	if err != nil {
		return nil, err
	}
	mapped := mapImageResizeSettings(*settings)
	return &mapped, nil
}

func mapAccelerationSettings(settings sdk.Acceleration) AccelerationSettings {
	extensions := settings.Extensions
	if extensions == nil {
		extensions = []string{}
	}
	return AccelerationSettings{
		Status:     settings.Status,
		Extensions: extensions,
	}
}

func mapImageResizeSettings(settings sdk.ImageResize) ImageResizeSettings {
	return ImageResizeSettings{
		Status:    settings.Status,
		HeightBy:  settings.HeightBy,
		WidthBy:   settings.WidthBy,
		Mode:      settings.Mode,
		ModeBy:    settings.ModeBy,
		QualityBy: settings.QualityBy,
	}
}
