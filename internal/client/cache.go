package client

import (
	"context"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type CacheSettings struct {
	Status           string
	MaxAge           string
	DeveloperMode    bool
	MaxSize          int64
	ConsistentUptime bool
	PageAny          string
	Browser          string
	Scheme           bool
	BypassOnCookie   bool
	Cookie           string
	Args             bool
	Arg              string
}

type UpdateCacheSettingsInput struct {
	DeveloperMode    *bool
	ConsistentUptime *bool
	MaxSize          *int64
	Status           *string
	MaxAge           *string
	PageAny          *string
	Browser          *string
	Scheme           *bool
	BypassOnCookie   *bool
	Cookie           *string
	Args             *bool
	Arg              *string
}

type PurgeCacheInput struct {
	Purge     string
	PurgeURLs []string
	PurgeTags []string
}

func (c *Client) GetCacheSettings(ctx context.Context, domain string) (*CacheSettings, error) {
	settings, err := c.sdk.GetCacheSettings(ctx, domain)
	if err != nil {
		return nil, err
	}
	mapped := mapCacheSettings(*settings)
	return &mapped, nil
}

func (c *Client) UpdateCacheSettings(ctx context.Context, domain string, input UpdateCacheSettingsInput) (*CacheSettings, error) {
	req := sdk.UpdateCacheSettingsRequest{
		CacheDeveloperMode:    input.DeveloperMode,
		CacheConsistentUptime: input.ConsistentUptime,
		CacheMaxSize:          input.MaxSize,
		CacheStatus:           input.Status,
		CacheMaxAge:           input.MaxAge,
		CachePageAny:          input.PageAny,
		CacheBrowser:          input.Browser,
		CacheScheme:           input.Scheme,
		CacheBypassOnCookie:   input.BypassOnCookie,
		CacheCookie:           input.Cookie,
		CacheArgs:             input.Args,
		CacheArg:              input.Arg,
	}
	if err := c.sdk.UpdateCacheSettings(ctx, domain, req); err != nil {
		return nil, err
	}
	return c.GetCacheSettings(ctx, domain)
}

func (c *Client) PurgeCache(ctx context.Context, domain string, input PurgeCacheInput) error {
	return c.sdk.PurgeCache(ctx, domain, sdk.CachingPurgeRequest{
		Purge:     input.Purge,
		PurgeURLs: input.PurgeURLs,
		PurgeTags: input.PurgeTags,
	})
}

func mapCacheSettings(settings sdk.CacheSettings) CacheSettings {
	return CacheSettings{
		Status:           settings.CacheStatus,
		MaxAge:           settings.CacheMaxAge,
		DeveloperMode:    settings.CacheDeveloperMode,
		MaxSize:          settings.CacheMaxSize,
		ConsistentUptime: settings.CacheConsistentUptime,
		PageAny:          settings.CachePageAny,
		Browser:          settings.CacheBrowser,
		Scheme:           settings.CacheScheme,
		BypassOnCookie:   settings.CacheBypassOnCookie,
		Cookie:           settings.CacheCookie,
		Args:             settings.CacheArgs,
		Arg:              settings.CacheArg,
	}
}
