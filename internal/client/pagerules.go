package client

import (
	"context"
	"encoding/json"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type PageRule struct {
	ID          string `json:"id"`
	Seq         int    `json:"seq"`
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
	IsProtected bool   `json:"is_protected"`
	CacheLevel  string `json:"cache_level,omitempty"`
	CacheMaxAge string `json:"cache_max_age,omitempty"`
	Raw         json.RawMessage `json:"raw,omitempty"`
}

type UpdatePageRuleInput struct {
	URL         *string
	Enabled     *bool
	Seq         *int
	CacheLevel  *string
	CacheMaxAge *string
}

type CreatePageRuleInput struct {
	URL         string
	Enabled     bool
	Seq         int
	CacheLevel  string
	CacheMaxAge string
}

func (c *Client) CreatePageRule(ctx context.Context, domain string, input CreatePageRuleInput) (*PageRule, error) {
	body, err := sdk.BuildCreatePageRuleBody(input.URL, input.Enabled, input.Seq, input.CacheLevel, input.CacheMaxAge)
	if err != nil {
		return nil, err
	}

	created, err := c.sdk.CreatePageRule(ctx, domain, body)
	if err != nil {
		return nil, err
	}
	return mapPageRuleRaw(created)
}

func (c *Client) ListPageRules(ctx context.Context, domain string) ([]PageRule, error) {
	var all []PageRule
	page := 1

	for {
		resp, err := c.sdk.ListPageRules(ctx, domain, page, defaultPerPage)
		if err != nil {
			return nil, err
		}

		for _, item := range resp.Data {
			all = append(all, mapPageRuleSummary(item))
		}

		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}

	return all, nil
}

func (c *Client) GetPageRule(ctx context.Context, domain, id string) (*PageRule, error) {
	raw, err := c.sdk.GetPageRule(ctx, domain, id)
	if err != nil {
		return nil, err
	}
	return mapPageRuleRaw(raw)
}

func (c *Client) UpdatePageRule(ctx context.Context, domain, id string, input UpdatePageRuleInput) (*PageRule, error) {
	existing, err := c.sdk.GetPageRule(ctx, domain, id)
	if err != nil {
		return nil, err
	}

	patch := map[string]any{}
	if input.URL != nil {
		patch["url"] = *input.URL
	}
	if input.Enabled != nil {
		patch["status"] = *input.Enabled
	}
	if input.Seq != nil {
		patch["seq"] = *input.Seq
	}
	if input.CacheLevel != nil {
		patch["cache_level"] = *input.CacheLevel
	}
	if input.CacheMaxAge != nil {
		patch["cache_max_age"] = *input.CacheMaxAge
	}

	body, err := sdk.MergePageRuleUpdate(existing, patch)
	if err != nil {
		return nil, err
	}

	updated, err := c.sdk.UpdatePageRule(ctx, domain, id, body)
	if err != nil {
		return nil, err
	}
	return mapPageRuleRaw(updated)
}

func (c *Client) DeletePageRule(ctx context.Context, domain, id string) error {
	return c.sdk.DeletePageRule(ctx, domain, id)
}

func mapPageRuleSummary(item sdk.PageRuleSummary) PageRule {
	return PageRule{
		ID:          item.ID,
		Seq:         item.Seq,
		URL:         item.URL,
		Enabled:     item.Status,
		IsProtected: item.IsProtected,
		CacheLevel:  item.CacheLevel,
	}
}

func mapPageRuleRaw(raw json.RawMessage) (*PageRule, error) {
	decoded, err := sdk.DecodePageRule(raw)
	if err != nil {
		return nil, err
	}
	return &PageRule{
		ID:          decoded.ID,
		Seq:         decoded.Seq,
		URL:         decoded.URL,
		Enabled:     decoded.Status,
		IsProtected: decoded.IsProtected,
		CacheLevel:  decoded.CacheLevel,
		CacheMaxAge: decoded.CacheMaxAge,
		Raw:         raw,
	}, nil
}
