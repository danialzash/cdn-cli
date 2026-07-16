package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

func (c *Client) ListPageRules(ctx context.Context, domain string, page, perPage int) (*PageRulesResponse, error) {
	query := paginateQuery(page, perPage)
	var resp PageRulesResponse
	if err := c.get(ctx, "/page-rules/"+url.PathEscape(domain), query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetPageRule(ctx context.Context, domain, id string) (json.RawMessage, error) {
	var resp PageRuleDataResponse
	path := "/page-rules/" + url.PathEscape(domain) + "/" + url.PathEscape(id)
	if err := c.get(ctx, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) UpdatePageRule(ctx context.Context, domain, id string, body json.RawMessage) (json.RawMessage, error) {
	var resp PageRuleResponse
	path := "/page-rules/" + url.PathEscape(domain) + "/" + url.PathEscape(id)
	if err := c.request(ctx, http.MethodPut, path, body, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) DeletePageRule(ctx context.Context, domain, id string) error {
	path := "/page-rules/" + url.PathEscape(domain) + "/" + url.PathEscape(id)
	return c.request(ctx, http.MethodDelete, path, nil, nil)
}

func DecodePageRule(raw json.RawMessage) (*PageRule, error) {
	if len(raw) == 0 {
		return &PageRule{}, nil
	}
	var rule PageRule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return nil, err
	}
	rule.Raw = raw
	return &rule, nil
}

func DecodePageRuleSummary(raw PageRuleSummary) PageRule {
	return PageRule{
		ID:          raw.ID,
		Seq:         raw.Seq,
		URL:         raw.URL,
		Status:      raw.Status,
		IsProtected: raw.IsProtected,
		CacheLevel:  raw.CacheLevel,
	}
}

func MergePageRuleUpdate(existing json.RawMessage, patch map[string]any) (json.RawMessage, error) {
	current := map[string]any{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &current); err != nil {
			return nil, err
		}
	}
	for key, value := range patch {
		current[key] = value
	}
	return json.Marshal(current)
}

func paginateQuery(page, perPage int) url.Values {
	query := url.Values{}
	if page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	if perPage > 0 {
		query.Set("per_page", strconv.Itoa(perPage))
	}
	return query
}
