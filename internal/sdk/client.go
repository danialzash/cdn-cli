package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/vergecloud/cdn-cli/internal/transport"
)

// Client is a minimal hand-written SDK for the VergeCloud CDN API.
// The OpenAPI spec at openapi.yaml is stored for future code generation.
type Client struct {
	baseURL    string
	auth       Auth
	httpClient *http.Client
}

type Options struct {
	BaseURL    string
	Auth       Auth
	HTTPClient *http.Client
	Verbose    bool
}

func New(opts Options) *Client {
	baseURL := strings.TrimRight(opts.BaseURL, "/")
	if !strings.HasSuffix(baseURL, "/v1") {
		baseURL += "/v1"
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = transport.NewHTTPClient(transport.Options{Verbose: opts.Verbose})
	}

	return &Client{
		baseURL:    baseURL,
		auth:       opts.Auth,
		httpClient: httpClient,
	}
}

func (c *Client) ListDomains(ctx context.Context, params ListDomainsParams) (*DomainsListResponse, error) {
	query := url.Values{}
	if params.Page > 0 {
		query.Set("page", strconv.Itoa(params.Page))
	}
	if params.PerPage > 0 {
		query.Set("per_page", strconv.Itoa(params.PerPage))
	}
	for _, status := range params.Statuses {
		query.Add("statuses", status)
	}
	if params.SortBy != "" {
		query.Set("sort_by", params.SortBy)
	}
	if params.Order != "" {
		query.Set("order", params.Order)
	}

	var resp DomainsListResponse
	if err := c.get(ctx, "/domains", query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetDomain(ctx context.Context, domain string) (*Domain, error) {
	var resp DomainResponse
	if err := c.get(ctx, "/domains/"+url.PathEscape(domain), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListFirewallRules(ctx context.Context, domain string, page, perPage int) (*FirewallRulesResponse, error) {
	query := url.Values{}
	if page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	if perPage > 0 {
		query.Set("per_page", strconv.Itoa(perPage))
	}

	var resp FirewallRulesResponse
	if err := c.get(ctx, "/firewall/"+url.PathEscape(domain)+"/rules", query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListWafPresets(ctx context.Context) (*WafPresetsResponse, error) {
	var resp WafPresetsResponse
	if err := c.get(ctx, "/waf", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ListDomainWafPackages(ctx context.Context, domain string) (*DomainWafPackagesResponse, error) {
	var resp DomainWafPackagesResponse
	if err := c.get(ctx, "/waf/"+url.PathEscape(domain)+"/packages", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetWafSettings(ctx context.Context, domain string) (*WafSettings, error) {
	var resp WafSettingsResponse
	if err := c.get(ctx, "/waf/"+url.PathEscape(domain)+"/settings", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) GetLatestSmartCheck(ctx context.Context, domain string) (*Troubleshoot, error) {
	var resp TroubleshootResponse
	if err := c.get(ctx, "/smart-checker/"+url.PathEscape(domain)+"/latest", nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return decodeError(body, resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) setAuth(req *http.Request) {
	switch c.auth.Method {
	case AuthMethodBearer:
		if c.auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.auth.Token)
		}
	default:
		if c.auth.Token != "" {
			req.Header.Set("X-API-Key", c.auth.Token)
		}
	}
	req.Header.Set("Accept", "application/json")
}

// Ping validates credentials by fetching the first page of domains.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.ListDomains(ctx, ListDomainsParams{Page: 1, PerPage: 1})
	return err
}

// RawRequest exposes the raw response body for JSON output mode.
func (c *Client) RawRequest(ctx context.Context, method, path string, query url.Values) ([]byte, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, decodeError(body, resp.StatusCode)
	}
	return bytes.TrimSpace(body), nil
}
