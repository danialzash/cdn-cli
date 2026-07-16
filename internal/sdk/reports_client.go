package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func (c *Client) FetchReport(ctx context.Context, path string, params ReportParams) (json.RawMessage, error) {
	body, err := c.RawRequest(ctx, http.MethodGet, path, params.Query())
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return json.RawMessage("{}"), nil
	}
	return json.RawMessage(body), nil
}

func (c *Client) DownloadDomainsReport(ctx context.Context) ([]byte, error) {
	u, err := url.Parse(c.baseURL + "/domains/reports/download")
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	c.setAuth(req)
	req.Header.Set("Accept", "text/csv")

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
	return body, nil
}
