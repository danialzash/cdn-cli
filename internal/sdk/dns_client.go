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
)

func (c *Client) ListDNSRecords(ctx context.Context, domain string, page, perPage int, recordType string) (*DnsRecordsListResponse, error) {
	query := url.Values{}
	if page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	if perPage > 0 {
		query.Set("per_page", strconv.Itoa(perPage))
	}
	if recordType != "" {
		query.Set("type", recordType)
	}

	var resp DnsRecordsListResponse
	if err := c.get(ctx, "/dns/"+url.PathEscape(domain)+"/records", query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetDNSRecord(ctx context.Context, domain, id string) (*DnsRecord, error) {
	var resp DnsRecordResponse
	if err := c.get(ctx, "/dns/"+url.PathEscape(domain)+"/records/"+url.PathEscape(id), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) CreateDNSRecord(ctx context.Context, domain string, req CreateDnsRecordRequest) (*DnsRecord, error) {
	var resp DnsRecordResponse
	if err := c.post(ctx, "/dns/"+url.PathEscape(domain)+"/records", req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return decodeError(respBody, resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
