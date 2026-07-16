package sdk

import (
	"context"
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
	if err := c.request(ctx, http.MethodPost, "/dns/"+url.PathEscape(domain)+"/records", req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateDNSRecord(ctx context.Context, domain, id string, req CreateDnsRecordRequest) (*DnsRecord, error) {
	var resp DnsRecordResponse
	path := "/dns/" + url.PathEscape(domain) + "/records/" + url.PathEscape(id)
	if err := c.request(ctx, http.MethodPut, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DeleteDNSRecord(ctx context.Context, domain, id string) error {
	path := "/dns/" + url.PathEscape(domain) + "/records/" + url.PathEscape(id)
	return c.request(ctx, http.MethodDelete, path, nil, nil)
}
