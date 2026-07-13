package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vergecloud/cdn-cli/internal/dnsverify"
	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type DNSRecord struct {
	ID          string
	Name        string
	Type        string
	TTL         int
	Cloud       bool
	Value       string
	RawValue    json.RawMessage
	IsProtected bool
	Usage       []string
	CreatedAt   string
	UpdatedAt   string
}

type CreateDNSRecordInput struct {
	Name     string
	Type     string
	Value    string
	TTL      int
	Cloud    bool
	Priority int
}

type DNSVerifyResult struct {
	RecordID string
	Name     string
	Type     string
	Expected string
	Actual   string
	Status   string
	Detail   string
}

func (c *Client) ListDNSRecords(ctx context.Context, domain, recordType string) ([]DNSRecord, error) {
	var all []DNSRecord
	page := 1

	for {
		resp, err := c.sdk.ListDNSRecords(ctx, domain, page, defaultPerPage, recordType)
		if err != nil {
			return nil, err
		}

		for _, record := range resp.Data {
			all = append(all, mapDNSRecord(record))
		}

		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}

	return all, nil
}

func (c *Client) GetDNSRecord(ctx context.Context, domain, id string) (*DNSRecord, error) {
	record, err := c.sdk.GetDNSRecord(ctx, domain, id)
	if err != nil {
		return nil, err
	}
	mapped := mapDNSRecord(*record)
	return &mapped, nil
}

func (c *Client) CreateDNSRecord(ctx context.Context, domain string, input CreateDNSRecordInput) (*DNSRecord, error) {
	value, err := buildDNSValue(input)
	if err != nil {
		return nil, err
	}

	req := sdk.CreateDnsRecordRequest{
		Name:  input.Name,
		Type:  strings.ToLower(input.Type),
		TTL:   input.TTL,
		Cloud: input.Cloud,
		Value: value,
	}

	record, err := c.sdk.CreateDNSRecord(ctx, domain, req)
	if err != nil {
		return nil, err
	}

	mapped := mapDNSRecord(*record)
	return &mapped, nil
}

func (c *Client) VerifyDNSRecords(ctx context.Context, domain string, records []DNSRecord) []DNSVerifyResult {
	checker := dnsverify.NewChecker()
	results := make([]DNSVerifyResult, 0, len(records))

	for _, record := range records {
		expected := record.Value
		if expected == "" {
			expected = formatDNSValue(record.Type, record.RawValue)
		}

		verify := checker.Verify(ctx, record.Type, record.Name, domain, expected, record.Cloud)
		results = append(results, DNSVerifyResult{
			RecordID: record.ID,
			Name:     verify.Name,
			Type:     verify.Type,
			Expected: verify.Expected,
			Actual:   verify.Actual,
			Status:   verify.Status,
			Detail:   verify.Detail,
		})
	}

	return results
}

func mapDNSRecord(record sdk.DnsRecord) DNSRecord {
	return DNSRecord{
		ID:          record.ID,
		Name:        record.Name,
		Type:        strings.ToUpper(record.Type),
		TTL:         record.TTL,
		Cloud:       record.Cloud,
		Value:       formatDNSValue(record.Type, record.Value),
		RawValue:    record.Value,
		IsProtected: record.IsProtected,
		Usage:       record.Usage,
		CreatedAt:   record.CreatedAt,
		UpdatedAt:   record.UpdatedAt,
	}
}

func buildDNSValue(input CreateDNSRecordInput) (json.RawMessage, error) {
	recordType := strings.ToLower(strings.TrimSpace(input.Type))
	value := strings.TrimSpace(input.Value)

	switch recordType {
	case "a":
		payload, err := json.Marshal([]map[string]any{{"ip": value}})
		if err != nil {
			return nil, err
		}
		return payload, nil
	case "aaaa":
		payload, err := json.Marshal([]map[string]any{{"ip": value}})
		if err != nil {
			return nil, err
		}
		return payload, nil
	case "cname":
		payload, err := json.Marshal(map[string]any{"host": value, "host_header": "source"})
		if err != nil {
			return nil, err
		}
		return payload, nil
	case "txt", "spf", "dkim":
		payload, err := json.Marshal(map[string]any{"text": value})
		if err != nil {
			return nil, err
		}
		return payload, nil
	case "mx":
		priority := input.Priority
		if priority == 0 {
			priority = 10
		}
		payload, err := json.Marshal(map[string]any{"host": value, "priority": priority})
		if err != nil {
			return nil, err
		}
		return payload, nil
	case "ns":
		payload, err := json.Marshal(map[string]any{"host": value})
		if err != nil {
			return nil, err
		}
		return payload, nil
	default:
		return nil, fmt.Errorf("unsupported record type %q (supported: a, aaaa, cname, txt, mx, ns)", input.Type)
	}
}

func formatDNSValue(recordType string, raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	recordType = strings.ToLower(recordType)

	switch recordType {
	case "a", "aaaa":
		var values []struct {
			IP      string `json:"ip"`
			Port    *int   `json:"port"`
			Weight  *int   `json:"weight"`
			Country string `json:"country"`
		}
		if err := json.Unmarshal(raw, &values); err != nil {
			return string(raw)
		}
		parts := make([]string, 0, len(values))
		for _, item := range values {
			part := item.IP
			if item.Weight != nil {
				part = fmt.Sprintf("%s (w=%d)", part, *item.Weight)
			}
			if item.Country != "" {
				part = fmt.Sprintf("%s [%s]", part, item.Country)
			}
			parts = append(parts, part)
		}
		return strings.Join(parts, ", ")
	case "cname", "aname":
		var value struct {
			Host       string `json:"host"`
			Location   string `json:"location"`
			HostHeader string `json:"host_header"`
			Port       *int   `json:"port"`
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return string(raw)
		}
		host := value.Host
		if host == "" {
			host = value.Location
		}
		if value.Port != nil {
			host = fmt.Sprintf("%s:%d", host, *value.Port)
		}
		if value.HostHeader != "" {
			host = fmt.Sprintf("%s (host_header=%s)", host, value.HostHeader)
		}
		return host
	case "txt", "spf", "dkim":
		var value struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return string(raw)
		}
		return value.Text
	case "mx":
		var value struct {
			Host     string `json:"host"`
			Priority int    `json:"priority"`
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return string(raw)
		}
		return fmt.Sprintf("%d %s", value.Priority, value.Host)
	case "ns", "ptr":
		var value struct {
			Host   string `json:"host"`
			Domain string `json:"domain"`
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return string(raw)
		}
		if value.Host != "" {
			return value.Host
		}
		return value.Domain
	case "srv":
		var value struct {
			Target   string `json:"target"`
			Port     int    `json:"port"`
			Priority int    `json:"priority"`
			Weight   int    `json:"weight"`
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return string(raw)
		}
		return fmt.Sprintf("%d %d %s:%d", value.Priority, value.Weight, value.Target, value.Port)
	default:
		return string(raw)
	}
}
