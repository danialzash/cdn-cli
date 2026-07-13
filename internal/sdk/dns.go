package sdk

import "encoding/json"

type DnsRecord struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	TTL         int             `json:"ttl"`
	Cloud       bool            `json:"cloud"`
	Value       json.RawMessage `json:"value"`
	IsProtected bool            `json:"is_protected"`
	UpstreamHTTPS string        `json:"upstream_https,omitempty"`
	Usage       []string        `json:"usage,omitempty"`
	CreatedAt   string          `json:"created_at,omitempty"`
	UpdatedAt   string          `json:"updated_at,omitempty"`
}

type DnsRecordsListResponse struct {
	Data  []DnsRecord    `json:"data"`
	Meta  PaginatedMeta  `json:"meta"`
	Links PaginatedLinks `json:"links"`
}

type DnsRecordResponse struct {
	Data    DnsRecord `json:"data"`
	Message string    `json:"message,omitempty"`
}

type CreateDnsRecordRequest struct {
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	TTL   int             `json:"ttl,omitempty"`
	Cloud bool            `json:"cloud,omitempty"`
	Value json.RawMessage `json:"value"`
}
