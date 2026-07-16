package sdk

import (
	"encoding/json"
	"fmt"
	"time"
)

type APIError struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Detail  struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Detail.Message != "" {
		return e.Detail.Message
	}
	return "API request failed"
}

type PaginatedMeta struct {
	CurrentPage int `json:"current_page"`
	LastPage    int `json:"last_page"`
	PerPage     int `json:"per_page"`
	Total       int `json:"total"`
}

type PaginatedLinks struct {
	Next *string `json:"next"`
}

type DomainPlan struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Domain struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Status         string     `json:"status"`
	Type           string     `json:"type"`
	NSKeys         []string   `json:"ns_keys"`
	CurrentNS      []string   `json:"current_ns"`
	CnameTarget    string     `json:"cname_target"`
	CustomCname    string     `json:"custom_cname"`
	DNSCloud       bool       `json:"dns_cloud"`
	Restrictions   []string   `json:"restriction"`
	Fingerprint    bool       `json:"fingerprint_status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	OrganizationID string     `json:"account_id"`
	Plan           DomainPlan `json:"plan"`
}

type ListDomainsParams struct {
	Page     int
	PerPage  int
	Statuses []string
	SortBy   string
	Order    string
}

type DomainsListResponse struct {
	Data  []Domain       `json:"data"`
	Meta  PaginatedMeta  `json:"meta"`
	Links PaginatedLinks `json:"links"`
}

type DomainResponse struct {
	Data Domain `json:"data"`
}

type FirewallRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	FilterExpr string `json:"filter_expr"`
	Action     string `json:"action"`
	Priority   int    `json:"priority"`
	IsEnabled  bool   `json:"is_enabled"`
	Note       string `json:"note"`
}

type FirewallRulesResponse struct {
	Data  []FirewallRule `json:"data"`
	Meta  PaginatedMeta  `json:"meta"`
	Links PaginatedLinks `json:"links"`
}

type FirewallRuleResponse struct {
	Data    FirewallRule `json:"data"`
	Message string       `json:"message,omitempty"`
}

type UpdateFirewallRuleRequest struct {
	Name       *string `json:"name,omitempty"`
	FilterExpr *string `json:"filter_expr,omitempty"`
	Action     *string `json:"action,omitempty"`
	Priority   *int    `json:"priority,omitempty"`
	IsEnabled  *bool   `json:"is_enabled,omitempty"`
	Note       *string `json:"note,omitempty"`
}

type CreateFirewallRuleRequest struct {
	Name       string `json:"name"`
	FilterExpr string `json:"filter_expr"`
	Action     string `json:"action"`
	Priority   int    `json:"priority,omitempty"`
	IsEnabled  bool   `json:"is_enabled,omitempty"`
	Note       string `json:"note,omitempty"`
}

type WafPackage struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IsEnabled *bool  `json:"is_enabled,omitempty"`
}

type WafPreset struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Packages []WafPackage `json:"packages"`
}

type WafPresets struct {
	Presets  []WafPreset  `json:"presets"`
	Packages []WafPackage `json:"packages"`
}

type WafPresetsResponse struct {
	Data WafPresets `json:"data"`
}

type DomainWafPackagesResponse struct {
	Data []WafPackage `json:"data"`
}

type WafSettings struct {
	Mode      string       `json:"mode"`
	IsEnabled bool         `json:"is_enabled"`
	Packages  []WafPackage `json:"packages,omitempty"`
}

type WafSettingsResponse struct {
	Data WafSettings `json:"data"`
}

type TroubleshootCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

type Troubleshoot struct {
	ID        string              `json:"id"`
	Details   []TroubleshootCheck `json:"details"`
	CreatedAt string              `json:"created_at"`
}

type TroubleshootResponse struct {
	Data Troubleshoot `json:"data"`
}

func decodeError(body []byte, status int) error {
	var apiErr APIError
	if err := json.Unmarshal(body, &apiErr); err == nil && (apiErr.Message != "" || apiErr.Detail.Message != "") {
		return &apiErr
	}
	return &APIError{Message: fmtStatusMessage(status, body)}
}

func fmtStatusMessage(status int, body []byte) string {
	msg := string(body)
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	if msg == "" {
		return fmt.Sprintf("request failed with status %d", status)
	}
	return fmt.Sprintf("request failed with status %d: %s", status, msg)
}
