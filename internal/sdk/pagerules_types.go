package sdk

import "encoding/json"

type PageRule struct {
	ID          string          `json:"id,omitempty"`
	Seq         int             `json:"seq,omitempty"`
	URL         string          `json:"url,omitempty"`
	Status      bool            `json:"status,omitempty"`
	IsProtected bool            `json:"is_protected,omitempty"`
	CacheLevel  string          `json:"cache_level,omitempty"`
	CacheMaxAge string          `json:"cache_max_age,omitempty"`
	CacheAny    string          `json:"cache_any,omitempty"`
	WafStatus   bool            `json:"waf_status,omitempty"`
	Raw         json.RawMessage `json:"-"`
}

type PageRuleResponse struct {
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message,omitempty"`
}

type PageRuleDataResponse struct {
	Data json.RawMessage `json:"data"`
}
