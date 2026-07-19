package sdk

type FirewallSettings struct {
	IsEnabled     bool   `json:"is_enabled"`
	DefaultAction string `json:"default_action"`
	VerifySNI     bool   `json:"verify_sni"`
	SkipGlobalFW  bool   `json:"skip_global_firewall"`
	SkipGlobalWL  bool   `json:"skip_global_whitelist"`
}

type FirewallSettingsResponse struct {
	Data FirewallSettings `json:"data"`
}

type CacheSettings struct {
	CacheStatus           string `json:"cache_status"`
	CacheMaxAge           string `json:"cache_max_age"`
	CacheDeveloperMode    bool   `json:"cache_developer_mode"`
	CacheMaxSize          int64  `json:"cache_max_size"`
	CacheConsistentUptime bool   `json:"cache_consistent_uptime"`
	CachePageAny          string `json:"cache_page_any,omitempty"`
	CacheBrowser          string `json:"cache_browser,omitempty"`
	CacheScheme           bool   `json:"cache_scheme,omitempty"`
	CacheBypassOnCookie   bool   `json:"cache_bypass_on_cookie,omitempty"`
	CacheCookie           string `json:"cache_cookie,omitempty"`
	CacheArgs             bool   `json:"cache_args,omitempty"`
	CacheArg              string `json:"cache_arg,omitempty"`
}

type UpdateCacheSettingsRequest struct {
	CacheDeveloperMode    *bool   `json:"cache_developer_mode,omitempty"`
	CacheConsistentUptime *bool   `json:"cache_consistent_uptime,omitempty"`
	CacheMaxSize          *int64  `json:"cache_max_size,omitempty"`
	CacheStatus           *string `json:"cache_status,omitempty"`
	CacheMaxAge           *string `json:"cache_max_age,omitempty"`
	CachePageAny          *string `json:"cache_page_any,omitempty"`
	CacheBrowser          *string `json:"cache_browser,omitempty"`
	CacheScheme           *bool   `json:"cache_scheme,omitempty"`
	CacheBypassOnCookie   *bool   `json:"cache_bypass_on_cookie,omitempty"`
	CacheCookie           *string `json:"cache_cookie,omitempty"`
	CacheArgs             *bool   `json:"cache_args,omitempty"`
	CacheArg              *string `json:"cache_arg,omitempty"`
}

type CachingPurgeRequest struct {
	Purge     string   `json:"purge"`
	PurgeURLs []string `json:"purge_urls,omitempty"`
	PurgeTags []string `json:"purge_tags,omitempty"`
}

type CacheSettingsResponse struct {
	Data CacheSettings `json:"data"`
}

type DdosSettings struct {
	IsEnabled      bool   `json:"is_enabled"`
	ProtectionMode string `json:"protection_mode"`
	CaptchaService string `json:"captcha_service"`
	TTL            int    `json:"ttl"`
}

type DdosSettingsResponse struct {
	Data DdosSettings `json:"data"`
}

type DdosRule struct {
	ID          string   `json:"id"`
	URLPattern  string   `json:"url_pattern"`
	Action      string   `json:"action"`
	IsEnabled   bool     `json:"is_enabled"`
	Description string   `json:"description"`
	Sources     []string `json:"sources"`
}

type DdosRulesResponse struct {
	Data  []DdosRule     `json:"data"`
	Meta  PaginatedMeta  `json:"meta"`
	Links PaginatedLinks `json:"links"`
}

type PageRuleSummary struct {
	ID          string `json:"id"`
	Seq         int    `json:"seq"`
	URL         string `json:"url"`
	Status      bool   `json:"status"`
	IsProtected bool   `json:"is_protected"`
	CacheLevel  string `json:"cache_level"`
}

type PageRulesResponse struct {
	Data  []PageRuleSummary `json:"data"`
	Meta  PaginatedMeta     `json:"meta"`
	Links PaginatedLinks    `json:"links"`
}

type LoadBalancerSetting struct {
	Method     string `json:"method"`
	Protocol   string `json:"protocol"`
	Keepalive  string `json:"keepalive"`
	GRPCStatus bool   `json:"grpc_status"`
}

type LoadBalancerSettingsResponse struct {
	Data LoadBalancerSetting `json:"data"`
}

type LoadBalancer struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      bool   `json:"status"`
	Method      string `json:"method"`
	PoolCount   int    `json:"-"`
}

type LoadBalancerAPI struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      bool   `json:"status"`
	Method      string `json:"method"`
	Pools       []struct {
		ID string `json:"id"`
	} `json:"pools"`
}

type LoadBalancersResponse struct {
	Data  []LoadBalancerAPI `json:"data"`
	Meta  PaginatedMeta     `json:"meta"`
	Links PaginatedLinks    `json:"links"`
}

type RateLimitSettings struct {
	DdosDetection  bool     `json:"ddos_detection"`
	ExcludeSources []string `json:"exclude_sources"`
}

type RateLimitSettingsResponse struct {
	Data RateLimitSettings `json:"data"`
}

type RateLimitRule struct {
	ID           string `json:"id"`
	URLPattern   string `json:"url_pattern"`
	Action       string `json:"action"`
	IsEnabled    bool   `json:"is_enabled"`
	Rate         int    `json:"rate"`
	TimeDuration int    `json:"time_duration"`
	Description  string `json:"description"`
}

type RateLimitRulesResponse struct {
	Data  []RateLimitRule `json:"data"`
	Meta  PaginatedMeta   `json:"meta"`
	Links PaginatedLinks  `json:"links"`
}

type Acceleration struct {
	Status     string   `json:"status"`
	Extensions []string `json:"extensions"`
}

type AccelerationResponse struct {
	Data Acceleration `json:"data"`
}

type UpdateAccelerationRequest struct {
	Status     *string  `json:"status,omitempty"`
	Extensions []string `json:"extensions,omitempty"`
}

type ImageResize struct {
	Status    string `json:"status"`
	HeightBy  string `json:"height_by"`
	WidthBy   string `json:"width_by"`
	Mode      string `json:"mode"`
	ModeBy    string `json:"mode_by"`
	QualityBy string `json:"quality_by"`
}

type ImageResizeResponse struct {
	Data ImageResize `json:"data"`
}

type UpdateImageResizeRequest struct {
	Status    *string `json:"status,omitempty"`
	HeightBy  *string `json:"height_by,omitempty"`
	WidthBy   *string `json:"width_by,omitempty"`
	Mode      *string `json:"mode,omitempty"`
	ModeBy    *string `json:"mode_by,omitempty"`
	QualityBy *string `json:"quality_by,omitempty"`
}
