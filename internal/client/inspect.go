package client

import (
	"context"
	"sync"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type InspectError struct {
	Section string `json:"section"`
	Error   string `json:"error"`
}

type DomainDetail struct {
	Domain
	UpdatedAt    string   `json:"updated_at,omitempty"`
	DNSCloud     bool     `json:"dns_cloud"`
	CurrentNS    []string `json:"current_ns,omitempty"`
	CnameTarget  string   `json:"cname_target,omitempty"`
	CustomCname  string   `json:"custom_cname,omitempty"`
	Restrictions []string `json:"restrictions,omitempty"`
	Fingerprint  bool     `json:"fingerprint_status"`
}

type FirewallInspect struct {
	Enabled       bool           `json:"enabled"`
	DefaultAction string         `json:"default_action,omitempty"`
	VerifySNI     bool           `json:"verify_sni"`
	RuleCount     int            `json:"rule_count"`
	Rules         []FirewallRule `json:"rules,omitempty"`
}

type WafInspect struct {
	Enabled      bool         `json:"enabled"`
	Mode         string       `json:"mode"`
	PackageCount int          `json:"package_count"`
	Packages     []WafPackage `json:"packages,omitempty"`
}

type DdosInspect struct {
	Enabled        bool             `json:"enabled"`
	ProtectionMode string           `json:"protection_mode,omitempty"`
	CaptchaService string           `json:"captcha_service,omitempty"`
	RuleCount      int              `json:"rule_count"`
	Rules          []DdosRule       `json:"rules,omitempty"`
}

type DdosRule struct {
	ID          string `json:"id"`
	URLPattern  string `json:"url_pattern"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

type PageRulesInspect struct {
	Count int        `json:"count"`
	Rules []PageRule `json:"rules,omitempty"`
}

type SslInspect struct {
	Enabled         bool                `json:"enabled"`
	CertificateMode string              `json:"certificate_mode,omitempty"`
	TLSVersion      string              `json:"tls_version,omitempty"`
	HSTS            bool                `json:"hsts"`
	HTTPSRedirect   bool                `json:"https_redirect"`
	QUIC            bool                `json:"quic"`
	CertificateCount int                `json:"certificate_count"`
	Certificates    []CertificateSummary `json:"certificates,omitempty"`
}

type CertificateSummary struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Active      bool     `json:"active"`
	DomainNames []string `json:"domain_names,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	ExpiryDate  string   `json:"expiry_date,omitempty"`
}

type CacheInspect struct {
	Status             string `json:"status,omitempty"`
	MaxAge             string `json:"max_age,omitempty"`
	DeveloperMode      bool   `json:"developer_mode"`
	MaxSize            int64  `json:"max_size,omitempty"`
	ConsistentUptime   bool   `json:"consistent_uptime"`
}

type LoadBalancingInspect struct {
	GlobalMethod string              `json:"global_method,omitempty"`
	Protocol     string              `json:"protocol,omitempty"`
	Keepalive    string              `json:"keepalive,omitempty"`
	GRPC         bool                `json:"grpc"`
	Count        int                 `json:"count"`
	Balancers    []LoadBalancerEntry `json:"balancers,omitempty"`
}

type LoadBalancerEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Method      string `json:"method"`
	PoolCount   int    `json:"pool_count"`
	Description string `json:"description,omitempty"`
}

type RateLimitInspect struct {
	DdosDetection bool             `json:"ddos_detection"`
	RuleCount     int              `json:"rule_count"`
	Rules         []RateLimitRule  `json:"rules,omitempty"`
}

type RateLimitRule struct {
	ID           string `json:"id"`
	URLPattern   string `json:"url_pattern"`
	Action       string `json:"action"`
	Enabled      bool   `json:"enabled"`
	Rate         int    `json:"rate"`
	TimeDuration int    `json:"time_duration"`
	Description  string `json:"description,omitempty"`
}

type AccelerationInspect struct {
	Status     string   `json:"status,omitempty"`
	Extensions []string `json:"extensions,omitempty"`
}

type DNSInspect struct {
	Count   int         `json:"count"`
	Records []DNSRecord `json:"records,omitempty"`
}

type DomainInspect struct {
	Domain       DomainDetail          `json:"domain"`
	DNS          DNSInspect            `json:"dns"`
	Firewall     FirewallInspect       `json:"firewall"`
	WAF          WafInspect            `json:"waf"`
	DDoS         DdosInspect           `json:"ddos"`
	PageRules    PageRulesInspect      `json:"page_rules"`
	SSL          SslInspect            `json:"ssl"`
	Cache        CacheInspect          `json:"cache"`
	LoadBalancing LoadBalancingInspect `json:"load_balancing"`
	RateLimit    RateLimitInspect      `json:"rate_limit"`
	Acceleration *AccelerationInspect  `json:"acceleration,omitempty"`
	SmartCheck   *SmartCheck           `json:"smart_check,omitempty"`
	Errors       []InspectError        `json:"errors,omitempty"`
}

func (c *Client) InspectDomain(ctx context.Context, domain string) (*DomainInspect, error) {
	result := &DomainInspect{}
	var mu sync.Mutex

	recordError := func(section string, err error) {
		if err == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		result.Errors = append(result.Errors, InspectError{
			Section: section,
			Error:   err.Error(),
		})
	}

	var wg sync.WaitGroup
	run := func(section string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ctx.Err(); err != nil {
				recordError(section, err)
				return
			}
			recordError(section, fn())
		}()
	}

	run("domain", func() error {
		d, err := c.sdk.GetDomain(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.Domain = mapDomainDetail(*d)
		mu.Unlock()
		return nil
	})

	run("dns", func() error {
		records, err := c.ListDNSRecords(ctx, domain, "")
		if err != nil {
			return err
		}
		mu.Lock()
		result.DNS = DNSInspect{Count: len(records), Records: records}
		mu.Unlock()
		return nil
	})

	run("firewall_settings", func() error {
		settings, err := c.sdk.GetFirewallSettings(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.Firewall.Enabled = settings.IsEnabled
		result.Firewall.DefaultAction = settings.DefaultAction
		result.Firewall.VerifySNI = settings.VerifySNI
		mu.Unlock()
		return nil
	})

	run("firewall_rules", func() error {
		rules, err := c.ListFirewallRules(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.Firewall.RuleCount = len(rules)
		result.Firewall.Rules = rules
		mu.Unlock()
		return nil
	})

	run("waf", func() error {
		waf, err := c.fetchWafInspect(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.WAF = *waf
		mu.Unlock()
		return nil
	})

	run("ddos_settings", func() error {
		settings, err := c.sdk.GetDdosSettings(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.DDoS.Enabled = settings.IsEnabled
		result.DDoS.ProtectionMode = settings.ProtectionMode
		result.DDoS.CaptchaService = settings.CaptchaService
		mu.Unlock()
		return nil
	})

	run("ddos_rules", func() error {
		rules, err := c.listAllDdosRules(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.DDoS.RuleCount = len(rules)
		result.DDoS.Rules = rules
		mu.Unlock()
		return nil
	})

	run("page_rules", func() error {
		rules, err := c.listAllPageRules(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.PageRules = PageRulesInspect{Count: len(rules), Rules: rules}
		mu.Unlock()
		return nil
	})

	run("ssl", func() error {
		settings, err := c.sdk.GetSslSettings(ctx, domain)
		if err != nil {
			return err
		}
		certs := make([]CertificateSummary, 0, len(settings.Certificates))
		for _, cert := range settings.Certificates {
			certs = append(certs, CertificateSummary{
				ID:          cert.ID,
				Type:        cert.Type,
				Active:      cert.Active,
				DomainNames: cert.DomainNames,
				Issuer:      cert.Issuer,
				ExpiryDate:  cert.ExpiryDate,
			})
		}
		mu.Lock()
		result.SSL = SslInspect{
			Enabled:          settings.SSLStatus,
			CertificateMode:  settings.CertificateMode,
			TLSVersion:       settings.TLSVersion,
			HSTS:             settings.HSTSStatus,
			HTTPSRedirect:    settings.HTTPSRedirect,
			QUIC:             settings.QUICStatus,
			CertificateCount: len(certs),
			Certificates:     certs,
		}
		mu.Unlock()
		return nil
	})

	run("cache", func() error {
		settings, err := c.sdk.GetCacheSettings(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.Cache = CacheInspect{
			Status:           settings.CacheStatus,
			MaxAge:           settings.CacheMaxAge,
			DeveloperMode:    settings.CacheDeveloperMode,
			MaxSize:          settings.CacheMaxSize,
			ConsistentUptime: settings.CacheConsistentUptime,
		}
		mu.Unlock()
		return nil
	})

	run("load_balancer_settings", func() error {
		settings, err := c.sdk.GetLoadBalancerSettings(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.LoadBalancing.GlobalMethod = settings.Method
		result.LoadBalancing.Protocol = settings.Protocol
		result.LoadBalancing.Keepalive = settings.Keepalive
		result.LoadBalancing.GRPC = settings.GRPCStatus
		mu.Unlock()
		return nil
	})

	run("load_balancers", func() error {
		balancers, err := c.listAllLoadBalancers(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.LoadBalancing.Count = len(balancers)
		result.LoadBalancing.Balancers = balancers
		mu.Unlock()
		return nil
	})

	run("rate_limit_settings", func() error {
		settings, err := c.sdk.GetRateLimitSettings(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.RateLimit.DdosDetection = settings.DdosDetection
		mu.Unlock()
		return nil
	})

	run("rate_limit_rules", func() error {
		rules, err := c.listAllRateLimitRules(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.RateLimit.RuleCount = len(rules)
		result.RateLimit.Rules = rules
		mu.Unlock()
		return nil
	})

	run("acceleration", func() error {
		accel, err := c.sdk.GetAcceleration(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.Acceleration = &AccelerationInspect{
			Status:     accel.Status,
			Extensions: accel.Extensions,
		}
		mu.Unlock()
		return nil
	})

	run("smart_check", func() error {
		check, err := c.GetLatestSmartCheck(ctx, domain)
		if err != nil {
			return err
		}
		mu.Lock()
		result.SmartCheck = check
		mu.Unlock()
		return nil
	})

	wg.Wait()
	return result, ctx.Err()
}

func mapDomainDetail(d sdk.Domain) DomainDetail {
	detail := DomainDetail{
		Domain:       mapDomain(d),
		DNSCloud:     d.DNSCloud,
		CurrentNS:    d.CurrentNS,
		CnameTarget:  d.CnameTarget,
		CustomCname:  d.CustomCname,
		Restrictions: d.Restrictions,
		Fingerprint:  d.Fingerprint,
	}
	if !d.UpdatedAt.IsZero() {
		detail.UpdatedAt = d.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
	}
	return detail
}

func (c *Client) listAllDdosRules(ctx context.Context, domain string) ([]DdosRule, error) {
	var all []DdosRule
	page := 1
	for {
		resp, err := c.sdk.ListDdosRules(ctx, domain, page, defaultPerPage)
		if err != nil {
			return nil, err
		}
		for _, rule := range resp.Data {
			all = append(all, DdosRule{
				ID:          rule.ID,
				URLPattern:  rule.URLPattern,
				Action:      rule.Action,
				Enabled:     rule.IsEnabled,
				Description: rule.Description,
			})
		}
		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}
	return all, nil
}

func (c *Client) listAllPageRules(ctx context.Context, domain string) ([]PageRule, error) {
	var all []PageRule
	page := 1
	for {
		resp, err := c.sdk.ListPageRules(ctx, domain, page, defaultPerPage)
		if err != nil {
			return nil, err
		}
		for _, rule := range resp.Data {
			all = append(all, mapPageRuleSummary(rule))
		}
		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}
	return all, nil
}

func (c *Client) listAllLoadBalancers(ctx context.Context, domain string) ([]LoadBalancerEntry, error) {
	var all []LoadBalancerEntry
	page := 1
	for {
		resp, err := c.sdk.ListLoadBalancers(ctx, domain, page, defaultPerPage)
		if err != nil {
			return nil, err
		}
		for _, lb := range resp.Data {
			all = append(all, LoadBalancerEntry{
				ID:          lb.ID,
				Name:        lb.Name,
				Enabled:     lb.Status,
				Method:      lb.Method,
				PoolCount:   len(lb.Pools),
				Description: lb.Description,
			})
		}
		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}
	return all, nil
}

func (c *Client) listAllRateLimitRules(ctx context.Context, domain string) ([]RateLimitRule, error) {
	var all []RateLimitRule
	page := 1
	for {
		resp, err := c.sdk.ListRateLimitRules(ctx, domain, page, defaultPerPage)
		if err != nil {
			return nil, err
		}
		for _, rule := range resp.Data {
			all = append(all, RateLimitRule{
				ID:           rule.ID,
				URLPattern:   rule.URLPattern,
				Action:       rule.Action,
				Enabled:      rule.IsEnabled,
				Rate:         rule.Rate,
				TimeDuration: rule.TimeDuration,
				Description:  rule.Description,
			})
		}
		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}
	return all, nil
}
