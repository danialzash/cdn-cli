package client

import (
	"context"
	"net"
	"strings"
	"sync"
)

type NSCheckResult struct {
	Published []string
	Expected  []string
}

type CnameCheckResult struct {
	ResolvedTarget string
	ExpectedTarget string
	Matches        bool
	Status         string
	ResolveError   string
}

func (c *Client) GetDomainDetail(ctx context.Context, idOrName string) (*DomainDetail, error) {
	d, err := c.sdk.GetDomain(ctx, idOrName)
	if err != nil {
		return nil, err
	}
	detail := mapDomainDetail(*d)
	return &detail, nil
}

func (c *Client) CheckNameservers(ctx context.Context, domain string) (*NSCheckResult, error) {
	data, err := c.sdk.CheckNameservers(ctx, domain)
	if err != nil {
		return nil, err
	}
	return &NSCheckResult{
		Published: data.Published,
		Expected:  data.Expected,
	}, nil
}

func (c *Client) CheckCnameSetup(ctx context.Context, domain string) (*CnameCheckResult, error) {
	d, err := c.sdk.CheckCnameSetup(ctx, domain)
	if err != nil {
		return nil, err
	}
	expected := d.CnameTarget
	if d.CustomCname != "" {
		expected = d.CustomCname
	}
	resolved, resolveErr := lookupPublicCNAME(ctx, domain)
	matches := cnameTargetMatches(resolved, expected) || strings.EqualFold(d.Status, "active")
	return &CnameCheckResult{
		ResolvedTarget: resolved,
		ExpectedTarget: expected,
		Status:         d.Status,
		Matches:        matches,
		ResolveError:   resolveErrString(resolveErr),
	}, nil
}

func lookupPublicCNAME(ctx context.Context, domain string) (string, error) {
	resolver := &net.Resolver{PreferGo: true}
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return "", err
	}
	return normalizeCnameHost(cname), nil
}

func normalizeCnameHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return host
}

func cnameTargetMatches(resolved, expected string) bool {
	resolved = normalizeCnameHost(resolved)
	expected = normalizeCnameHost(expected)
	if resolved == "" || expected == "" {
		return false
	}
	if strings.EqualFold(resolved, expected) {
		return true
	}
	return strings.HasSuffix(strings.ToLower(resolved), "."+strings.ToLower(expected))
}

func resolveErrString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (c *Client) LoadCheckupInspect(ctx context.Context, domain string, sections map[string]bool) (*DomainInspect, error) {
	if sections["configuration"] {
		return c.InspectDomain(ctx, domain)
	}
	return c.loadPartialInspect(ctx, domain, sections)
}

func (c *Client) loadPartialInspect(ctx context.Context, domain string, sections map[string]bool) (*DomainInspect, error) {
	result := &DomainInspect{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	recordError := func(section string, err error) {
		if err == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		result.Errors = append(result.Errors, InspectError{Section: section, Error: err.Error()})
	}

	run := func(section string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
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

	if sections["dns"] || sections["activation"] {
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
	}

	if sections["security"] || sections["configuration"] {
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
	}

	if sections["cache"] || sections["configuration"] {
		run("cache", func() error {
			settings, err := c.sdk.GetCacheSettings(ctx, domain)
			if err != nil {
				return err
			}
			mu.Lock()
			result.Cache = CacheInspect{
				Status: settings.CacheStatus, MaxAge: settings.CacheMaxAge,
				DeveloperMode: settings.CacheDeveloperMode, MaxSize: settings.CacheMaxSize,
				ConsistentUptime: settings.CacheConsistentUptime,
			}
			mu.Unlock()
			return nil
		})
	}

	if sections["tls"] || sections["security"] || sections["http"] || sections["configuration"] {
		run("ssl", func() error {
			settings, err := c.sdk.GetSslSettings(ctx, domain)
			if err != nil {
				return err
			}
			certs := make([]CertificateSummary, 0, len(settings.Certificates))
			for _, cert := range settings.Certificates {
				certs = append(certs, CertificateSummary{
					ID: cert.ID, Type: cert.Type, Active: cert.Active,
					DomainNames: cert.DomainNames, Issuer: cert.Issuer, ExpiryDate: cert.ExpiryDate,
				})
			}
			mu.Lock()
			result.SSL = SslInspect{
				Enabled: settings.SSLStatus, CertificateMode: settings.CertificateMode,
				TLSVersion: settings.TLSVersion, HSTS: settings.HSTSStatus,
				HTTPSRedirect: settings.HTTPSRedirect, QUIC: settings.QUICStatus,
				CertificateCount: len(certs), Certificates: certs,
			}
			mu.Unlock()
			return nil
		})
	}

	if sections["configuration"] {
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
		run("load_balancers", func() error {
			settings, err := c.sdk.GetLoadBalancerSettings(ctx, domain)
			if err != nil {
				return err
			}
			mu.Lock()
			result.LoadBalancing.GlobalMethod = settings.Method
			result.LoadBalancing.Protocol = settings.Protocol
			mu.Unlock()
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
	}

	if sections["smartcheck"] {
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
	}

	wg.Wait()
	return result, ctx.Err()
}

func (c *Client) fetchWafInspect(ctx context.Context, domain string) (*WafInspect, error) {
	settings, err := c.sdk.GetWafSettings(ctx, domain)
	if err != nil {
		return nil, err
	}
	mode := settings.Mode
	if mode == "" {
		mode = "off"
	}
	resp, err := c.sdk.ListDomainWafPackages(ctx, domain)
	if err != nil {
		return nil, err
	}
	packages := make([]WafPackage, 0, len(resp.Data))
	for _, pkg := range resp.Data {
		status := "disabled"
		enabled := false
		if pkg.IsEnabled != nil && *pkg.IsEnabled {
			status = "enabled"
			enabled = true
		}
		packages = append(packages, WafPackage{
			ID: pkg.ID, Name: pkg.Name, Mode: mode, Status: status, Enabled: enabled,
		})
	}
	return &WafInspect{
		Enabled: settings.IsEnabled, Mode: mode,
		PackageCount: len(packages), Packages: packages,
	}, nil
}

func (c *Client) DisableCacheDeveloperMode(ctx context.Context, domain string) error {
	falseVal := false
	_, err := c.UpdateCacheSettings(ctx, domain, UpdateCacheSettingsInput{DeveloperMode: &falseVal})
	return err
}

func (c *Client) DisableDNSCloudProxy(ctx context.Context, domain, recordID string) error {
	falseVal := false
	_, err := c.UpdateDNSRecord(ctx, domain, recordID, UpdateDNSRecordInput{Cloud: &falseVal})
	return err
}

func (c *Client) EnableHTTPSRedirect(ctx context.Context, domain string) error {
	trueVal := true
	_, err := c.UpdateSslSettings(ctx, domain, UpdateSslSettingsInput{HTTPSRedirect: &trueVal})
	return err
}
