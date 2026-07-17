package checkup

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vergecloud/cdn-cli/internal/client"
)

type ClientSource struct {
	Client *client.Client
}

func NewClientSource(c *client.Client) *ClientSource {
	return &ClientSource{Client: c}
}

func (s *ClientSource) ResolveDomain(ctx context.Context, idOrName string) (*client.DomainDetail, error) {
	return s.Client.GetDomainDetail(ctx, idOrName)
}

func (s *ClientSource) LoadInspect(ctx context.Context, domain string, sections map[string]bool) (*client.DomainInspect, error) {
	return s.Client.LoadCheckupInspect(ctx, domain, sections)
}

func (s *ClientSource) CheckNameservers(ctx context.Context, domain string) (*client.NSCheckResult, error) {
	return s.Client.CheckNameservers(ctx, domain)
}

func (s *ClientSource) FetchCnameSetupStatus(ctx context.Context, domain string) (*client.CnameSetupStatus, error) {
	return s.Client.FetchCnameSetupStatus(ctx, domain)
}

func (s *ClientSource) GetLatestSmartCheck(ctx context.Context, domain string) (*client.SmartCheck, error) {
	return s.Client.GetLatestSmartCheck(ctx, domain)
}

type ClientFixApplier struct {
	Client       *client.Client
	ProbeTimeout time.Duration
}

func NewClientFixApplier(c *client.Client) *ClientFixApplier {
	return &ClientFixApplier{Client: c, ProbeTimeout: DefaultProbeTimeout}
}

func (a *ClientFixApplier) ApplyFix(ctx context.Context, domain string, plan FixPlan) error {
	switch {
	case plan.ID == "cache.developer-mode":
		return a.Client.DisableCacheDeveloperMode(ctx, domain)
	case strings.HasPrefix(plan.ID, "dns.mail-cloud-proxy."):
		recordID := strings.TrimPrefix(plan.ID, "dns.mail-cloud-proxy.")
		return a.Client.DisableDNSCloudProxy(ctx, domain, recordID)
	case plan.ID == "ssl.https-redirect":
		return a.Client.EnableHTTPSRedirect(ctx, domain)
	default:
		return fmt.Errorf("unsupported automatic fix %q", plan.ID)
	}
}

func (a *ClientFixApplier) VerifyFix(ctx context.Context, domain string, plan FixPlan) (FixVerification, string, error) {
	switch {
	case plan.ID == "cache.developer-mode":
		settings, err := a.Client.GetCacheSettings(ctx, domain)
		if err != nil {
			return FixVerification{}, "", err
		}
		if settings.DeveloperMode {
			return FixVerification{ConfigurationVerified: false}, "cache developer mode is still enabled", nil
		}
		return FixVerification{ConfigurationVerified: true, BehaviorVerified: true}, "", nil
	case strings.HasPrefix(plan.ID, "dns.mail-cloud-proxy."):
		recordID := strings.TrimPrefix(plan.ID, "dns.mail-cloud-proxy.")
		record, err := a.Client.GetDNSRecord(ctx, domain, recordID)
		if err != nil {
			return FixVerification{}, "", err
		}
		if record.Cloud {
			return FixVerification{ConfigurationVerified: false}, "DNS record cloud proxy is still enabled", nil
		}
		return FixVerification{ConfigurationVerified: true, BehaviorVerified: true}, "", nil
	case plan.ID == "ssl.https-redirect":
		settings, err := a.Client.GetSslSettings(ctx, domain)
		if err != nil {
			return FixVerification{}, "", err
		}
		verification := FixVerification{ConfigurationVerified: settings.HTTPSRedirect}
		if !settings.HTTPSRedirect {
			return verification, "HTTPS redirect is still disabled", nil
		}
		timeout := a.ProbeTimeout
		if timeout <= 0 {
			timeout = DefaultProbeTimeout
		}
		probe := ProbeHTTP(ctx, NewProbeHTTPClient(timeout), "http://"+domain+"/", "")
		verification.BehaviorVerified = httpRedirectsToRelatedHTTPS(probe, domain)
		if !verification.BehaviorVerified {
			return verification, "HTTPS redirect is enabled in the API but live HTTP did not redirect to HTTPS", nil
		}
		return verification, "", nil
	default:
		return FixVerification{}, "", fmt.Errorf("unsupported automatic fix %q", plan.ID)
	}
}
