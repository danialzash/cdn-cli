package checkup

import (
	"context"
	"fmt"
	"strings"

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
	Client *client.Client
}

func NewClientFixApplier(c *client.Client) *ClientFixApplier {
	return &ClientFixApplier{Client: c}
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

func (a *ClientFixApplier) VerifyFix(ctx context.Context, domain string, plan FixPlan) (bool, string, error) {
	switch {
	case plan.ID == "cache.developer-mode":
		settings, err := a.Client.GetCacheSettings(ctx, domain)
		if err != nil {
			return false, "", err
		}
		if settings.DeveloperMode {
			return false, "cache developer mode is still enabled", nil
		}
		return true, "", nil
	case strings.HasPrefix(plan.ID, "dns.mail-cloud-proxy."):
		recordID := strings.TrimPrefix(plan.ID, "dns.mail-cloud-proxy.")
		record, err := a.Client.GetDNSRecord(ctx, domain, recordID)
		if err != nil {
			return false, "", err
		}
		if record.Cloud {
			return false, "DNS record cloud proxy is still enabled", nil
		}
		return true, "", nil
	case plan.ID == "ssl.https-redirect":
		settings, err := a.Client.GetSslSettings(ctx, domain)
		if err != nil {
			return false, "", err
		}
		if !settings.HTTPSRedirect {
			return false, "HTTPS redirect is still disabled", nil
		}
		return true, "", nil
	default:
		return false, "", fmt.Errorf("unsupported automatic fix %q", plan.ID)
	}
}
