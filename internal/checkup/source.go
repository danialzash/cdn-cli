package checkup

import (
	"context"
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

func (s *ClientSource) LoadInspect(ctx context.Context, domain string, categories map[Category]bool) (*client.DomainInspect, error) {
	sections := make(map[string]bool, len(categories))
	for c, enabled := range categories {
		if enabled {
			sections[string(c)] = true
		}
	}
	return s.Client.LoadCheckupInspect(ctx, domain, sections)
}

func (s *ClientSource) CheckNameservers(ctx context.Context, domain string) (*client.NSCheckResult, error) {
	return s.Client.CheckNameservers(ctx, domain)
}

func (s *ClientSource) CheckCnameSetup(ctx context.Context, domain string) (*client.CnameCheckResult, error) {
	return s.Client.CheckCnameSetup(ctx, domain)
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
		return nil
	}
}
