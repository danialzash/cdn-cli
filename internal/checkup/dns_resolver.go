package checkup

import (
	"context"
	"net"
	"strings"
	"time"
)

// PublicDNSResolver performs public DNS lookups using configured resolvers.
type PublicDNSResolver struct {
	Resolver *net.Resolver
}

func NewPublicDNSResolver(resolvers []string, timeout time.Duration) *PublicDNSResolver {
	if len(resolvers) == 0 {
		return &PublicDNSResolver{Resolver: net.DefaultResolver}
	}
	dialer := &net.Dialer{Timeout: timeout}
	return &PublicDNSResolver{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if len(resolvers) > 0 {
					address = net.JoinHostPort(resolvers[0], "53")
				}
				return dialer.DialContext(ctx, network, address)
			},
		},
	}
}

func (r *PublicDNSResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	if r == nil || r.Resolver == nil {
		return "", net.ErrClosed
	}
	cname, err := r.Resolver.LookupCNAME(ctx, name)
	if err != nil {
		return "", err
	}
	return normalizeCnameHost(cname), nil
}

func (r *PublicDNSResolver) HostResolves(ctx context.Context, name string) bool {
	if r == nil || r.Resolver == nil {
		return false
	}
	_, err := r.Resolver.LookupHost(ctx, name)
	return err == nil
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

func BuildCnameCheckResult(apiStatus, expected, resolved, resolveErr string) *CnameCheckResult {
	liveMatches := cnameTargetMatches(resolved, expected)
	return &CnameCheckResult{
		APIStatus:      apiStatus,
		ExpectedTarget: expected,
		ResolvedTarget: resolved,
		LiveMatches:    liveMatches,
		ResolveError:   resolveErr,
	}
}

// CnameCheckResult holds live and API activation facts separately.
type CnameCheckResult struct {
	APIStatus      string
	ExpectedTarget string
	ResolvedTarget string
	LiveMatches    bool
	ResolveError   string
}
