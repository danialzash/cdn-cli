package checkup

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

type resolverDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// PublicDNSResolver performs public DNS lookups using configured resolvers.
type PublicDNSResolver struct {
	servers []string
	timeout time.Duration
	dialFn  resolverDialFunc
	next    atomic.Uint64
}

func NewPublicDNSResolver(resolvers []string, timeout time.Duration) (*PublicDNSResolver, error) {
	servers, err := dnsverify.NormalizeResolvers(resolvers)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	return &PublicDNSResolver{
		servers: servers,
		timeout: timeout,
		dialFn:  dialer.DialContext,
	}, nil
}

func (r *PublicDNSResolver) dial(ctx context.Context, network, defaultAddress string) (net.Conn, error) {
	if r == nil || r.dialFn == nil {
		return nil, net.ErrClosed
	}
	if len(r.servers) == 0 {
		return r.dialFn(ctx, network, defaultAddress)
	}
	index := r.next.Add(1) - 1
	server := r.servers[index%uint64(len(r.servers))]
	return r.dialFn(ctx, network, server)
}

func (r *PublicDNSResolver) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return r.dial(ctx, network, address)
		},
	}
}

func (r *PublicDNSResolver) LookupHost(ctx context.Context, name string) ([]string, error) {
	if r == nil {
		return nil, net.ErrClosed
	}
	return r.resolver().LookupHost(ctx, name)
}

func (r *PublicDNSResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	if r == nil {
		return "", net.ErrClosed
	}
	cname, err := r.resolver().LookupCNAME(ctx, name)
	if err != nil {
		return "", err
	}
	return normalizeCnameHost(cname), nil
}

func (r *PublicDNSResolver) Lookup(ctx context.Context, name string) DNSLookupResult {
	result := DNSLookupResult{Hostname: name}
	addresses, err := r.LookupHost(ctx, name)
	result.Classification = ClassifyDNSError(err)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Addresses = addresses
	result.Classification = DNSLookupFound
	return result
}

func normalizeCnameHost(host string) string {
	return dnsverify.NormalizeCnameHost(host)
}

func cnameTargetMatches(resolved, expected string) bool {
	return dnsverify.CnameTargetMatches(resolved, expected)
}

func BuildCnameCheckResult(apiStatus, expected, resolved string, classification DNSLookupClassification, resolveErr string) *CnameCheckResult {
	liveMatches := cnameTargetMatches(resolved, expected)
	return &CnameCheckResult{
		APIStatus:      apiStatus,
		ExpectedTarget: expected,
		ResolvedTarget: resolved,
		LiveMatches:    liveMatches,
		Classification: classification,
		ResolveError:   resolveErr,
	}
}

// CnameCheckResult holds live and API activation facts separately.
type CnameCheckResult struct {
	APIStatus      string
	ExpectedTarget string
	ResolvedTarget string
	LiveMatches    bool
	Classification DNSLookupClassification
	ResolveError   string
}
