package dnsverify

import (
	"context"
	"net"
	"strings"
	"time"
)

const (
	DefaultWorkers    = 10
	DefaultDNSTimeout = 5 * time.Second
)

func NewChecker() *Checker {
	return &Checker{Resolver: newResolver(DefaultDNSTimeout, nil)}
}

func NewCheckerWithResolvers(timeout time.Duration, resolvers []string) *Checker {
	if timeout <= 0 {
		timeout = DefaultDNSTimeout
	}
	return &Checker{Resolver: newResolver(timeout, resolvers)}
}

func newResolver(timeout time.Duration, resolvers []string) *net.Resolver {
	if len(resolvers) == 0 {
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: timeout}
				return dialer.DialContext(ctx, network, address)
			},
		}
	}
	servers := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !strings.Contains(r, ":") {
			r = net.JoinHostPort(r, "53")
		}
		servers = append(servers, r)
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: timeout}
			if len(servers) == 0 {
				return dialer.DialContext(ctx, network, address)
			}
			server := servers[0]
			if len(servers) > 1 {
				// Round-robin across resolvers based on time for basic distribution.
				server = servers[int(time.Now().UnixNano())%len(servers)]
			}
			return dialer.DialContext(ctx, network, server)
		},
	}
}
