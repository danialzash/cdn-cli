package dnsverify

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

const (
	DefaultWorkers    = 10
	DefaultDNSTimeout = 5 * time.Second
)

var resolverDialIndex atomic.Uint64

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
	normalized, err := NormalizeResolvers(resolvers)
	if err != nil || len(normalized) == 0 {
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: timeout}
				return dialer.DialContext(ctx, network, address)
			},
		}
	}
	servers := append([]string(nil), normalized...)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: timeout}
			index := resolverDialIndex.Add(1) - 1
			server := servers[index%uint64(len(servers))]
			return dialer.DialContext(ctx, network, server)
		},
	}
}
