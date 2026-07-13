package dnsverify

import (
	"context"
	"net"
	"time"
)

const (
	DefaultWorkers    = 10
	DefaultDNSTimeout = 5 * time.Second
)

func NewChecker() *Checker {
	return &Checker{Resolver: newResolver(DefaultDNSTimeout)}
}

func newResolver(timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, network, address)
		},
	}
}
