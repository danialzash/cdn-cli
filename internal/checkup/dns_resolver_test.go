package checkup

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPublicDNSResolverUsesDefaultAddressWithoutCustomResolver(t *testing.T) {
	r, err := NewPublicDNSResolver(nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	gotAddress := dialTarget(t, r)
	if gotAddress != "192.0.2.1:53" {
		t.Fatalf("expected default resolver address 192.0.2.1:53, got %q", gotAddress)
	}
}

func TestPublicDNSResolverUsesCustomResolver(t *testing.T) {
	r, err := NewPublicDNSResolver([]string{"192.0.2.1:53"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	gotAddress := dialTarget(t, r)
	if gotAddress != "192.0.2.1:53" {
		t.Fatalf("got %q", gotAddress)
	}
}

func TestPublicDNSResolverRoundRobin(t *testing.T) {
	publicResolverDialIndex.Store(0)
	r, err := NewPublicDNSResolver([]string{"192.0.2.1:53", "192.0.2.2:53"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first := dialTarget(t, r)
	second := dialTarget(t, r)
	if first == second {
		t.Fatalf("expected round-robin addresses, got %q twice", first)
	}
}

func dialTarget(t *testing.T, r *PublicDNSResolver) string {
	t.Helper()
	_, err := r.dial(context.Background(), "udp", "192.0.2.1:53")
	addrErr, ok := err.(*net.OpError)
	if !ok {
		t.Fatalf("expected OpError, got %v", err)
	}
	return addrErr.Addr.String()
}

func TestOptionsRejectInvalidResolverPort(t *testing.T) {
	opts := DefaultOptions()
	opts.Resolvers = []string{"1.1.1.1:99999"}
	if err := opts.Validate(); err == nil {
		t.Fatal("expected invalid resolver port error")
	}
}
