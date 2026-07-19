package checkup

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPublicDNSResolverUsesDefaultAddressWithoutCustomResolver(t *testing.T) {
	var addresses []string
	r, err := NewPublicDNSResolver(nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r.dialFn = func(_ context.Context, _, address string) (net.Conn, error) {
		addresses = append(addresses, address)
		return nil, errors.New("test dial stopped")
	}
	_, err = r.dial(context.Background(), "udp", "192.0.2.1:53")
	if err == nil {
		t.Fatal("expected dial error")
	}
	if len(addresses) != 1 || addresses[0] != "192.0.2.1:53" {
		t.Fatalf("addresses = %v", addresses)
	}
}

func TestPublicDNSResolverUsesCustomResolver(t *testing.T) {
	var addresses []string
	r, err := NewPublicDNSResolver([]string{"192.0.2.1:53"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r.dialFn = func(_ context.Context, _, address string) (net.Conn, error) {
		addresses = append(addresses, address)
		return nil, errors.New("test dial stopped")
	}
	_, err = r.dial(context.Background(), "udp", "192.0.2.1:53")
	if err == nil {
		t.Fatal("expected dial error")
	}
	if len(addresses) != 1 || addresses[0] != "192.0.2.1:53" {
		t.Fatalf("addresses = %v", addresses)
	}
}

func TestPublicDNSResolverRoundRobin(t *testing.T) {
	var addresses []string
	var mu sync.Mutex
	r, err := NewPublicDNSResolver([]string{"192.0.2.1:53", "192.0.2.2:53"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r.dialFn = func(_ context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		addresses = append(addresses, address)
		mu.Unlock()
		return nil, errors.New("test dial stopped")
	}
	_, _ = r.dial(context.Background(), "udp", "192.0.2.1:53")
	_, _ = r.dial(context.Background(), "udp", "192.0.2.1:53")
	if len(addresses) != 2 || addresses[0] == addresses[1] {
		t.Fatalf("expected round-robin addresses, got %v", addresses)
	}
}

func TestPublicDNSResolverIPv6AddressPreserved(t *testing.T) {
	var addresses []string
	r, err := NewPublicDNSResolver([]string{"[2001:db8::1]:53"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r.dialFn = func(_ context.Context, _, address string) (net.Conn, error) {
		addresses = append(addresses, address)
		return nil, errors.New("test dial stopped")
	}
	_, _ = r.dial(context.Background(), "udp", "192.0.2.1:53")
	if len(addresses) != 1 || addresses[0] != "[2001:db8::1]:53" {
		t.Fatalf("addresses = %v", addresses)
	}
}

func TestOptionsRejectInvalidResolverPort(t *testing.T) {
	opts := DefaultOptions()
	opts.Resolvers = []string{"1.1.1.1:99999"}
	if err := opts.Validate(); err == nil {
		t.Fatal("expected invalid resolver port error")
	}
}
