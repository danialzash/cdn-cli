package checkup

import (
	"context"
	"errors"
	"net"
	"strings"
)

type DNSLookupClassification string

const (
	DNSLookupFound       DNSLookupClassification = "found"
	DNSLookupNotFound    DNSLookupClassification = "not_found"
	DNSLookupTimeout     DNSLookupClassification = "timeout"
	DNSLookupUnavailable DNSLookupClassification = "resolver_unavailable"
	DNSLookupCancelled   DNSLookupClassification = "cancelled"
	DNSLookupError       DNSLookupClassification = "error"
)

type DNSLookupResult struct {
	Hostname       string
	Addresses      []string
	CNAME          string
	Classification DNSLookupClassification
	Error          string
}

func ClassifyDNSError(err error) DNSLookupClassification {
	if err == nil {
		return DNSLookupFound
	}
	if errors.Is(err, context.Canceled) {
		return DNSLookupCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return DNSLookupTimeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return DNSLookupNotFound
		}
		if dnsErr.IsTimeout {
			return DNSLookupTimeout
		}
		if dnsErr.IsTemporary {
			return DNSLookupUnavailable
		}
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "network is unreachable") {
		return DNSLookupUnavailable
	}
	return DNSLookupError
}

func (c DNSLookupClassification) IsProbeError() bool {
	switch c {
	case DNSLookupTimeout, DNSLookupUnavailable, DNSLookupCancelled, DNSLookupError:
		return true
	default:
		return false
	}
}

func (c DNSLookupClassification) IsNotFound() bool {
	return c == DNSLookupNotFound
}
