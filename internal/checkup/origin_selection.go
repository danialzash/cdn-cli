package checkup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type OriginSelection struct {
	Scheme   string
	Address  string
	Port     int
	Attempts []OriginSchemeAttempt
}

func originDefaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

func tlsSNIForScheme(scheme, customerDomain string) string {
	if scheme == "https" {
		return customerDomain
	}
	return ""
}

func parseOriginHostPort(origin string, explicitPort int) (host string, port int, portFromOrigin bool) {
	host = strings.TrimSpace(origin)
	port = explicitPort
	if host == "" {
		return "", 0, false
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if explicitPort == 0 {
			fmt.Sscanf(p, "%d", &port)
			portFromOrigin = true
		}
	}
	if explicitPort != 0 {
		port = explicitPort
		portFromOrigin = true
	}
	return host, port, portFromOrigin
}

func (r *Runner) selectOrigin(ctx context.Context, state *State, customerDomain, path string) OriginSelection {
	opts := state.Options
	scheme := strings.ToLower(strings.TrimSpace(opts.OriginScheme))
	if scheme == "" {
		scheme = "auto"
	}

	host, port, portFromOrigin := parseOriginHostPort(opts.Origin, opts.OriginPort)
	timeout := opts.ProbeTimeoutDuration()

	switch scheme {
	case "http", "https":
		if !portFromOrigin {
			port = originDefaultPort(scheme)
		}
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		return OriginSelection{
			Scheme:  scheme,
			Address: address,
			Port:    port,
			Attempts: []OriginSchemeAttempt{{
				Scheme:  scheme,
				Status:  "selected",
				Address: address,
			}},
		}
	default:
		if portFromOrigin {
			httpsAttempt, httpsOK := r.probeOriginScheme(ctx, timeout, "https", host, port, path, customerDomain)
			if httpsOK {
				return OriginSelection{Scheme: "https", Address: httpsAttempt.Address, Port: port, Attempts: []OriginSchemeAttempt{httpsAttempt}}
			}
			httpAttempt, httpOK := r.probeOriginScheme(ctx, timeout, "http", host, port, path, customerDomain)
			if httpOK {
				return OriginSelection{Scheme: "http", Address: httpAttempt.Address, Port: port, Attempts: []OriginSchemeAttempt{httpsAttempt, httpAttempt}}
			}
			return OriginSelection{Scheme: "https", Address: httpsAttempt.Address, Port: port, Attempts: []OriginSchemeAttempt{httpsAttempt, httpAttempt}}
		}
		httpsAttempt, httpsOK := r.probeOriginScheme(ctx, timeout, "https", host, 443, path, customerDomain)
		if httpsOK {
			return OriginSelection{Scheme: "https", Address: httpsAttempt.Address, Port: 443, Attempts: []OriginSchemeAttempt{httpsAttempt}}
		}
		httpAttempt, httpOK := r.probeOriginScheme(ctx, timeout, "http", host, 80, path, customerDomain)
		if httpOK {
			return OriginSelection{Scheme: "http", Address: httpAttempt.Address, Port: 80, Attempts: []OriginSchemeAttempt{httpsAttempt, httpAttempt}}
		}
		return OriginSelection{Scheme: "https", Address: httpsAttempt.Address, Port: 443, Attempts: []OriginSchemeAttempt{httpsAttempt, httpAttempt}}
	}
}

func (r *Runner) probeOriginScheme(ctx context.Context, timeout time.Duration, scheme, host string, port int, path, customerDomain string) (OriginSchemeAttempt, bool) {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	client := NewOriginProbeHTTPClient(timeout, address, tlsSNIForScheme(scheme, customerDomain))
	url := fmt.Sprintf("%s://%s%s", scheme, address, path)
	probe := ProbeHTTP(ctx, client, url, customerDomain)
	if probe.Error == "" {
		return OriginSchemeAttempt{Scheme: scheme, Status: "success", Address: address}, true
	}
	return OriginSchemeAttempt{Scheme: scheme, Status: "failed", Error: probe.Error, Address: address}, false
}
