package checkup

import (
	"context"
	"fmt"
	"net"
	"strconv"
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

func (r *Runner) selectOrigin(ctx context.Context, state *State, customerDomain, path string) OriginSelection {
	opts := state.Options
	scheme := strings.ToLower(strings.TrimSpace(opts.OriginScheme))
	if scheme == "" {
		scheme = "auto"
	}

	host, embeddedPort, portProvided, err := parseOriginHostPort(opts.Origin, opts.OriginPort, opts.OriginPortSet)
	if err != nil {
		state.AddProbeError("origin.parse", err.Error())
		return OriginSelection{}
	}

	port := embeddedPort
	if opts.OriginPortSet {
		port = opts.OriginPort
		portProvided = true
	}

	timeout := opts.ProbeTimeoutDuration()

	switch scheme {
	case "http", "https":
		if !portProvided {
			port = originDefaultPort(scheme)
		}
		address := joinOriginAddress(host, port)
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
		if portProvided {
			httpsAttempt, httpsOK := r.probeOriginScheme(ctx, timeout, "https", host, port, path, customerDomain)
			if httpsOK {
				return OriginSelection{Scheme: "https", Address: httpsAttempt.Address, Port: port, Attempts: []OriginSchemeAttempt{httpsAttempt}}
			}
			httpAttempt, httpOK := r.probeOriginScheme(ctx, timeout, "http", host, port, path, customerDomain)
			if httpOK {
				return OriginSelection{Scheme: "http", Address: httpAttempt.Address, Port: port, Attempts: []OriginSchemeAttempt{httpsAttempt, httpAttempt}}
			}
			return OriginSelection{Attempts: []OriginSchemeAttempt{httpsAttempt, httpAttempt}}
		}
		httpsAttempt, httpsOK := r.probeOriginScheme(ctx, timeout, "https", host, 443, path, customerDomain)
		if httpsOK {
			return OriginSelection{Scheme: "https", Address: httpsAttempt.Address, Port: 443, Attempts: []OriginSchemeAttempt{httpsAttempt}}
		}
		httpAttempt, httpOK := r.probeOriginScheme(ctx, timeout, "http", host, 80, path, customerDomain)
		if httpOK {
			return OriginSelection{Scheme: "http", Address: httpAttempt.Address, Port: 80, Attempts: []OriginSchemeAttempt{httpsAttempt, httpAttempt}}
		}
		return OriginSelection{Attempts: []OriginSchemeAttempt{httpsAttempt, httpAttempt}}
	}
}

func (r *Runner) probeOriginScheme(ctx context.Context, timeout time.Duration, scheme, host string, port int, path, customerDomain string) (OriginSchemeAttempt, bool) {
	address := joinOriginAddress(host, port)
	client := NewOriginProbeHTTPClient(timeout, address, tlsSNIForScheme(scheme, customerDomain))
	url := fmt.Sprintf("%s://%s%s", scheme, address, path)
	probe := ProbeHTTP(ctx, client, url, customerDomain)
	if probe.Error == "" {
		return OriginSchemeAttempt{Scheme: scheme, Status: "success", Address: address}, true
	}
	return OriginSchemeAttempt{
		Scheme:         scheme,
		Status:         "failed",
		Error:          probe.Error,
		Address:        address,
		ProbeExecError: probe.ProbeExecError,
		TimedOut:       probe.TimedOut,
	}, false
}

func defaultOriginHostHeader(address, scheme string) string {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	if net.ParseIP(host) != nil {
		return address
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return address
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return host
	}
	return address
}
