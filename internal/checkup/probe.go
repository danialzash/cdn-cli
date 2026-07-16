package checkup

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/vergecloud/cdn-cli/internal/version"
)

const (
	maxRedirects    = 10
	maxBodyRead     = 64 * 1024
	maxProbeWorkers = 6
)

var safeHeaderAllowlist = map[string]struct{}{
	"server":                    {},
	"date":                      {},
	"location":                  {},
	"content-type":              {},
	"content-length":            {},
	"cache-control":             {},
	"age":                       {},
	"vary":                      {},
	"etag":                      {},
	"last-modified":             {},
	"content-encoding":          {},
	"strict-transport-security": {},
	"x-cache":                   {},
	"x-cache-status":            {},
	"x-poweredby":               {},
	"x-powered-by":              {},
	"x-request-id":              {},
	"x-verge-request-id":        {},
	"via":                       {},
	"alt-svc":                   {},
}

var analysisHeaderAllowlist = map[string]struct{}{
	"content-security-policy":      {},
	"x-content-type-options":       {},
	"referrer-policy":              {},
	"permissions-policy":           {},
	"x-frame-options":              {},
	"cross-origin-opener-policy":   {},
	"cross-origin-resource-policy": {},
	"cross-origin-embedder-policy": {},
	"strict-transport-security":    {},
	"cache-control":                {},
	"age":                          {},
	"vary":                         {},
	"x-cache":                      {},
	"x-cache-status":               {},
	"x-poweredby":                  {},
	"x-powered-by":                 {},
	"x-request-id":                 {},
	"x-verge-request-id":           {},
	"server":                       {},
	"via":                          {},
}

func FilterSafeHeaders(headers http.Header) map[string]string {
	out := make(map[string]string)
	for key, values := range headers {
		lower := strings.ToLower(key)
		if _, ok := safeHeaderAllowlist[lower]; !ok {
			continue
		}
		if len(values) > 0 {
			out[lower] = values[0]
		}
	}
	return out
}

func FilterAnalysisHeaders(headers http.Header) map[string]string {
	out := make(map[string]string)
	for key, values := range headers {
		lower := strings.ToLower(key)
		if _, ok := analysisHeaderAllowlist[lower]; !ok {
			continue
		}
		if len(values) > 0 {
			out[lower] = values[0]
		}
	}
	// Merge safe output headers needed for analysis.
	for k, v := range FilterSafeHeaders(headers) {
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	}
	return out
}

func NewProbeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   false,
		},
	}
}

// NewOriginProbeHTTPClient dials dialAddress while using tlsServerName for TLS SNI.
func NewOriginProbeHTTPClient(timeout time.Duration, dialAddress, tlsServerName string) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		},
		TLSHandshakeTimeout: timeout,
	}
	if tlsServerName != "" {
		transport.TLSClientConfig = &tls.Config{ServerName: tlsServerName}
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
		Transport: transport,
	}
}

func ProbeHTTP(ctx context.Context, client *http.Client, rawURL string, hostHeader string) *HTTPProbeResult {
	result := &HTTPProbeResult{URL: rawURL}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		result.Error = err.Error()
		result.ProbeExecError = true
		return result
	}
	req.Header.Set("User-Agent", version.UserAgent+"-checkup")
	if hostHeader != "" {
		req.Host = hostHeader
	}

	var (
		dnsStart, dnsDone         time.Time
		connectStart, connectDone time.Time
		tlsStart, tlsDone         time.Time
		gotFirstResponse          time.Time
		start                     = time.Now()
	)

	trace := &httptrace.ClientTrace{
		DNSStart:             func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:              func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart:         func(_, _ string) { connectStart = time.Now() },
		ConnectDone:          func(_, _ string, _ error) { connectDone = time.Now() },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { gotFirstResponse = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	redirects := make([]string, 0, 4)
	probeClient := *client
	probeClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			result.TooManyRedirects = true
			return fmt.Errorf("too many redirects")
		}
		redirects = append(redirects, req.URL.String())
		for _, prev := range via {
			if prev.URL.String() == req.URL.String() {
				result.RedirectLoop = true
				return fmt.Errorf("redirect loop detected")
			}
		}
		return nil
	}

	resp, err := probeClient.Do(req)
	result.TotalDuration = time.Since(start)
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		result.DNSDuration = dnsDone.Sub(dnsStart)
	}
	if !connectStart.IsZero() && !connectDone.IsZero() {
		result.ConnectDuration = connectDone.Sub(connectStart)
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		result.TLSDuration = tlsDone.Sub(tlsStart)
	}
	if !gotFirstResponse.IsZero() {
		result.TTFBDuration = gotFirstResponse.Sub(start)
	}

	if err != nil {
		if ctx.Err() != nil {
			result.TimedOut = true
			result.ProbeExecError = true
		}
		result.Error = err.Error()
		result.RedirectEvidence = buildRedirectEvidence(rawURL, redirects, "", 0, result, "")
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.FinalURL = resp.Request.URL.String()
	result.RedirectChain = redirects
	result.Headers = FilterSafeHeaders(resp.Header)
	result.AnalysisHeaders = FilterAnalysisHeaders(resp.Header)
	result.RedirectEvidence = buildRedirectEvidence(rawURL, redirects, result.FinalURL, result.StatusCode, result, resp.Request.URL.Hostname())

	_, _ = io.CopyN(io.Discard, resp.Body, maxBodyRead)
	return result
}

func buildRedirectEvidence(initial string, chain []string, final string, status int, probe *HTTPProbeResult, domain string) RedirectEvidence {
	ev := RedirectEvidence{
		InitialURL:       initial,
		RedirectChain:    append([]string(nil), chain...),
		FinalURL:         final,
		FinalStatus:      status,
		LoopDetected:     probe != nil && probe.RedirectLoop,
		TooManyRedirects: probe != nil && probe.TooManyRedirects,
	}

	for _, hop := range chain {
		if host := redirectHost(hop); host != "" && !hostsRelated(domain, host) {
			ev.UnexpectedHosts = appendUnique(ev.UnexpectedHosts, host)
		}
	}

	previousScheme := schemeOf(initial)
	for _, hop := range chain {
		curScheme := schemeOf(hop)
		if previousScheme == "https" && curScheme == "http" {
			ev.DowngradeDetected = true
		}
		previousScheme = curScheme
	}

	if final != "" {
		if host := redirectHost(final); host != "" && !hostsRelated(domain, host) {
			ev.UnexpectedHosts = appendUnique(ev.UnexpectedHosts, host)
		}
		finalScheme := schemeOf(final)
		if previousScheme == "https" && finalScheme == "http" {
			ev.DowngradeDetected = true
		}
	}
	return ev
}

func redirectHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

func hostsRelated(domain, host string) bool {
	return relatedHost(domain, host)
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}

func schemeOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}

func registrableHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

func hostsEquivalent(a, b string) bool {
	a = strings.TrimPrefix(strings.ToLower(a), "www.")
	b = strings.TrimPrefix(strings.ToLower(b), "www.")
	return a == b
}

func ProbeTLS(ctx context.Context, address, serverName string, timeout time.Duration) *TLSProbeResult {
	result := &TLSProbeResult{}
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Error = err.Error()
		if ctx.Err() != nil {
			result.ProbeExecError = true
		}
		result.DiagnosticNote = "verified TLS handshake failed"
		diag := probeTLSInsecure(ctx, address, serverName, timeout)
		if diag.Connected {
			result.DiagnosticNote = "diagnostic insecure handshake succeeded; certificate verification failed"
			if diag.Issuer != "" {
				result.Issuer = diag.Issuer
			}
			if !diag.NotAfter.IsZero() {
				result.NotAfter = diag.NotAfter
			}
		}
		return result
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		result.Error = err.Error()
		if ctx.Err() != nil {
			result.ProbeExecError = true
		}
		result.DiagnosticNote = "verified TLS handshake failed"
		diag := probeTLSInsecure(ctx, address, serverName, timeout)
		if diag.Connected {
			result.DiagnosticNote = "diagnostic insecure handshake succeeded; certificate verification failed"
			if diag.Issuer != "" {
				result.Issuer = diag.Issuer
			}
			if !diag.NotAfter.IsZero() {
				result.NotAfter = diag.NotAfter
			}
		}
		return result
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	result.Connected = true
	result.NegotiatedVersion = tlsVersionName(state.Version)
	result.ALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) == 0 {
		result.ChainValid = false
		result.Error = "no peer certificates"
		return result
	}
	cert := state.PeerCertificates[0]
	result.NotAfter = cert.NotAfter
	result.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
	result.Expired = time.Now().After(cert.NotAfter)
	result.Issuer = cert.Issuer.CommonName
	result.Subject = cert.Subject.CommonName
	for _, name := range cert.DNSNames {
		result.SANs = append(result.SANs, name)
	}
	result.HostnameMatch = cert.VerifyHostname(serverName) == nil
	result.ChainValid = !result.Expired && result.HostnameMatch
	return result
}

func probeTLSInsecure(ctx context.Context, address, serverName string, timeout time.Duration) *TLSProbeResult {
	result := &TLSProbeResult{}
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return result
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return result
	}
	defer tlsConn.Close()
	result.Connected = true
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Issuer = cert.Issuer.CommonName
		result.NotAfter = cert.NotAfter
	}
	return result
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func CacheStatusFromHeaders(headers map[string]string) string {
	for _, key := range []string{"x-cache-status", "x-cache", "cf-cache-status", "x-verge-cache"} {
		if value, ok := headers[key]; ok {
			return strings.ToLower(value)
		}
	}
	if age, ok := headers["age"]; ok && age != "" && age != "0" {
		return "hit"
	}
	return "unknown"
}
