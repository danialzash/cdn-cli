package checkup

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
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
	"server":                      {},
	"date":                        {},
	"location":                    {},
	"content-type":                {},
	"content-length":              {},
	"cache-control":               {},
	"age":                         {},
	"vary":                        {},
	"etag":                        {},
	"last-modified":               {},
	"content-encoding":            {},
	"strict-transport-security":   {},
	"x-cache":                     {},
	"x-cache-status":              {},
	"x-poweredby":                 {},
	"x-powered-by":                {},
	"x-request-id":                {},
	"x-verge-request-id":          {},
	"via":                         {},
	"alt-svc":                     {},
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

func IsVergeEdgeHeader(headers map[string]string) bool {
	for key, value := range headers {
		switch key {
		case "x-poweredby", "x-powered-by":
			if strings.Contains(strings.ToLower(value), "verge") {
				return true
			}
		case "server":
			if strings.Contains(strings.ToLower(value), "verge") {
				return true
			}
		case "x-request-id", "x-verge-request-id":
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
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

func ProbeHTTP(ctx context.Context, client *http.Client, url string, hostHeader string) *HTTPProbeResult {
	result := &HTTPProbeResult{URL: url}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", version.UserAgent+"-checkup")
	if hostHeader != "" {
		req.Host = hostHeader
	}

	var (
		dnsStart, dnsDone       time.Time
		connectStart, connectDone time.Time
		tlsStart, tlsDone       time.Time
		gotFirstResponse        time.Time
		start                   = time.Now()
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart: func(_, _ string) { connectStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) { connectDone = time.Now() },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { gotFirstResponse = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	redirects := make([]string, 0, 4)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
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

	resp, err := client.Do(req)
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
			result.Error = ctx.Err().Error()
		} else if strings.Contains(err.Error(), "redirect") {
			result.Error = err.Error()
		} else {
			result.Error = err.Error()
		}
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.FinalURL = resp.Request.URL.String()
	result.RedirectChain = redirects
	result.Headers = FilterSafeHeaders(resp.Header)

	_, _ = io.CopyN(io.Discard, resp.Body, maxBodyRead)
	return result
}

func ProbeTLS(ctx context.Context, address, serverName string, timeout time.Duration) *TLSProbeResult {
	result := &TLSProbeResult{}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
	})
	if err != nil {
		result.Error = err.Error()
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
	defer conn.Close()

	state := conn.ConnectionState()
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
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result
	}
	defer conn.Close()
	result.Connected = true
	state := conn.ConnectionState()
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
