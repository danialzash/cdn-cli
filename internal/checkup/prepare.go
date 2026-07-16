package checkup

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

func (r *Runner) prepareState(ctx context.Context, state *State) {
	enabled := state.Options.EnabledCategories()
	domain := state.Domain.Name
	path := state.Options.Path
	timeout := state.Options.ProbeTimeout

	if enabled[CategoryActivation] {
		domainType := strings.ToLower(state.Domain.Type)
		if domainType == "partial" || domainType == "cname" {
			if check, err := r.source.CheckCnameSetup(ctx, domain); err == nil {
				state.CnameCheck = check
			}
		} else if check, err := r.source.CheckNameservers(ctx, domain); err == nil {
			state.NSCheck = check
		}
	}

	if enabled[CategorySmartCheck] {
		if sc, err := r.source.GetLatestSmartCheck(ctx, domain); err == nil {
			state.SmartCheck = sc
		}
	}

	checker := dnsverify.NewCheckerWithResolvers(timeout, state.Options.Resolvers)

	needHTTP := enabled[CategoryHTTP] || enabled[CategoryCDN] || enabled[CategoryCache] || enabled[CategorySecurity] || enabled[CategoryDNS]
	if needHTTP {
		client := NewProbeHTTPClient(timeout)
		state.HTTPProbe = ProbeHTTP(ctx, client, fmt.Sprintf("http://%s%s", domain, path), "")
		state.HTTPSProbe = ProbeHTTP(ctx, client, fmt.Sprintf("https://%s%s", domain, path), "")
		if enabled[CategoryCache] && state.HTTPSProbe != nil && state.HTTPSProbe.Error == "" {
			state.SecondHTTPSProbe = ProbeHTTP(ctx, client, fmt.Sprintf("https://%s%s", domain, path), "")
		}
	}

	if enabled[CategoryDNS] {
		state.ApexResolution = hostResolves(ctx, checker.Resolver, domain)
		state.WWWResolution = hostResolves(ctx, checker.Resolver, "www."+domain)
		if state.Inspect != nil {
			state.DNSResults = r.verifyDNSRecords(ctx, checker, domain, state)
		}
	}

	if enabled[CategoryTLS] || enabled[CategorySecurity] {
		addr := net.JoinHostPort(domain, "443")
		state.TLSProbe = ProbeTLS(ctx, addr, domain, timeout)
	}

	if enabled[CategoryOrigin] && state.Options.Origin != "" {
		r.runOriginProbes(ctx, state)
	}
}

func hostResolves(ctx context.Context, resolver *net.Resolver, name string) bool {
	if resolver == nil {
		return false
	}
	_, err := resolver.LookupHost(ctx, name)
	return err == nil
}

func (r *Runner) verifyDNSRecords(ctx context.Context, checker *dnsverify.Checker, domain string, state *State) []dnsverify.Result {
	records := state.Inspect.DNS.Records
	jobs := make([]dnsverify.VerifyJob, len(records))
	for i, record := range records {
		jobs[i] = dnsverify.VerifyJob{
			RecordID:   record.ID,
			RecordType: record.Type,
			Name:       record.Name,
			Domain:     domain,
			Expected:   record.Value,
			Cloud:      record.Cloud,
		}
	}
	results := checker.VerifyAll(ctx, jobs, dnsverify.DefaultWorkers)
	for i := range results {
		record := records[i]
		fqdn := dnsverify.FQDN(record.Name, domain)
		if record.Cloud && IsMailRelatedHostname(fqdn) {
			results[i].MailCloudProxy = true
		}
		if record.Cloud {
			results[i].Cloud = true
			results[i].CloudWeak = !cloudProxyStrongEvidence(state, results[i])
		}
	}
	return results
}

func cloudProxyStrongEvidence(state *State, result dnsverify.Result) bool {
	if state.HTTPSProbe != nil && IsVergeEdgeHeader(state.HTTPSProbe.Headers) {
		return true
	}
	expected := strings.TrimSuffix(strings.ToLower(state.Domain.CnameTarget), ".")
	if expected != "" && strings.Contains(strings.ToLower(result.Actual), expected) {
		return true
	}
	return result.Status == "ok" && result.Actual != ""
}

func (r *Runner) runOriginProbes(ctx context.Context, state *State) {
	opts := state.Options
	scheme := opts.OriginScheme
	if scheme == "" || scheme == "auto" {
		scheme = "http"
		if state.Inspect != nil && state.Inspect.SSL.Enabled {
			scheme = "https"
		}
	}
	port := opts.OriginPort
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	host := opts.Origin
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		if h, p, err := net.SplitHostPort(host); err == nil {
			host = h
			if opts.OriginPort == 0 {
				fmt.Sscanf(p, "%d", &port)
			}
		}
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	path := opts.Path
	domain := state.Domain.Name
	url := fmt.Sprintf("%s://%s%s", scheme, address, path)

	client := NewProbeHTTPClient(opts.ProbeTimeout)
	state.OriginProbe = mapOriginProbe(ProbeHTTP(ctx, client, url, domain), scheme, address, domain)
	state.OriginHostProbe = mapOriginProbe(ProbeHTTP(ctx, client, url, ""), scheme, address, "")
}

func mapOriginProbe(result *HTTPProbeResult, scheme, address, hostHeader string) *OriginProbeResult {
	if result == nil {
		return nil
	}
	return &OriginProbeResult{
		Scheme:        scheme,
		Address:       address,
		StatusCode:    result.StatusCode,
		Headers:       result.Headers,
		HostHeader:    hostHeader,
		TotalDuration: result.TotalDuration,
		Error:         result.Error,
	}
}
