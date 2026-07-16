package checkup

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

func (r *Runner) prepareState(ctx context.Context, state *State, req Requirements) {
	domain := state.Domain.Name
	path := state.Options.Path
	timeout := state.Options.ProbeTimeout
	resolver := NewPublicDNSResolver(state.Options.Resolvers, timeout)

	if req.ActivationCNAME {
		r.prepareCnameActivation(ctx, state, resolver, domain)
	}
	if req.ActivationNS {
		r.prepareNSActivation(ctx, state, domain)
	}

	if req.SmartCheck {
		r.prepareSmartCheck(ctx, state, domain)
	}

	if req.PublicHTTP || req.PublicHTTPS || req.SecondHTTPS {
		client := NewProbeHTTPClient(timeout)
		if req.PublicHTTP {
			state.HTTPProbe = ProbeHTTP(ctx, client, fmt.Sprintf("http://%s%s", domain, path), "")
			recordHTTPProbeError(state, "http", state.HTTPProbe)
		}
		if req.PublicHTTPS || req.SecondHTTPS {
			state.HTTPSProbe = ProbeHTTP(ctx, client, fmt.Sprintf("https://%s%s", domain, path), "")
			recordHTTPProbeError(state, "https", state.HTTPSProbe)
		}
		if req.SecondHTTPS && state.HTTPSProbe != nil && state.HTTPSProbe.Error == "" {
			state.SecondHTTPSProbe = ProbeHTTP(ctx, client, fmt.Sprintf("https://%s%s", domain, path), "")
		}
	}

	if req.DNSApex || req.DNSWWW || req.DNSRecords {
		r.prepareDNS(ctx, state, req, resolver, domain)
	}

	if req.TLS {
		addr := net.JoinHostPort(domain, "443")
		state.TLSProbe = ProbeTLS(ctx, addr, domain, timeout)
		if state.TLSProbe != nil && state.TLSProbe.Error != "" && state.TLSProbe.ProbeExecError {
			state.AddProbeError("tls", state.TLSProbe.Error)
		}
	}

	if req.Origin && state.Options.Origin != "" {
		r.runOriginProbes(ctx, state)
	}
}

func recordHTTPProbeError(state *State, name string, probe *HTTPProbeResult) {
	if probe == nil {
		state.AddProbeError(name, "probe did not run")
		return
	}
	if probe.Error != "" && probe.ProbeExecError {
		state.AddProbeError(name, probe.Error)
	}
}

func (r *Runner) prepareCnameActivation(ctx context.Context, state *State, resolver *PublicDNSResolver, domain string) {
	api, err := r.source.FetchCnameSetupStatus(ctx, domain)
	if err != nil {
		state.AddProbeError("activation.cname", err.Error())
		return
	}
	expected := api.CnameTarget
	if api.CustomCname != "" {
		expected = api.CustomCname
	}
	resolved, resolveErr := resolver.LookupCNAME(ctx, domain)
	resolveErrStr := ""
	if resolveErr != nil {
		resolveErrStr = resolveErr.Error()
		state.AddProbeError("activation.cname.lookup", resolveErrStr)
	}
	state.CnameCheck = BuildCnameCheckResult(api.Status, expected, resolved, resolveErrStr)
}

func (r *Runner) prepareNSActivation(ctx context.Context, state *State, domain string) {
	check, err := r.source.CheckNameservers(ctx, domain)
	if err != nil {
		state.AddProbeError("activation.nameservers", err.Error())
		return
	}
	state.NSCheck = check
}

func (r *Runner) prepareSmartCheck(ctx context.Context, state *State, domain string) {
	if state.Inspect != nil && state.Inspect.SmartCheck != nil {
		state.SmartCheck = state.Inspect.SmartCheck
		return
	}
	sc, err := r.source.GetLatestSmartCheck(ctx, domain)
	if err != nil {
		state.AddProbeError("smartcheck", err.Error())
		return
	}
	state.SmartCheck = sc
}

func (r *Runner) prepareDNS(ctx context.Context, state *State, req Requirements, resolver *PublicDNSResolver, domain string) {
	checker := dnsverify.NewCheckerWithResolvers(state.Options.ProbeTimeout, state.Options.Resolvers)
	if req.DNSApex {
		state.ApexResolution = resolver.HostResolves(ctx, domain)
		if !state.ApexResolution {
			// Resolution failure is a domain finding, not a probe execution error.
		}
	}
	if req.DNSWWW {
		state.WWWRequired = wwwRequired(state)
		if state.WWWRequired {
			state.WWWResolution = resolver.HostResolves(ctx, "www."+domain)
		}
	}
	if req.DNSRecords && state.Inspect != nil {
		state.DNSResults = r.verifyDNSRecords(ctx, checker, domain, state)
	}
}

func wwwRequired(state *State) bool {
	if state.Inspect == nil {
		return false
	}
	for _, record := range state.Inspect.DNS.Records {
		name := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		if name == "www" || name == "www."+strings.ToLower(state.Domain.Name) {
			return true
		}
	}
	if state.SmartCheck != nil {
		for _, item := range state.SmartCheck.Items {
			if strings.Contains(strings.ToLower(item.ID+" "+item.Details), "www") {
				return true
			}
		}
	}
	if state.Inspect.SSL.HTTPSRedirect {
		return true
	}
	return false
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
	if state.HTTPSProbe != nil && IsVergeEdgeStrong(state.HTTPSProbe.AnalysisHeaders) {
		return true
	}
	expected := strings.TrimSuffix(strings.ToLower(state.Domain.CnameTarget), ".")
	if expected != "" && strings.Contains(strings.ToLower(result.Actual), expected) {
		return true
	}
	if state.Domain.CustomCname != "" {
		custom := strings.TrimSuffix(strings.ToLower(state.Domain.CustomCname), ".")
		if custom != "" && strings.Contains(strings.ToLower(result.Actual), custom) {
			return true
		}
	}
	return false
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
	dialAddress := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	path := opts.Path
	customerDomain := state.Domain.Name
	requestURL := fmt.Sprintf("%s://%s%s", scheme, dialAddress, path)

	tlsServerName := customerDomain
	client := NewOriginProbeHTTPClient(opts.ProbeTimeout, dialAddress, tlsServerName)
	state.OriginProbe = mapOriginProbe(ProbeHTTP(ctx, client, requestURL, customerDomain), scheme, dialAddress, customerDomain)

	// Compare Host header only; TLS SNI stays on the customer domain.
	defaultHost := host
	if net.ParseIP(host) != nil {
		defaultHost = dialAddress
	}
	state.OriginHostProbe = mapOriginProbe(ProbeHTTP(ctx, client, requestURL, defaultHost), scheme, dialAddress, defaultHost)
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
