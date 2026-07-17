package checkup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

func (r *Runner) prepareState(ctx context.Context, state *State, req Requirements) {
	domain := state.Domain.Name
	path := state.Options.Path
	timeout := state.Options.ProbeTimeoutDuration()
	resolver, err := NewPublicDNSResolver(state.Options.Resolvers, timeout)
	if err != nil {
		state.AddProbeError("dns.resolver", err.Error())
		resolver = &PublicDNSResolver{timeout: timeout}
	}

	state.HostEdgeProbes = map[string]*HTTPProbeResult{}
	state.HostCNAMEChains = map[string][]string{}

	if req.Activation {
		r.prepareActivation(ctx, state, resolver, domain)
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
			recordHTTPProbeError(state, "cache.second-https", state.SecondHTTPSProbe)
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

func (r *Runner) prepareActivation(ctx context.Context, state *State, resolver *PublicDNSResolver, domain string) {
	domainType := strings.ToLower(strings.TrimSpace(state.Domain.Type))
	switch domainType {
	case "partial":
		r.prepareCnameActivation(ctx, state, resolver, domain)
	case "full":
		r.prepareNSActivation(ctx, state, domain)
	default:
		state.AddProbeError("activation.domain-type", fmt.Sprintf("unsupported domain type %q", state.Domain.Type))
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
	classification := DNSLookupFound
	resolveErrStr := ""
	if resolveErr != nil {
		classification = ClassifyDNSError(resolveErr)
		resolveErrStr = resolveErr.Error()
		if classification.IsProbeError() {
			state.AddProbeError("activation.cname.lookup", resolveErrStr)
		}
	}
	state.CnameCheck = BuildCnameCheckResult(api.Status, expected, resolved, classification, resolveErrStr)
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
	if state.InspectRequestedSections["smartcheck"] {
		if state.Inspect != nil {
			if HasInspectSectionError(state.Inspect, "smart_check") {
				state.SmartCheckLoadStatus = SmartCheckLoadFailed
				for _, errItem := range InspectSectionErrors(state.Inspect, "smart_check") {
					state.SmartCheckLoadError = errItem.Error
					state.AddProbeError("smartcheck", errItem.Error)
				}
				return
			}
			if state.Inspect.SmartCheck != nil {
				state.SmartCheck = state.Inspect.SmartCheck
				state.SmartCheckLoadStatus = SmartCheckLoaded
				return
			}
			state.SmartCheckLoadStatus = SmartCheckNotFound
		}
		return
	}
	sc, err := r.source.GetLatestSmartCheck(ctx, domain)
	if err != nil {
		state.SmartCheckLoadStatus = SmartCheckLoadFailed
		state.SmartCheckLoadError = err.Error()
		state.AddProbeError("smartcheck", err.Error())
		return
	}
	if sc == nil {
		state.SmartCheckLoadStatus = SmartCheckNotFound
		return
	}
	state.SmartCheck = sc
	state.SmartCheckLoadStatus = SmartCheckLoaded
}

func (r *Runner) prepareDNS(ctx context.Context, state *State, req Requirements, resolver *PublicDNSResolver, domain string) {
	if req.DNSApex {
		state.ApexLookup = resolver.Lookup(ctx, domain)
	}
	if req.DNSWWW {
		state.WWWRequired = wwwRequired(state)
		if state.WWWRequired {
			state.WWWLookup = resolver.Lookup(ctx, "www."+domain)
		}
	}
	if req.DNSRecords && state.Inspect != nil && !HasInspectSectionError(state.Inspect, "dns") {
		state.DNSResults = r.verifyDNSRecords(ctx, state, domain)
	}
}

func wwwRequired(state *State) bool {
	if state.Inspect == nil || HasInspectSectionError(state.Inspect, "dns") {
		return false
	}
	for _, record := range state.Inspect.DNS.Records {
		name := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		domain := strings.ToLower(state.Domain.Name)
		if name == "www" || name == "www."+domain {
			return true
		}
	}
	if state.SmartCheck != nil {
		for _, item := range state.SmartCheck.Items {
			id := strings.ToLower(item.ID)
			switch {
			case strings.Contains(id, "www_missing"), strings.Contains(id, "www_resolution"), strings.Contains(id, "canonical_www"):
				return true
			}
		}
	}
	for _, rule := range state.Inspect.PageRules.Rules {
		if strings.Contains(strings.ToLower(rule.URL), "www."+strings.ToLower(state.Domain.Name)) {
			return true
		}
	}
	return false
}

func (r *Runner) verifyDNSRecords(ctx context.Context, state *State, domain string) []dnsverify.Result {
	timeout := state.Options.ProbeTimeoutDuration()
	checker := dnsverify.NewCheckerWithResolvers(timeout, state.Options.Resolvers)
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

	resolver, _ := NewPublicDNSResolver(state.Options.Resolvers, timeout)
	httpClient := NewProbeHTTPClient(timeout)
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxProbeWorkers)

	for i := range results {
		record := records[i]
		fqdn := dnsverify.FQDN(record.Name, domain)
		if record.Cloud && IsMailRelatedHostname(fqdn) {
			results[i].MailCloudProxy = true
		}
		if record.Cloud {
			results[i].Cloud = true
			if resolver != nil {
				if chain, err := lookupCNAMEChain(ctx, resolver, fqdn); err == nil {
					state.mu.Lock()
					state.HostCNAMEChains[fqdn] = chain
					state.mu.Unlock()
				}
			}
			if shouldProbeCloudHostname(record.Type, record.Name, domain) && fqdn != state.Domain.Name {
				wg.Add(1)
				sem <- struct{}{}
				go func(host string) {
					defer wg.Done()
					defer func() { <-sem }()
					probe := ProbeHTTP(ctx, httpClient, "https://"+host+"/", "")
					state.mu.Lock()
					state.HostEdgeProbes[host] = probe
					state.mu.Unlock()
				}(fqdn)
			}
		}
	}
	wg.Wait()

	for i := range results {
		record := records[i]
		fqdn := dnsverify.FQDN(record.Name, domain)
		if record.Cloud {
			strong, source := cloudProxyStrongEvidenceForRecord(state, results[i], fqdn)
			results[i].CloudWeak = !strong
			if source != "none" {
				if results[i].Detail != "" {
					results[i].Detail += " "
				}
				results[i].Detail += "cloud_evidence=" + source
			}
		}
	}
	return results
}

func lookupCNAMEChain(ctx context.Context, resolver *PublicDNSResolver, name string) ([]string, error) {
	var chain []string
	current := name
	for i := 0; i < 8; i++ {
		target, err := resolver.LookupCNAME(ctx, current)
		if err != nil {
			return chain, err
		}
		if target == "" || strings.EqualFold(normalizeCnameHost(target), normalizeCnameHost(current)) {
			break
		}
		chain = append(chain, target)
		current = target
	}
	return chain, nil
}

func (r *Runner) runOriginProbes(ctx context.Context, state *State) {
	opts := state.Options
	customerDomain := state.Domain.Name
	path := opts.Path

	selection := r.selectOrigin(ctx, state, customerDomain, path)
	state.OriginSelection = selection
	state.OriginSchemeAttempts = selection.Attempts
	if selection.Scheme == "" || selection.Address == "" {
		return
	}
	scheme := selection.Scheme
	address := selection.Address
	tlsSNI := tlsSNIForScheme(scheme, customerDomain)
	client := NewOriginProbeHTTPClient(opts.ProbeTimeoutDuration(), address, tlsSNI)
	requestURL := fmt.Sprintf("%s://%s%s", scheme, address, path)
	state.OriginProbe = mapOriginProbe(ProbeHTTP(ctx, client, requestURL, customerDomain), scheme, address, customerDomain)

	defaultHost := defaultOriginHostHeader(address, scheme)
	state.OriginHostProbe = mapOriginProbe(ProbeHTTP(ctx, client, requestURL, defaultHost), scheme, address, defaultHost)
}

func mapOriginProbe(result *HTTPProbeResult, scheme, address, hostHeader string) *OriginProbeResult {
	if result == nil {
		return nil
	}
	return &OriginProbeResult{
		Scheme:         scheme,
		Address:        address,
		StatusCode:     result.StatusCode,
		Headers:        result.Headers,
		HostHeader:     hostHeader,
		TotalDuration:  result.TotalDuration,
		Error:          result.Error,
		ProbeExecError: result.ProbeExecError,
		TimedOut:       result.TimedOut,
	}
}
