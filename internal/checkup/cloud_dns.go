package checkup

import (
	"strings"

	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

func shouldProbeCloudHostname(recordType, name, domain string) bool {
	recordType = strings.ToLower(recordType)
	switch recordType {
	case "a", "aaaa", "cname", "aname":
	default:
		return false
	}
	fqdn := dnsverify.FQDN(name, domain)
	return !IsMailRelatedHostname(fqdn)
}

func cloudProxyStrongEvidenceForRecord(state *State, result dnsverify.Result, hostname string) (bool, string) {
	if strong, source := hostnameEdgeProbeStrong(state, hostname); strong {
		return true, source
	}
	expected := strings.TrimSuffix(strings.ToLower(state.Domain.CnameTarget), ".")
	if expected != "" && cnameTargetMatches(result.Actual, expected) {
		return true, "cname-target"
	}
	if state.Domain.CustomCname != "" {
		custom := strings.TrimSuffix(strings.ToLower(state.Domain.CustomCname), ".")
		if custom != "" && cnameTargetMatches(result.Actual, custom) {
			return true, "custom-cname-target"
		}
	}
	if chain := state.HostCNAMEChains[hostname]; len(chain) > 0 {
		if expected != "" {
			for _, hop := range chain {
				if cnameTargetMatches(hop, expected) {
					return true, "cname-target"
				}
			}
		}
	}
	return false, "none"
}

func hostnameEdgeProbeStrong(state *State, hostname string) (bool, string) {
	var probe *HTTPProbeResult
	if strings.EqualFold(hostname, state.Domain.Name) {
		probe = state.HTTPSProbe
	} else {
		probe = state.HostEdgeProbes[hostname]
	}
	if probe == nil || probe.Error != "" {
		return false, "none"
	}
	if len(probe.RedirectEvidence.UnexpectedHosts) > 0 {
		return false, "none"
	}
	finalHost := redirectHost(probe.FinalURL)
	if finalHost != "" && !strings.EqualFold(finalHost, hostname) {
		return false, "none"
	}
	if IsVergeEdgeStrong(probe.AnalysisHeaders) {
		return true, "hostname-edge-probe"
	}
	return false, "none"
}
