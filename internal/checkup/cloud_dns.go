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
	if probe := state.HostEdgeProbes[hostname]; probe != nil && probe.Error == "" {
		if IsVergeEdgeStrong(probe.AnalysisHeaders) {
			return true, "hostname-edge-probe"
		}
	}
	expected := strings.TrimSuffix(strings.ToLower(state.Domain.CnameTarget), ".")
	if expected != "" && cnameChainMatchesTarget(result.Actual, expected) {
		return true, "cname-target"
	}
	if state.Domain.CustomCname != "" {
		custom := strings.TrimSuffix(strings.ToLower(state.Domain.CustomCname), ".")
		if custom != "" && cnameChainMatchesTarget(result.Actual, custom) {
			return true, "custom-cname-target"
		}
	}
	if chain := state.HostCNAMEChains[hostname]; len(chain) > 0 {
		if expected != "" {
			for _, hop := range chain {
				if cnameChainMatchesTarget(hop, expected) {
					return true, "cname-target"
				}
			}
		}
	}
	return false, "none"
}

func cnameChainMatchesTarget(actual, expected string) bool {
	actual = strings.TrimSuffix(strings.ToLower(actual), ".")
	expected = strings.TrimSuffix(strings.ToLower(expected), ".")
	if actual == "" || expected == "" {
		return false
	}
	return strings.Contains(actual, expected)
}
