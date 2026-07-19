package checkup

import "strings"

func fixRelatedFindingIDs(plan FixPlan) []string {
	switch {
	case plan.ID == "cache.developer-mode":
		return []string{"cache.developer-mode"}
	case plan.ID == "ssl.https-redirect":
		return []string{"http.redirect-to-https"}
	case strings.HasPrefix(plan.ID, "dns.mail-cloud-proxy."):
		recordID := strings.TrimPrefix(plan.ID, "dns.mail-cloud-proxy.")
		return []string{
			FindingID("dns.mail-cloud-proxy", recordID),
			FindingID("dns.configured-records", recordID),
		}
	default:
		return []string{plan.ID}
	}
}

func FindingStillUnhealthy(report Report, plan FixPlan) bool {
	ids := fixRelatedFindingIDs(plan)
	for _, finding := range report.Findings {
		for _, id := range ids {
			if finding.ID != id && !strings.HasPrefix(finding.ID, id+".") {
				continue
			}
			switch finding.Status {
			case StatusFail, StatusWarn, StatusError:
				return true
			}
		}
	}
	return false
}
