package checkup

import "sort"

var statusRank = map[Status]int{
	StatusFail:  0,
	StatusError: 1,
	StatusWarn:  2,
	StatusSkip:  3,
	StatusPass:  4,
}

var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if statusRank[a.Status] != statusRank[b.Status] {
			return statusRank[a.Status] < statusRank[b.Status]
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.ID < b.ID
	})
}
