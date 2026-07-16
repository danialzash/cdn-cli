package checkup

const (
	ExitOK           = 0
	ExitError        = 1
	ExitChecksFailed = 2
	ExitProbeError   = 3
	ExitFixFailed    = 4
)

// ComputeExitCode determines the process exit status.
//
// Classification policy:
//   - ExitFixFailed (4): an approved fix failed or could not be verified
//   - ExitProbeError (3): required probe/API data could not be collected
//   - ExitChecksFailed (2): domain misconfiguration or unhealthy signal
//   - ExitOK (0): completed; warnings alone are OK unless strict
func ComputeExitCode(summary Summary, strict bool, probeErrors []ProbeError, fixFailed bool) int {
	if fixFailed {
		return ExitFixFailed
	}
	if len(probeErrors) > 0 || summary.Errors > 0 {
		return ExitProbeError
	}
	if summary.Failed > 0 {
		return ExitChecksFailed
	}
	if strict && summary.Warnings > 0 {
		return ExitChecksFailed
	}
	return ExitOK
}

func SummarizeFindings(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Status {
		case StatusPass:
			s.Passed++
		case StatusWarn:
			s.Warnings++
		case StatusFail:
			s.Failed++
		case StatusSkip:
			s.Skipped++
		case StatusError:
			s.Errors++
		}
	}
	return s
}
