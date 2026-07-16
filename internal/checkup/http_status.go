package checkup

import "fmt"

// ClassifyHTTPStatus maps an HTTP status code to checkup status, severity, and summary.
// Policy:
//   - 0: probe error (caller handles transport errors separately)
//   - 200-399: pass (redirects are reachable)
//   - 401,403: warning — reachable but restricted
//   - 404: warning for general paths; failure when path is explicitly expected
//   - 408,429: warning
//   - 500-599: failure
func ClassifyHTTPStatus(status int, path string, healthPath bool) (Status, Severity, string) {
	if status == 0 {
		return StatusError, SeverityMedium, "No HTTP status code was returned."
	}
	switch {
	case status >= 200 && status < 400:
		return StatusPass, SeverityInfo, fmt.Sprintf("Responded with HTTP %d.", status)
	case status == 401 || status == 403:
		return StatusWarn, SeverityLow, fmt.Sprintf("Application responded with HTTP %d (access restricted).", status)
	case status == 404:
		if healthPath {
			return StatusFail, SeverityHigh, fmt.Sprintf("Health endpoint returned HTTP %d.", status)
		}
		return StatusWarn, SeverityMedium, fmt.Sprintf("Responded with HTTP %d.", status)
	case status == 408 || status == 429:
		return StatusWarn, SeverityMedium, fmt.Sprintf("Responded with HTTP %d.", status)
	case status >= 500 && status < 600:
		return StatusFail, SeverityHigh, fmt.Sprintf("Server error HTTP %d.", status)
	default:
		return StatusWarn, SeverityMedium, fmt.Sprintf("Responded with HTTP %d.", status)
	}
}

func IsHealthPath(path string) bool {
	path = NormalizePath(path)
	switch path {
	case "/health", "/healthz", "/health/", "/healthz/", "/ready", "/readyz", "/live", "/livez":
		return true
	default:
		return false
	}
}
