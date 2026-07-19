package checkup

import "strings"

// EdgeEvidence captures whether a response appears to be served through VergeCloud.
type EdgeEvidence struct {
	Detected   bool
	Confidence string // strong, medium, weak, none
	Signals    []string
}

func DetectEdgeEvidence(headers map[string]string) EdgeEvidence {
	if len(headers) == 0 {
		return EdgeEvidence{Confidence: "none"}
	}
	var strong, weak []string
	for key, value := range headers {
		lowerKey := strings.ToLower(key)
		lowerVal := strings.ToLower(strings.TrimSpace(value))
		switch lowerKey {
		case "x-poweredby", "x-powered-by":
			if strings.Contains(lowerVal, "verge") {
				strong = append(strong, lowerKey+": VergeCloud")
			}
		case "x-verge-request-id":
			if lowerVal != "" {
				strong = append(strong, "x-verge-request-id")
			}
		case "server":
			if strings.Contains(lowerVal, "verge") {
				strong = append(strong, "server: VergeCloud")
			}
		case "x-request-id":
			if lowerVal != "" {
				weak = append(weak, "x-request-id")
			}
		case "via", "age":
			if lowerVal != "" {
				weak = append(weak, lowerKey)
			}
		case "x-cache", "x-cache-status":
			if lowerVal != "" {
				weak = append(weak, lowerKey)
			}
		}
	}
	ev := EdgeEvidence{Signals: append(append([]string{}, strong...), weak...)}
	switch {
	case len(strong) > 0:
		ev.Detected = true
		ev.Confidence = "strong"
	case len(weak) > 0:
		ev.Confidence = "weak"
	default:
		ev.Confidence = "none"
	}
	return ev
}

// IsVergeEdgeStrong returns true only when strong VergeCloud-specific evidence exists.
func IsVergeEdgeStrong(headers map[string]string) bool {
	return DetectEdgeEvidence(headers).Confidence == "strong"
}
