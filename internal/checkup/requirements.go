package checkup

// Requirements describes data that must be collected before running visible checks.
type Requirements struct {
	InspectSections map[string]bool
	PublicHTTP      bool
	PublicHTTPS     bool
	SecondHTTPS     bool
	TLS             bool
	DNSApex         bool
	DNSWWW          bool
	DNSRecords      bool
	SmartCheck      bool
	Activation      bool
	Origin          bool
}

func (r Requirements) Merge(other Requirements) Requirements {
	out := r
	if out.InspectSections == nil {
		out.InspectSections = map[string]bool{}
	}
	for k, v := range other.InspectSections {
		if v {
			out.InspectSections[k] = true
		}
	}
	out.PublicHTTP = out.PublicHTTP || other.PublicHTTP
	out.PublicHTTPS = out.PublicHTTPS || other.PublicHTTPS
	out.SecondHTTPS = out.SecondHTTPS || other.SecondHTTPS
	out.TLS = out.TLS || other.TLS
	out.DNSApex = out.DNSApex || other.DNSApex
	out.DNSWWW = out.DNSWWW || other.DNSWWW
	out.DNSRecords = out.DNSRecords || other.DNSRecords
	out.SmartCheck = out.SmartCheck || other.SmartCheck
	out.Activation = out.Activation || other.Activation
	out.Origin = out.Origin || other.Origin
	return out
}

// ExecutionPlan separates user-visible checks from internal data prerequisites.
type ExecutionPlan struct {
	VisibleChecks     []Check
	VisibleCategories map[Category]bool
	Requirements      Requirements
}

func categoryRequirements(cat Category) Requirements {
	switch cat {
	case CategoryActivation:
		return Requirements{
			InspectSections: map[string]bool{"dns": true},
			Activation:      true,
		}
	case CategoryDNS:
		return Requirements{
			InspectSections: map[string]bool{"dns": true},
			PublicHTTPS:     true,
			DNSApex:         true,
			DNSWWW:          true,
			DNSRecords:      true,
		}
	case CategoryHTTP:
		return Requirements{
			InspectSections: map[string]bool{"http": true, "tls": true},
			PublicHTTP:      true,
			PublicHTTPS:     true,
			TLS:             true,
		}
	case CategoryTLS:
		return Requirements{
			InspectSections: map[string]bool{"tls": true},
			PublicHTTPS:     true,
			TLS:             true,
		}
	case CategoryCDN:
		return Requirements{PublicHTTPS: true}
	case CategoryCache:
		return Requirements{
			InspectSections: map[string]bool{"cache": true},
			PublicHTTPS:     true,
			SecondHTTPS:     true,
		}
	case CategorySecurity:
		return Requirements{
			InspectSections: map[string]bool{"security": true, "tls": true},
			PublicHTTPS:     true,
			TLS:             true,
		}
	case CategoryConfiguration:
		return Requirements{InspectSections: map[string]bool{"configuration": true}}
	case CategorySmartCheck:
		return Requirements{SmartCheck: true}
	case CategoryOrigin:
		return Requirements{
			PublicHTTP:  true,
			PublicHTTPS: true,
			Origin:      true,
		}
	default:
		return Requirements{}
	}
}

func RequirementsForCategories(enabled map[Category]bool) Requirements {
	var req Requirements
	for cat, on := range enabled {
		if !on {
			continue
		}
		req = req.Merge(categoryRequirements(cat))
	}
	return req
}

func inspectSectionsFromRequirements(req Requirements) map[string]bool {
	if req.InspectSections["configuration"] {
		return map[string]bool{"configuration": true}
	}
	sections := map[string]bool{}
	for k, v := range req.InspectSections {
		if v {
			sections[k] = true
		}
	}
	if req.DNSRecords || req.DNSApex || req.DNSWWW || req.Activation {
		sections["dns"] = true
	}
	if req.SmartCheck {
		sections["smartcheck"] = true
	}
	if req.PublicHTTP {
		sections["http"] = true
	}
	if req.PublicHTTPS || req.TLS {
		sections["tls"] = true
	}
	if req.SecondHTTPS {
		sections["cache"] = true
	}
	return sections
}
