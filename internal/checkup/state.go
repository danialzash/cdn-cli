package checkup

import (
	"context"
	"sync"
	"time"

	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

// DataSource loads domain and configuration data for checkup.
type DataSource interface {
	ResolveDomain(ctx context.Context, idOrName string) (*client.DomainDetail, error)
	LoadInspect(ctx context.Context, domain string, categories map[Category]bool) (*client.DomainInspect, error)
	CheckNameservers(ctx context.Context, domain string) (*client.NSCheckResult, error)
	CheckCnameSetup(ctx context.Context, domain string) (*client.CnameCheckResult, error)
	GetLatestSmartCheck(ctx context.Context, domain string) (*client.SmartCheck, error)
}

// FixApplier applies safe automatic fixes.
type FixApplier interface {
	ApplyFix(ctx context.Context, domain string, plan FixPlan) error
}

type State struct {
	Options Options
	Domain  DomainSummary

	Inspect    *client.DomainInspect
	NSCheck    *client.NSCheckResult
	CnameCheck *client.CnameCheckResult
	SmartCheck *client.SmartCheck

	DNSResults []dnsverify.Result

	HTTPProbe        *HTTPProbeResult
	HTTPSProbe       *HTTPProbeResult
	SecondHTTPSProbe *HTTPProbeResult
	TLSProbe         *TLSProbeResult
	OriginProbe      *OriginProbeResult
	OriginHostProbe  *OriginProbeResult

	ProbeErrors []ProbeError

	ApexResolution bool
	WWWResolution  bool

	mu sync.RWMutex
}

func (s *State) AddProbeError(probe, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProbeErrors = append(s.ProbeErrors, ProbeError{Probe: probe, Message: message})
}

type HTTPProbeResult struct {
	URL              string
	FinalURL         string
	StatusCode       int
	RedirectChain    []string
	Headers          map[string]string
	TimedOut         bool
	RedirectLoop     bool
	TooManyRedirects bool
	DNSDuration      time.Duration
	ConnectDuration  time.Duration
	TLSDuration      time.Duration
	TTFBDuration     time.Duration
	TotalDuration    time.Duration
	BodySampleHash   string
	Error            string
}

type TLSProbeResult struct {
	Connected         bool
	HostnameMatch     bool
	ChainValid        bool
	Expired           bool
	DaysUntilExpiry   int
	NotAfter          time.Time
	Issuer            string
	Subject           string
	SANs              []string
	NegotiatedVersion string
	ALPN              string
	Error             string
	DiagnosticNote    string
}

type OriginProbeResult struct {
	Scheme            string
	Address           string
	StatusCode        int
	Headers           map[string]string
	HostHeader        string
	TotalDuration     time.Duration
	Error             string
	DefaultHostStatus int
}

type Check interface {
	ID() string
	Category() Category
	Dependencies() []string
	Run(ctx context.Context, state *State) []Finding
}
