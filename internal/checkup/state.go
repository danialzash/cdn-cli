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
	LoadInspect(ctx context.Context, domain string, sections map[string]bool) (*client.DomainInspect, error)
	CheckNameservers(ctx context.Context, domain string) (*client.NSCheckResult, error)
	FetchCnameSetupStatus(ctx context.Context, domain string) (*client.CnameSetupStatus, error)
	GetLatestSmartCheck(ctx context.Context, domain string) (*client.SmartCheck, error)
}

// FixApplier applies safe automatic fixes.
type FixApplier interface {
	ApplyFix(ctx context.Context, domain string, plan FixPlan) error
}

// FixVerifier confirms a fix reached the desired state.
type FixVerifier interface {
	VerifyFix(ctx context.Context, domain string, plan FixPlan) (FixVerification, string, error)
}

type State struct {
	Options           Options
	Domain            DomainSummary
	VisibleCategories map[Category]bool
	Requirements      Requirements

	Inspect    *client.DomainInspect
	NSCheck    *client.NSCheckResult
	CnameCheck *CnameCheckResult
	SmartCheck *client.SmartCheck

	DNSResults []dnsverify.Result

	HTTPProbe        *HTTPProbeResult
	HTTPSProbe       *HTTPProbeResult
	SecondHTTPSProbe *HTTPProbeResult
	TLSProbe         *TLSProbeResult
	OriginProbe      *OriginProbeResult
	OriginHostProbe  *OriginProbeResult

	ProbeErrors []ProbeError

	HostEdgeProbes       map[string]*HTTPProbeResult
	HostCNAMEChains      map[string][]string
	OriginSchemeAttempts []OriginSchemeAttempt

	ApexLookup  DNSLookupResult
	WWWLookup   DNSLookupResult
	WWWRequired bool

	mu sync.RWMutex
}

type OriginSchemeAttempt struct {
	Scheme string `json:"scheme"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
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
	AnalysisHeaders  map[string]string
	RedirectEvidence RedirectEvidence
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
	ProbeExecError   bool
}

type RedirectEvidence struct {
	InitialURL        string
	RedirectChain     []string
	FinalURL          string
	FinalStatus       int
	UnexpectedHosts   []string
	DowngradeDetected bool
	LoopDetected      bool
	TooManyRedirects  bool
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
	ProbeExecError    bool
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
