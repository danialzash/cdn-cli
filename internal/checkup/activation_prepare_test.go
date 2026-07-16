package checkup

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vergecloud/cdn-cli/internal/client"
)

type activationSource struct {
	nsCalls    int32
	cnameCalls int32
}

func (s *activationSource) ResolveDomain(context.Context, string) (*client.DomainDetail, error) {
	return nil, errors.New("unused")
}
func (s *activationSource) LoadInspect(context.Context, string, map[string]bool) (*client.DomainInspect, error) {
	return nil, nil
}
func (s *activationSource) CheckNameservers(context.Context, string) (*client.NSCheckResult, error) {
	atomic.AddInt32(&s.nsCalls, 1)
	return &client.NSCheckResult{Expected: []string{"ns1.cdn.net"}, Published: []string{"ns1.cdn.net"}}, nil
}
func (s *activationSource) FetchCnameSetupStatus(context.Context, string) (*client.CnameSetupStatus, error) {
	atomic.AddInt32(&s.cnameCalls, 1)
	return &client.CnameSetupStatus{Status: "active", CnameTarget: "edge.cdn.net"}, nil
}
func (s *activationSource) GetLatestSmartCheck(context.Context, string) (*client.SmartCheck, error) {
	return nil, nil
}

func TestPartialDomainCallsCNAMEOnly(t *testing.T) {
	src := &activationSource{}
	runner, _ := NewRunner(src)
	state := &State{
		Domain:  DomainSummary{Name: "app.example.com", Type: "partial"},
		Options: DefaultOptions(),
	}
	resolver, err := NewPublicDNSResolver([]string{"127.0.0.1:1"}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	runner.prepareActivation(context.Background(), state, resolver, "app.example.com")
	if atomic.LoadInt32(&src.cnameCalls) != 1 {
		t.Fatalf("cname calls = %d", src.cnameCalls)
	}
	if atomic.LoadInt32(&src.nsCalls) != 0 {
		t.Fatalf("ns calls = %d", src.nsCalls)
	}
	if state.CnameCheck == nil {
		t.Fatal("expected CNAME check result after public lookup attempt")
	}
}

func TestFullDomainCallsNSOnly(t *testing.T) {
	src := &activationSource{}
	runner, _ := NewRunner(src)
	state := &State{
		Domain:  DomainSummary{Name: "example.com", Type: "full"},
		Options: DefaultOptions(),
	}
	runner.prepareActivation(context.Background(), state, nil, "example.com")
	if atomic.LoadInt32(&src.nsCalls) != 1 {
		t.Fatalf("ns calls = %d", src.nsCalls)
	}
	if atomic.LoadInt32(&src.cnameCalls) != 0 {
		t.Fatalf("cname calls = %d", src.cnameCalls)
	}
	if state.NSCheck == nil {
		t.Fatal("expected NS check result")
	}
}

func TestUnknownDomainTypeProbeError(t *testing.T) {
	src := &activationSource{}
	runner, _ := NewRunner(src)
	state := &State{
		Domain:  DomainSummary{Name: "example.com", Type: "legacy"},
		Options: DefaultOptions(),
	}
	runner.prepareActivation(context.Background(), state, nil, "example.com")
	if len(state.ProbeErrors) != 1 || state.ProbeErrors[0].Probe != "activation.domain-type" {
		t.Fatalf("probe errors = %+v", state.ProbeErrors)
	}
	if atomic.LoadInt32(&src.nsCalls) != 0 || atomic.LoadInt32(&src.cnameCalls) != 0 {
		t.Fatal("activation endpoints should not be called")
	}
	check := &ActivationCheck{}
	findings := check.Run(context.Background(), state)
	found := false
	for _, f := range findings {
		if f.ID == "activation.domain-type" && f.Status == StatusError {
			found = true
		}
	}
	if !found {
		t.Fatal("expected activation.domain-type error finding")
	}
	if ComputeExitCode(Summary{Errors: 1}, false, state.ProbeErrors, false) != ExitProbeError {
		t.Fatal("expected exit 3")
	}
}
