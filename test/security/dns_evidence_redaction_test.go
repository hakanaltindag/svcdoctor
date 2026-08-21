// Package security holds cross-package security tests, per the test data
// convention in docs/ARCHITECTURE.md section 17.
//
// This file answers one question that neither the probe nor the redactor can
// answer alone: does the evidence a real probe produces survive structural
// redaction with no identity left behind?
//
// It is a contract test between two packages that do not, and must not, import
// each other. Redaction may not import a probe, and a probe has no reason to
// import redaction, so the only place their agreement can be checked is here. If
// a future probe records identity in a shape redaction cannot recognize, this is
// where it should fail.
package security

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// Values chosen so that a leak is unmistakable in a diff and cannot be confused
// with anything the model produces on its own.
const (
	canaryHost    = "primary-canary.prod.internal"
	canaryIPv4    = "10.11.12.13"
	canaryIPv6    = "2001:db8::c0ca"
	canaryVantage = "workstation-canary.local"
)

type fixedResolver struct {
	addrs []netip.Addr
}

func (f fixedResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return f.addrs, nil
}

// localReport builds a LOCAL_FULL report whose only evidence came from the DNS
// probe, exactly as orchestration will later assemble one.
func localReport(t *testing.T) domain.Report {
	t.Helper()

	evidence, err := dns.Lookup(
		context.Background(),
		fixedResolver{addrs: []netip.Addr{
			netip.MustParseAddr(canaryIPv4),
			netip.MustParseAddr(canaryIPv6),
		}},
		canaryHost,
	)
	if err != nil {
		t.Fatalf("dns.Lookup: %v", err)
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	service, err := domain.NewServiceID("example")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("0.0.0-dev", time.Unix(1700000000, 0).UTC(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(canaryHost+":5555", canaryHost+":5555")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(canaryVantage)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run:      run,
		Target:   target,
		Vantage:  vantage,
		Graph:    graph,
		Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func canonicalJSON(t *testing.T, report domain.Report) string {
	t.Helper()

	encoded, err := report.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	return string(encoded)
}

// TestLocalReportContainsTheCanaries proves the leak assertions below can fail.
// A test that only asserts absence would pass just as happily against a report
// that never contained the values in the first place.
func TestLocalReportContainsTheCanaries(t *testing.T) {
	encoded := canonicalJSON(t, localReport(t))

	for _, canary := range []string{canaryHost, canaryIPv4, canaryIPv6, canaryVantage} {
		if !strings.Contains(encoded, canary) {
			t.Errorf("local report does not contain %q, so the leak test would prove nothing", canary)
		}
	}
}

// TestDNSEvidenceRedactsWithoutLeaking is the contract itself: every identity
// the DNS probe recorded is gone from the shareable report.
func TestDNSEvidenceRedactsWithoutLeaking(t *testing.T) {
	shareable, err := redaction.Redact(localReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	encoded := canonicalJSON(t, shareable)
	for _, canary := range []string{canaryHost, canaryIPv4, canaryIPv6, canaryVantage} {
		if strings.Contains(encoded, canary) {
			t.Errorf("shareable report leaks %q:\n%s", canary, encoded)
		}
	}
	if got := shareable.Security().OutputMode(); got != domain.OutputModeShareableRedacted {
		t.Errorf("output mode = %s, want SHAREABLE_REDACTED", got)
	}
}

// TestRedactedDNSEvidenceStaysDiagnostic checks the other half of the bargain.
// A shareable report with no identity but also no facts would not be worth
// sharing: the layer, step, state and answer count must survive.
func TestRedactedDNSEvidenceStaysDiagnostic(t *testing.T) {
	shareable, err := redaction.Redact(localReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	nodes := shareable.Graph().Nodes()
	if len(nodes) != 1 {
		t.Fatalf("node count = %d, want 1", len(nodes))
	}
	node := nodes[0]

	if node.Layer() != domain.LayerDNS {
		t.Errorf("layer = %s, want L1", node.Layer())
	}
	if node.Step() != dns.StepLookup {
		t.Errorf("step = %s, want %s", node.Step(), dns.StepLookup)
	}
	if node.State() != domain.StatePass {
		t.Errorf("state = %s, want PASS", node.State())
	}

	value, ok := node.Attribute(dns.AttrAnswers)
	if !ok {
		t.Fatalf("attribute %s is missing after redaction", dns.AttrAnswers)
	}
	answers, ok := value.StringList()
	if !ok {
		t.Fatalf("attribute %s has kind %s, want stringList", dns.AttrAnswers, value.Kind())
	}
	if len(answers) != 2 {
		t.Errorf("answers = %v, want 2 pseudonymized entries", answers)
	}
	for _, answer := range answers {
		if !strings.HasPrefix(answer, "ip-") {
			t.Errorf("answer %q is not a pseudonym, so redaction did not recognize its shape", answer)
		}
	}
}

// TestRedactionPreservesCorrelation checks that the hostname the probe recorded
// as a subject maps to the same pseudonym as the one in the target. Losing that
// would make a shared report unreadable: nobody could tell that the name that
// failed to resolve is the name that was asked about.
func TestRedactionPreservesCorrelation(t *testing.T) {
	shareable, err := redaction.Redact(localReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	subjectRef := shareable.Graph().Nodes()[0].Subject().Ref()
	if !strings.HasPrefix(subjectRef, "host-") {
		t.Fatalf("subject ref = %q, want a host pseudonym", subjectRef)
	}
	if requested := shareable.Target().Requested(); !strings.HasPrefix(requested, subjectRef+":") {
		t.Errorf("target %q does not carry the subject pseudonym %q", requested, subjectRef)
	}
}
