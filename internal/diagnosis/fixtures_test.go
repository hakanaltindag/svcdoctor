package diagnosis

import (
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Fixtures for the Phase 10.1a reasoning core.
//
// engine_test.go has its own, older, single-subject graph. These build the
// shapes the boundary, the sibling counts and the epistemic properties need:
// several subjects, several layers per subject, and recorded blocking.
//
// Every subject reference here is a placeholder name. Nothing in this package
// may know a service, and the guard that enforces it reads production files
// only — but a fixture that spelled a real product name would still make the
// wrong point about what this package is allowed to think about.

// spec accumulates a graph for one test.
type spec struct {
	t *testing.T
	b *domain.GraphBuilder
}

func newSpec(t *testing.T) *spec {
	t.Helper()
	return &spec{t: t, b: domain.NewGraphBuilder()}
}

// endpoint records one node about an endpoint subject.
func (s *spec) endpoint(
	id, ref string, layer domain.Layer, step string, state domain.State,
) domain.EvidenceID {
	s.t.Helper()

	subject, err := domain.NewEndpointSubject(ref)
	if err != nil {
		s.t.Fatalf("NewEndpointSubject(%q): %v", ref, err)
	}
	return s.node(id, subject, layer, step, state)
}

func (s *spec) node(
	id string, subject domain.Subject, layer domain.Layer, step string, state domain.State,
) domain.EvidenceID {
	s.t.Helper()

	evidenceID, err := domain.NewEvidenceID(id)
	if err != nil {
		s.t.Fatalf("NewEvidenceID(%q): %v", id, err)
	}
	stepName, err := domain.NewStep(step)
	if err != nil {
		s.t.Fatalf("NewStep(%q): %v", step, err)
	}

	// A failure class is required for FAIL and forbidden nowhere else that
	// matters here; the specific class never affects a boundary, which reads
	// states alone.
	failure := domain.FailureNone
	switch state {
	case domain.StateFail:
		failure = domain.FailureTCPConnectionRefused
	case domain.StateSkipped:
		failure = domain.FailureExecSkippedPrerequisiteFailed
	case domain.StateDegraded:
		failure = domain.FailureTLSCertificateExpired
	case domain.StateUnknown, domain.StatePass:
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           evidenceID,
		Subject:      subject,
		Layer:        layer,
		Step:         stepName,
		State:        state,
		FailureClass: failure,
		StartedAt:    time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
		Elapsed:      domain.Measured(time.Millisecond),
	})
	if err != nil {
		s.t.Fatalf("NewEvidence(%q): %v", id, err)
	}
	if err := s.b.AddEvidence(evidence); err != nil {
		s.t.Fatalf("AddEvidence(%q): %v", id, err)
	}
	return evidenceID
}

// unknown records a node whose step was entered and reached no conclusion,
// carrying the class a local budget produces.
func (s *spec) unknown(
	id, ref string, layer domain.Layer, step string,
) domain.EvidenceID {
	s.t.Helper()

	subject, err := domain.NewEndpointSubject(ref)
	if err != nil {
		s.t.Fatalf("NewEndpointSubject(%q): %v", ref, err)
	}
	evidenceID, err := domain.NewEvidenceID(id)
	if err != nil {
		s.t.Fatalf("NewEvidenceID(%q): %v", id, err)
	}
	stepName, err := domain.NewStep(step)
	if err != nil {
		s.t.Fatalf("NewStep(%q): %v", step, err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           evidenceID,
		Subject:      subject,
		Layer:        layer,
		Step:         stepName,
		State:        domain.StateUnknown,
		FailureClass: domain.FailureExecLocalTimeout,
		StartedAt:    time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
		Elapsed:      domain.Unmeasured(),
	})
	if err != nil {
		s.t.Fatalf("NewEvidence(%q): %v", id, err)
	}
	if err := s.b.AddEvidence(evidence); err != nil {
		s.t.Fatalf("AddEvidence(%q): %v", id, err)
	}
	return evidenceID
}

func (s *spec) parent(child, parent domain.EvidenceID) {
	s.t.Helper()
	if err := s.b.AddParent(child, parent); err != nil {
		s.t.Fatalf("AddParent(%q, %q): %v", child, parent, err)
	}
}

func (s *spec) blockedBy(skipped, blocker domain.EvidenceID) {
	s.t.Helper()
	if err := s.b.AddBlockedBy(skipped, blocker); err != nil {
		s.t.Fatalf("AddBlockedBy(%q, %q): %v", skipped, blocker, err)
	}
}

func (s *spec) freeze() domain.Graph {
	s.t.Helper()
	g, err := s.b.Freeze()
	if err != nil {
		s.t.Fatalf("Freeze: %v", err)
	}
	return g
}

// endpointSubject is the subject value for a reference, for assertions.
func endpointSubject(t *testing.T, ref string) domain.Subject {
	t.Helper()
	subject, err := domain.NewEndpointSubject(ref)
	if err != nil {
		t.Fatalf("NewEndpointSubject(%q): %v", ref, err)
	}
	return subject
}

// findingAbout builds a valid finding for merge and validation tests.
func findingAbout(
	t *testing.T,
	code string,
	subject domain.Subject,
	kind domain.FindingKind,
	severity domain.Severity,
	confidence domain.Confidence,
	summary string,
	refs ...domain.EvidenceID,
) domain.Finding {
	t.Helper()

	findingCode, err := domain.NewFindingCode(code)
	if err != nil {
		t.Fatalf("NewFindingCode(%q): %v", code, err)
	}
	in := domain.FindingInput{
		Code:         findingCode,
		Kind:         kind,
		Severity:     severity,
		Confidence:   confidence,
		Layer:        domain.LayerTCP,
		Subject:      subject,
		Summary:      summary,
		EvidenceRefs: refs,
	}
	f, err := domain.NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding(%q): %v", code, err)
	}
	return f
}

// linearGraph is the shape most tests start from:
//
//	one endpoint, dns PASS -> tcp FAIL -> tls SKIPPED blocked by tcp
func linearGraph(t *testing.T) (domain.Graph, domain.Subject) {
	t.Helper()

	s := newSpec(t)
	dns := s.endpoint("a-dns", "one.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.endpoint("a-tcp", "one.example:5432", domain.LayerTCP, "tcp.connect", domain.StateFail)
	tls := s.endpoint("a-tls", "one.example:5432", domain.LayerTLS, "tls.handshake", domain.StateSkipped)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	s.blockedBy(tls, tcp)

	return s.freeze(), endpointSubject(t, "one.example:5432")
}

// fuzzStart is the fixed instant every fuzz-built node is stamped with.
//
// A fuzz target that read the clock would produce a corpus entry that behaves
// differently on replay, which defeats the point of a corpus.
var fuzzStart = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
