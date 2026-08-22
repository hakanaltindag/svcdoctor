package transport

import (
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Graph fixtures for the rule semantics.
//
// These are hand-built because the semantics are a pure function of graph shape,
// and building the shapes directly is the only way to cover states a real run
// cannot be made to produce on demand — a dialer that returns neither a
// connection nor an error, a sweep cut short mid-address, twenty failing
// addresses.
//
// The shapes themselves are not invented. They reproduce what
// internal/probe/transport and internal/app actually emit, which was dumped from
// real runs; the ownership and report claims are then verified against real
// graphs in internal/app and test/security, where a fixture could not prove them.

// builder accumulates a graph in the shape a run produces.
type builder struct {
	t   *testing.T
	g   *domain.GraphBuilder
	now time.Time
}

func newBuilder(t *testing.T) *builder {
	t.Helper()
	return &builder{t: t, g: domain.NewGraphBuilder(), now: time.Unix(1700000000, 0).UTC()}
}

// anchor mints a requested-target node exactly as internal/app does.
func (b *builder) anchor(endpoint string) domain.EvidenceID {
	b.t.Helper()

	subject, err := domain.NewTargetSubject(endpoint)
	if err != nil {
		b.t.Fatalf("NewTargetSubject: %v", err)
	}
	return b.add(domain.EvidenceInput{
		ID:           domain.EvidenceID("target.requested/" + endpoint),
		Subject:      subject,
		Layer:        domain.LayerInput,
		Step:         vocabulary.StepTargetRequested,
		State:        domain.StatePass,
		FailureClass: domain.FailureNone,
		StartedAt:    b.now,
	}, "")
}

// lookup mints a DNS node beneath a parent.
func (b *builder) lookup(
	parent domain.EvidenceID, host string, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	b.t.Helper()
	return b.add(domain.EvidenceInput{
		ID:           domain.EvidenceID("dns.lookup/" + host),
		Subject:      b.endpointSubject(host),
		Layer:        domain.LayerDNS,
		Step:         vocabulary.StepDNSLookup,
		State:        state,
		FailureClass: class,
		StartedAt:    b.now,
	}, parent)
}

// connect mints a TCP node beneath a lookup.
func (b *builder) connect(
	parent domain.EvidenceID, address string, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	b.t.Helper()
	return b.add(domain.EvidenceInput{
		ID:           domain.EvidenceID("tcp.connect/endpoint/" + address),
		Subject:      b.endpointSubject(address),
		Layer:        domain.LayerTCP,
		Step:         vocabulary.StepTCPConnect,
		State:        state,
		FailureClass: class,
		StartedAt:    b.now,
	}, parent)
}

// node mints an arbitrary node, for the shapes the rules must not recognize.
func (b *builder) node(
	parent domain.EvidenceID, id string, step domain.Step, layer domain.Layer,
	state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	b.t.Helper()
	return b.add(domain.EvidenceInput{
		ID:           domain.EvidenceID(id),
		Subject:      b.endpointSubject(id),
		Layer:        layer,
		Step:         step,
		State:        state,
		FailureClass: class,
		StartedAt:    b.now,
	}, parent)
}

func (b *builder) endpointSubject(ref string) domain.Subject {
	b.t.Helper()
	subject, err := domain.NewEndpointSubject(ref)
	if err != nil {
		b.t.Fatalf("NewEndpointSubject(%q): %v", ref, err)
	}
	return subject
}

func (b *builder) add(in domain.EvidenceInput, parent domain.EvidenceID) domain.EvidenceID {
	b.t.Helper()

	evidence, err := domain.NewEvidence(in)
	if err != nil {
		b.t.Fatalf("NewEvidence(%s): %v", in.ID, err)
	}
	if err := b.g.AddEvidence(evidence); err != nil {
		b.t.Fatalf("AddEvidence(%s): %v", in.ID, err)
	}
	if parent != "" {
		if err := b.g.AddParent(evidence.ID(), parent); err != nil {
			b.t.Fatalf("AddParent(%s): %v", in.ID, err)
		}
	}
	return evidence.ID()
}

func (b *builder) freeze() domain.Graph {
	b.t.Helper()

	graph, err := b.g.Freeze()
	if err != nil {
		b.t.Fatalf("Freeze: %v", err)
	}
	return graph
}

// requestedDNS builds the common shape: one anchor, one lookup with a given
// outcome, and no connections.
func requestedDNS(t *testing.T, state domain.State, class domain.FailureClass) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	anchor := b.anchor("db.example.com:5432")
	b.lookup(anchor, "db.example.com", state, class)
	return b.freeze()
}

// connectOutcome is one address's measured result.
type connectOutcome struct {
	address string
	state   domain.State
	class   domain.FailureClass
}

func fail(address string, class domain.FailureClass) connectOutcome {
	return connectOutcome{address: address, state: domain.StateFail, class: class}
}

func pass(address string) connectOutcome {
	return connectOutcome{address: address, state: domain.StatePass, class: domain.FailureNone}
}

func unknown(address string, class domain.FailureClass) connectOutcome {
	return connectOutcome{address: address, state: domain.StateUnknown, class: class}
}

func skipped(address string, class domain.FailureClass) connectOutcome {
	return connectOutcome{address: address, state: domain.StateSkipped, class: class}
}

// requestedTCP builds a passing lookup with the given connection outcomes.
func requestedTCP(t *testing.T, outcomes ...connectOutcome) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	anchor := b.anchor("db.example.com:5432")
	lookup := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
	for _, o := range outcomes {
		b.connect(lookup, o.address, o.state, o.class)
	}
	return b.freeze()
}

// codesOf returns the codes a rule produced, in order.
func codesOf(findings []domain.Finding) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code())
	}
	return out
}

// requireOne asserts a rule produced exactly one finding with the wanted code.
func requireOne(
	t *testing.T, findings []domain.Finding, want domain.FindingCode,
) domain.Finding {
	t.Helper()

	if len(findings) != 1 {
		t.Fatalf("got %d findings %v, want exactly one %s", len(findings), codesOf(findings), want)
	}
	if got := findings[0].Code(); got != want {
		t.Fatalf("code = %s, want %s", got, want)
	}
	return findings[0]
}

// requireNone asserts a rule withheld.
func requireNone(t *testing.T, findings []domain.Finding) {
	t.Helper()

	if len(findings) != 0 {
		t.Fatalf("got %v, want no finding", codesOf(findings))
	}
}
