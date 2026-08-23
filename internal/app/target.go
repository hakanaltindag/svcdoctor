package app

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// logicalTarget is the run's single authority for the endpoint the operator
// asked about.
//
// # Why this type exists rather than two strings
//
// The requested endpoint is rendered twice in one report: once as the
// requested-target anchor's subject, and once as domain.Target on the report
// envelope. Those are two canonical contracts, and a diagnostic tool whose two
// copies of the target disagree is worse than one with neither.
//
// **Neither copy is authoritative over the other. This value is.** Both are
// projections of it, produced by one function, so IPv6 bracketing, port
// rendering and every future normalization decision are made once and cannot
// drift. ADR 0042 section 12 rejected the alternatives: deriving the report's
// target by searching the graph would put step vocabulary into internal/domain,
// and deriving the anchor from the report is backwards, because the graph is
// frozen before the report is assembled.
type logicalTarget struct {
	host string
	port uint16
}

// normalizeHost is L0 input normalization for the one host a run is about.
//
// # Why the composition root does this rather than each consumer
//
// The host an operator typed reaches four places that must agree: the
// requested-target anchor's subject, the report envelope's target, the logical
// endpoint every transport node is scoped by, and the key the credential is
// bound to. Canonicalizing at each of them is how they come to disagree, and the
// disagreement is not hypothetical — before this rule, `--host
// 2001:0db8:0:0:0:0:0:1` produced an anchor reading `[2001:0db8:0:0:0:0:0:1]:1`
// and a connection subject reading `[2001:db8::1]:1`, two spellings of one
// address inside a single evidence identifier.
//
// So it happens once, here, before validate runs. Everything downstream receives
// the canonical spelling and no longer has an opportunity to pick a different
// one. The rule itself is internal/probe's, shared with the transport chain, so
// L0 and L1 cannot drift apart either (ADR 0059).
//
// # Empty is left alone
//
// An empty host is a caller defect with an existing, more specific message in
// validate. Producing an "unsupported host" error for it here would replace a
// precise diagnosis with a vaguer one.
//
// # A name is returned verbatim
//
// Lowercasing, trailing-dot removal and IDNA conversion all change the question
// the resolver is asked, and evidence must record the question that was actually
// asked. Only an address literal has a canonical form this layer may impose,
// because for a literal there is no question to change.
func normalizeHost(host string) (string, error) {
	if host == "" {
		return host, nil
	}
	h, err := probe.ParseHost(host)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return h.String(), nil
}

// label renders the logical endpoint.
//
// net.JoinHostPort is the whole implementation on purpose. It is the bracketing
// rule for IPv6 literals, it is what internal/security and the redactor's
// endpoint splitter already expect, and reimplementing it here would be the
// second normalization ADR 0042 section 12 exists to prevent.
func (t logicalTarget) label() string {
	return net.JoinHostPort(t.host, strconv.FormatUint(uint64(t.port), 10))
}

// evidenceID is the anchor's identifier.
//
// One component, always, whatever the host looks like. ADR 0032 section 3's
// injectivity argument rests on a step minting a fixed number of components, so
// a step that sometimes minted one and sometimes two would quietly break the
// scheme for every scoped identifier in the repository.
//
// The encoding comes from internal/probe because ADR 0019 put it there precisely
// so that two producers cannot disagree about escaping. This package mints one
// identifier and borrows the rule rather than copying it.
func (t logicalTarget) evidenceID() domain.EvidenceID {
	return probe.EvidenceID(vocabulary.StepTargetRequested, t.label())
}

// target projects the logical endpoint onto the report envelope.
func (t logicalTarget) target() (domain.Target, error) {
	return domain.NewTarget(t.label())
}

// recordRequestedTarget writes the one piece of evidence this package is
// authorized to create.
//
// # What the node claims
//
// That input normalization accepted this logical endpoint as the run's target,
// and nothing else. It does not claim that the name resolves, that the port
// accepts connections, that TLS verifies, that PostgreSQL answers, that a
// credential works or that anything is healthy. It is an input fact, and it is
// the only node in a graph that is not a measurement (ADR 0042 section 1).
//
// # Why PASS
//
// L0 is a layer because normalizing input is work that can succeed, and by the
// time this is called it has: PostgresParams.validate ran, and unusable input
// returned ErrInvalidInput before a builder existed. **So there is no FAIL form
// of this node**, and a caller defect never becomes evidence — the same
// separation every layer below already keeps between an error and a fact about
// the target.
//
// # Why it has no parent and adds no edge
//
// It is a graph root: nothing caused the operator to ask. The edge that matters
// — from here down to the sweep this target caused — is recorded by the
// transport chain when it runs, from the identifier returned here. Orchestration
// declares a cause and the producer records it, which is why this package needs
// no AddParent authority and does not have any.
//
// # Why it carries no attributes
//
// The subject is the endpoint. target.host, target.port and requested=true would
// each be a second copy of something already stated, and the last is a boolean
// that is true on every instance of a node that only exists when it is true
// (ADR 0042 section 6).
func recordRequestedTarget(
	builder *domain.GraphBuilder, t logicalTarget, at time.Time,
) (domain.EvidenceID, error) {
	subject, err := domain.NewTargetSubject(t.label())
	if err != nil {
		return "", fmt.Errorf("building requested target subject: %w", err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:      t.evidenceID(),
		Subject: subject,
		Layer:   domain.LayerInput,
		Step:    vocabulary.StepTargetRequested,
		State:   domain.StatePass,
		// Explicit rather than left to the zero value. A reader should not have
		// to know that FailureNone is the zero FailureClass to see that this
		// node asserts no failure.
		FailureClass: domain.FailureNone,
		StartedAt:    at,
		// The run has not measured anything yet, so there is no elapsed time to
		// report. This is the anchor's whole point: it records what was asked
		// for, and asking is not an operation with a duration. Before the
		// Elapsed type it wrote a zero that a reader could not tell from an
		// instantaneous measurement.
		Elapsed: domain.Unmeasured(),
	})
	if err != nil {
		return "", fmt.Errorf("building %s evidence: %w", vocabulary.StepTargetRequested, err)
	}

	if err := builder.AddEvidence(evidence); err != nil {
		return "", fmt.Errorf("recording %s evidence: %w", vocabulary.StepTargetRequested, err)
	}
	return evidence.ID(), nil
}
