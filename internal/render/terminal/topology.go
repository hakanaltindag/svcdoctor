package terminal

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// topologyLine counts what discovery measured, and reports whether there is
// anything to count.
//
// # It is a count, not a judgement
//
// ADR 0052 section 4: it ranks nothing, calls nothing degraded, applies no
// threshold and names no endpoint. The findings carry the claims. In particular
// the words `usable`, `healthy`, `reachable` and `cluster reachable` are all
// rejected — an advertised endpoint is never authenticated (ADR 0050), so
// nothing in a run supports a fitness claim about a discovered broker, and a
// present-tense capability word would overstate a past-tense observation.
//
//	topology   2 of 3 advertised broker endpoints reached
//	topology   2 of 3 advertised broker endpoints reached, 1 not measured
//
// # `not measured` is never folded into the unreached count
//
// Without the second clause, `2 of 3 reached` asserts a failure nobody observed.
// An advertisement svcdoctor's own budget stopped it from measuring is not an
// endpoint that refused: a client selecting the address svcdoctor never tried
// might have connected. That is the same false certainty ADR 0051's
// PASS-is-existential / FAIL-is-universal rule exists to prevent, one layer up.
//
// # Advertisements are counted as the cluster stated them
//
// Two entries naming the same endpoint are two advertisements. Nothing here
// deduplicates: the count is what the Metadata response said, and collapsing
// duplicates would be the renderer editing the cluster's own answer. No Accepted
// record authorizes a different cardinality.
func topologyLine(g domain.Graph, view serviceView) (string, bool) {
	advertisements := collectAdvertisements(g, view)
	if len(advertisements) == 0 {
		return "", false
	}

	reached, notMeasured := 0, 0
	for _, a := range advertisements {
		switch classify(a) {
		case advertisementReached:
			reached++
		case advertisementNotMeasured:
			notMeasured++
		case advertisementNotReached:
			// Positively observed: counted only in the total, and the findings
			// say what happened.
		}
	}

	line := fmt.Sprintf("%d of %d advertised broker endpoints reached",
		reached, len(advertisements))
	if notMeasured > 0 {
		line += fmt.Sprintf(", %d not measured", notMeasured)
	}
	return line, true
}

// The three verdicts an advertisement can have.
type advertisementVerdict int

const (
	// advertisementNotReached is a complete negative: every selectable path was
	// tried and none completed the transport the run required.
	advertisementNotReached advertisementVerdict = iota

	// advertisementReached is a complete positive: one path completed.
	advertisementReached

	// advertisementNotMeasured is neither. The run did not learn whether this
	// endpoint was reachable, so it claims nothing about it.
	advertisementNotMeasured
)

// classify decides one advertisement's verdict.
//
// # It is ADR 0051's predicate, read from the graph
//
// `internal/app` owns the same rule for run completeness, and the two must agree
// or the Result block would say `3 of 3 reached` on a run it also called
// INCOMPLETE. They cannot share an implementation — depguard denies a renderer
// the application, for good reasons that have nothing to do with this — so the
// agreement is proven by test against real runs rather than by construction.
//
// PASS is existential and FAIL is universal. One working path resolves an
// advertisement outright, whatever happened on its siblings; a negative is
// complete only when nothing was left unmeasured.
//
// # An unrecognized shape is `not measured`, never a verdict
//
// An advertisement with no sweep, two lookups where the producer mints one, or a
// resolved name nothing was attempted against, is a shape this function does not
// understand. The failure it exists to prevent is a run claiming an endpoint was
// unreachable when nobody looked, so the direction it errs in is the one that
// says so.
//
// # An advertisement the cluster stated unusably is not `not measured`
//
// It is a positively observed negative. There was no endpoint to sweep, no
// sweep was promised, and ADR 0051 leaves it out of the completeness rule for
// exactly that reason. Its own finding carries the claim.
func classify(a advertisement) advertisementVerdict {
	if a.node.State() != domain.StatePass {
		return advertisementNotReached
	}
	if a.hasLookup {
		if unknownLocal(a.lookup) {
			return advertisementNotMeasured
		}
		if a.lookup.State() == domain.StateFail {
			// Resolution produced nothing to connect to, which is a complete
			// negative on its own: there is no address a client could have
			// selected instead.
			return advertisementNotReached
		}
	}
	if len(a.paths) == 0 {
		// Either the name resolved and nothing was attempted against it, or
		// there was neither a lookup nor a connection — a sweep the budget
		// stopped before it began. Both are shapes nobody measured.
		//
		// **An advertisement that named an address is not one of them.** It has
		// no lookup and never will (ADR 0059), and it reaches here with its
		// connection nodes intact, so it is classified by the same existential
		// and universal rules below as a name that resolved. Reading "no lookup"
		// as "not measured" would have counted every reachable literal broker as
		// unmeasured and made the topology line understate a working cluster.
		return advertisementNotMeasured
	}

	// Existential first: one usable path settles it.
	for _, p := range a.paths {
		if reachedTransport(p) {
			return advertisementReached
		}
	}

	// No usable path, so this is about to be a universal negative. It may be one
	// only if nothing was left unmeasured — on a connection, or on the handshake
	// the plan required over it.
	for _, p := range a.paths {
		connection, ok := p.stages[vocabulary.StepTCPConnect]
		if !ok || unknownLocal(connection) {
			return advertisementNotMeasured
		}
		if handshake, planned := p.stages[vocabulary.StepTLSHandshake]; planned &&
			unknownLocal(handshake) {
			return advertisementNotMeasured
		}
	}
	return advertisementNotReached
}

// reachedTransport reports whether one address completed the transport the run
// required.
//
// **TLS is part of transport success when the plan asked for it**, and the plan
// is read off the graph rather than passed in: the sweep mints a `tls.handshake`
// node under every connection if and only if TLS was required (ADR 0034 section
// 4), so a handshake's presence is the plan and its absence is the plan too.
func reachedTransport(p path) bool {
	connection, ok := p.stages[vocabulary.StepTCPConnect]
	if !ok || connection.State() != domain.StatePass {
		return false
	}
	handshake, planned := p.stages[vocabulary.StepTLSHandshake]
	if !planned {
		return true
	}
	return handshake.State() == domain.StatePass
}

// unknownLocal reports whether a node records svcdoctor stopping rather than the
// target answering.
//
// SKIPPED is deliberately excluded, matching ADR 0051: a SKIPPED node under a
// sweep restates a failure its blocker already owns, or reflects a context that
// was already done — and a run in that state is INCOMPLETE for a reason the
// execution line already states.
func unknownLocal(node domain.Evidence) bool {
	if node.State() != domain.StateUnknown {
		return false
	}
	switch node.FailureClass() {
	case domain.FailureExecLocalTimeout, domain.FailureExecCancelled:
		return true
	default:
		return false
	}
}
