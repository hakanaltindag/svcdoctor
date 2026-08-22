package transport

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// sweep is the transport measurement one requested target caused, read off the
// graph rather than reconstructed from anything a rule knows.
//
// It is built by walking Children downward from a requested-target anchor, which
// is the whole ownership mechanism (ADR 0042 section 7, ADR 0043 section 1).
// Nothing here starts from a transport node and asks what that node is about, so
// no provenance is inferred and none is available to infer.
//
// A sweep is well formed when its shape is one internal/probe/transport
// produces. When it is not, wellFormed is false and every claim is withheld:
// diagnosis must not invent a target claim from a graph it does not recognize.
type sweep struct {
	// anchor is the requested-target node. It owns the subject every finding
	// about this sweep carries.
	anchor domain.Evidence

	// lookup is the sweep's single DNS root.
	lookup domain.Evidence

	// connects are the per-address TCP measurements beneath the lookup, in
	// canonical order. Empty when the lookup did not pass, because the chain
	// mints no connection node for an address it never learned.
	connects []domain.Evidence

	wellFormed bool
}

// collectSweeps reads every requested-target sweep in the graph.
//
// The anchor predicate is all three properties the producer commits to, not just
// the step. A node that carried the right step with the wrong layer or the wrong
// subject kind would be a shape internal/app does not produce, and matching it
// loosely is how a rule starts diagnosing something else's evidence.
func collectSweeps(g domain.Graph) []sweep {
	var out []sweep
	// Canonical node order in, deterministic sweep order out, before the engine
	// sorts anything.
	for _, node := range g.Nodes() {
		if node.Step() != vocabulary.StepTargetRequested ||
			node.Layer() != domain.LayerInput ||
			node.Subject().Kind() != domain.SubjectKindTarget {
			continue
		}
		out = append(out, collectSweep(g, node))
	}
	return out
}

// collectSweep reads the sweep one anchor caused.
//
// It rejects, by returning wellFormed false, any shape the transport chain does
// not produce: an anchor child that is not a DNS lookup, more than one lookup
// under one anchor, a lookup child that is not a TCP connection, or an edge
// naming a node the graph does not hold. Each would leave a rule guessing what it
// was looking at.
//
// # Why more than one lookup is refused rather than handled
//
// ADR 0043 section 2 fixes the aggregation unit as the anchor: one anchor yields
// at most one DNS finding and at most one TCP finding. A second lookup would be a
// second execution under one target — expressible under ADR 0032, and produced by
// nothing today — and the rule has no policy for which one the finding is about.
// Withholding is the honest answer to a question no record has answered.
//
// # Why the TLS level is absent
//
// The walk stops at TCP. A tls.handshake node under a requested tcp.connect would
// be generic transport evidence, and no production run produces one; PostgreSQL's
// handshake hangs off its own negotiation node and is the service's. See the
// package documentation and ADR 0043 section 14.
func collectSweep(g domain.Graph, anchor domain.Evidence) sweep {
	s := sweep{anchor: anchor}

	children := g.Children(anchor.ID())
	if len(children) == 0 {
		// An anchor with no sweep beneath it. The run recorded its target and
		// measured nothing, which is a truthful graph and supports no transport
		// claim.
		s.wellFormed = true
		return s
	}
	if len(children) > 1 {
		return sweep{}
	}

	lookup, ok := g.Node(children[0])
	if !ok || lookup.Step() != vocabulary.StepDNSLookup {
		return sweep{}
	}
	s.lookup = lookup

	for _, connectID := range g.Children(lookup.ID()) {
		connect, ok := g.Node(connectID)
		if !ok || connect.Step() != vocabulary.StepTCPConnect {
			return sweep{}
		}
		s.connects = append(s.connects, connect)
	}

	s.wellFormed = true
	return s
}

// hasLookup reports whether a DNS root was measured at all.
func (s sweep) hasLookup() bool { return !s.lookup.IsZero() }
