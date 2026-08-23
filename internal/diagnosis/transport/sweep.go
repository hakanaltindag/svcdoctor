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

	// lookup is the sweep's single DNS root, and is zero when the sweep
	// performed no resolution.
	//
	// **Absent is a shape, not a gap.** A sweep of an address literal has
	// nothing to resolve, so internal/probe/transport mints no L1 node and the
	// connection attempts hang directly off the anchor (ADR 0059). A rule reads
	// hasLookup to learn which of the two it is looking at, and neither answer
	// means the graph is malformed.
	lookup domain.Evidence

	// connects are the per-address TCP measurements beneath the lookup, in
	// canonical order. Empty when the lookup did not pass, because the chain
	// mints no connection node for an address it never learned.
	connects []domain.Evidence

	// handshakes are the tls.handshake nodes that are **direct children** of a
	// connect in this sweep, in canonical order.
	//
	// Direct is the whole ownership test for generic TLS (ADR 0053 section 8).
	// The generic transport chain hangs a handshake straight off the connection
	// it upgraded, so a node here was performed for the target the operator
	// asked about. PostgreSQL's in-band handshake hangs off
	// postgres.ssl_request instead — a grandchild of the connect — so it is not
	// collected and ADR 0044 keeps it.
	//
	// Empty on every PostgreSQL run and on every run whose plan asked for no
	// TLS, which is why nothing here changes what DNS and TCP already claim.
	handshakes []upgrade

	wellFormed bool
}

// upgrade pairs a handshake with the connection it was performed on, so a rule
// never has to ask the graph what a node hangs from to cite its parent.
type upgrade struct {
	connect   domain.Evidence
	handshake domain.Evidence
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
// # The TLS level, and why it does not tighten the shape
//
// A tls.handshake that is a **direct child** of a requested tcp.connect is
// generic transport evidence, and ADR 0053 gave it an owner. It is collected
// here so the TLS rule descends from the anchor like its siblings rather than
// walking upward.
//
// **A connect child that is not a handshake is ignored, not rejected.** That is
// deliberate and load-bearing: PostgreSQL's connect carries a
// postgres.ssl_request child, and refusing the shape would make every PostgreSQL
// sweep ill-formed and silence the DNS and TCP findings that already work. So an
// unrecognized child means only "no generic handshake here", never "this sweep
// is unreadable".
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
	connectIDs, ok := s.readRoot(g, children)
	if !ok {
		return sweep{}
	}

	for _, connectID := range connectIDs {
		connect, ok := g.Node(connectID)
		if !ok || connect.Step() != vocabulary.StepTCPConnect {
			return sweep{}
		}
		s.connects = append(s.connects, connect)

		// Direct children only, and no recursion: a deeper walk would reach a
		// service's own negotiation and, below a Kafka bootstrap target, the
		// advertised sweep that ADR 0034 owns.
		for _, childID := range g.Children(connect.ID()) {
			child, ok := g.Node(childID)
			if !ok {
				return sweep{}
			}
			if child.Step() != vocabulary.StepTLSHandshake {
				continue
			}
			s.handshakes = append(s.handshakes, upgrade{connect: connect, handshake: child})
		}
	}

	s.wellFormed = true
	return s
}

// readRoot recognizes which of the two shapes the transport chain produced
// beneath an anchor, records the lookup when there is one, and returns the
// identifiers of the connection nodes.
//
// # The two shapes, and why the *step* decides
//
//	target.requested -> dns.lookup -> tcp.connect ...   a name was resolved
//	target.requested -> tcp.connect ...                 an address was supplied
//
// The discriminator is the step of the anchor's children, which is a fact the
// producer wrote into the graph. Nothing here parses a subject, inspects a
// string for dots or colons, or asks whether a host "looks like" an address:
// depguard denies this package `net` and `internal/probe` precisely so that the
// question can only be answered structurally, and the structural answer is the
// truthful one — the L1 node exists exactly when an L1 operation happened.
//
// # Why a resolution-free sweep may hold several connections
//
// It will hold one, because one literal is one address. The loop is written over
// however many the graph holds rather than asserting one, because the assertion
// would buy nothing: a rule that refused a second connection node would withhold
// every claim about a shape it could otherwise read correctly, and "every
// connection failed" is already the aggregation both shapes use.
//
// # A mixed shape is refused
//
// An anchor whose children are a lookup *and* a connection is a graph no
// producer makes. It is rejected rather than partially read, on the same
// principle as the multiple-lookup case below: a rule that guesses which half of
// an unrecognized shape to believe is a rule that will eventually publish the
// guess.
func (s *sweep) readRoot(g domain.Graph, children []domain.EvidenceID) ([]domain.EvidenceID, bool) {
	first, ok := g.Node(children[0])
	if !ok {
		return nil, false
	}

	switch first.Step() {
	case vocabulary.StepDNSLookup:
		// ADR 0043 section 2 fixes the aggregation unit as the anchor: one anchor
		// yields at most one DNS finding and at most one TCP finding. A second
		// lookup would be a second execution under one target — expressible under
		// ADR 0032, produced by nothing today — and the rule has no policy for
		// which one the finding is about. Withholding is the honest answer to a
		// question no record has answered.
		if len(children) > 1 {
			return nil, false
		}
		s.lookup = first
		return g.Children(first.ID()), true

	case vocabulary.StepTCPConnect:
		for _, id := range children[1:] {
			node, ok := g.Node(id)
			if !ok || node.Step() != vocabulary.StepTCPConnect {
				return nil, false
			}
		}
		return children, true

	default:
		return nil, false
	}
}

// hasLookup reports whether a DNS root was measured at all.
//
// False means the sweep resolved nothing because there was nothing to resolve.
// It never means resolution failed: a failed lookup is a present node in a FAIL
// state, and the DNS rule reads it.
func (s sweep) hasLookup() bool { return !s.lookup.IsZero() }
