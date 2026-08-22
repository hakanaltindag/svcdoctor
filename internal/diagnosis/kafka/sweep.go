package kafka

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// sweep is the transport measurement one advertisement caused, read off the
// graph rather than reconstructed from anything the rule knows.
//
// It is built by walking Children downward from the advertisement, which is the
// whole anchoring mechanism (ADR 0034 section 2). Nothing here starts from a
// transport node and asks what that node is about: the rule is looking at these
// nodes because it walked here from one advertisement, so the context is
// structural and no provenance is inferred.
//
// A sweep is well formed when the shape matches what internal/probe/transport
// produces. When it does not, wellFormed is false and the caller withholds every
// claim — diagnosis must not invent a target claim from a graph it does not
// recognize.
type sweep struct {
	// lookupFailures are the DNS roots that did not pass. Such a root has no
	// paths beneath it, so it is the whole causal set for its own branch
	// (ADR 0034 section 11.1).
	lookupFailures []domain.Evidence

	// paths are the per-address measurements: one TCP node and, when the plan
	// required TLS, the handshake node beneath it.
	paths []transportPath

	// nodes is every node of the sweep, used only for the incompleteness scan,
	// which ADR 0034 section 5 condition 4 states over the sweep rather than
	// over the causal set.
	nodes []domain.Evidence

	wellFormed bool
}

// transportPath is one measured route to the endpoint.
type transportPath struct {
	tcp domain.Evidence

	// handshake is the TLS node beneath tcp. Whether it exists is how the rule
	// learns what the run required: the chain mints one — real or SKIPPED —
	// under every TCP node if and only if the plan asked for TLS, which
	// internal/probe/transport/terminallayer_test.go pins in both directions.
	// See ADR 0034 section 4.
	handshake domain.Evidence
	hasTLS    bool
}

// collectSweep reads the sweep derived from one advertisement.
//
// It rejects, by returning wellFormed false, any shape the transport chain does
// not produce: a child of the advertisement that is not a DNS lookup, a child of
// a lookup that is not a TCP connection, a child of a TCP connection that is not
// a handshake, more than one handshake under one connection, or an edge naming a
// node the graph does not hold. Each of those would leave the rule guessing what
// it was looking at, and a guess is the one thing a rule may not make.
func collectSweep(g domain.Graph, advertisement domain.EvidenceID) sweep {
	var s sweep

	for _, rootID := range g.Children(advertisement) {
		root, ok := g.Node(rootID)
		if !ok || root.Layer() != domain.LayerDNS {
			return sweep{}
		}
		s.nodes = append(s.nodes, root)

		if root.State() != domain.StatePass {
			// A lookup that did not pass resolved nothing, so nothing hangs
			// beneath it and the node itself carries the branch's outcome.
			s.lookupFailures = append(s.lookupFailures, root)
			continue
		}

		for _, connectionID := range g.Children(rootID) {
			connection, ok := g.Node(connectionID)
			if !ok || connection.Layer() != domain.LayerTCP {
				return sweep{}
			}
			s.nodes = append(s.nodes, connection)

			path := transportPath{tcp: connection}
			for _, handshakeID := range g.Children(connectionID) {
				handshake, ok := g.Node(handshakeID)
				if !ok || handshake.Layer() != domain.LayerTLS || path.hasTLS {
					return sweep{}
				}
				path.handshake = handshake
				path.hasTLS = true
				s.nodes = append(s.nodes, handshake)
			}
			s.paths = append(s.paths, path)
		}
	}

	s.wellFormed = true
	return s
}

// terminalIsTLS reports whether reaching this endpoint required a handshake.
//
// The transport plan is a caller-supplied value that is not stored in the graph
// (ADR 0033 section 2), so the only truthful answer available to a reader is the
// structural one: a TCP node has a TLS child if and only if the plan required
// TLS. Reading "a handshake was attempted here" off a node that records a
// handshake is reading what the graph states about an execution, which is
// evidence — unlike reading provenance off graph shape, which is why Origin
// stays deferred (ADR 0034 section 4).
//
// The quantifier is universal on purpose. Under the pinned invariant "some" and
// "every" cannot disagree, so the choice is only visible on a graph that already
// violates it — and there the safe answer is the one that withholds a claim
// rather than the one that calls a passing TCP path insufficient.
func (s sweep) terminalIsTLS() bool {
	if len(s.paths) == 0 {
		return false
	}
	for _, p := range s.paths {
		if !p.hasTLS {
			return false
		}
	}
	return true
}

// reachedTerminal reports whether p completed the layer the run required.
func (p transportPath) reachedTerminal(terminalIsTLS bool) bool {
	if terminalIsTLS {
		return p.hasTLS && p.handshake.State() == domain.StatePass
	}
	return p.tcp.State() == domain.StatePass
}

// owner returns the earliest node on p whose state is not PASS.
//
// This single selection is the whole evidence-reference algorithm for a measured
// path, and it is also why no separate SKIPPED exclusion rule is needed: a
// handshake is SKIPPED only when its own TCP node did not pass, and that node is
// earlier on the same path, so a prerequisite skip can never be selected. Two
// rules collapse into one. See ADR 0034 sections 9 and 11.2.
//
// The second result is false when every node on the path passed.
func (p transportPath) owner() (domain.Evidence, bool) {
	if p.tcp.State() != domain.StatePass {
		return p.tcp, true
	}
	if p.hasTLS && p.handshake.State() != domain.StatePass {
		return p.handshake, true
	}
	return domain.Evidence{}, false
}

// owners returns the causal set of the sweep: one node per branch that did not
// pass, in graph order.
func (s sweep) owners(terminalIsTLS bool) []domain.Evidence {
	out := make([]domain.Evidence, 0, len(s.lookupFailures)+len(s.paths))
	out = append(out, s.lookupFailures...)
	for _, p := range s.paths {
		if p.reachedTerminal(terminalIsTLS) {
			continue
		}
		if node, ok := p.owner(); ok {
			out = append(out, node)
		}
	}
	return out
}

// anyReachedTerminal reports whether a client selecting some measured address
// would have completed the transport the run required.
func (s sweep) anyReachedTerminal(terminalIsTLS bool) bool {
	for _, p := range s.paths {
		if p.reachedTerminal(terminalIsTLS) {
			return true
		}
	}
	return false
}

// incomplete reports whether any part of the sweep is unresolved for a reason
// that belongs to svcdoctor rather than to the target.
//
// It is stated over every node of the sweep, matching ADR 0034 section 5
// condition 4 literally: no UNKNOWN node, and no TCP node skipped for budget.
// On a graph the chain produces the two readings coincide, because such a node
// is always its own branch's earliest non-PASS node; stating it over the sweep
// costs nothing and can only withhold a confirmed claim, never manufacture one.
func (s sweep) incomplete() bool {
	for _, n := range s.nodes {
		if isIncomplete(n) {
			return true
		}
	}
	return false
}

// isIncomplete reports whether one node records svcdoctor not finishing rather
// than the target failing.
//
// A prerequisite skip is deliberately excluded: it is a downstream explanation
// of a failure its blocker already owns, not a gap in the measurement.
func isIncomplete(n domain.Evidence) bool {
	if n.State() == domain.StateUnknown {
		return true
	}
	if n.State() != domain.StateSkipped {
		return false
	}
	switch n.FailureClass() {
	case domain.FailureExecLocalTimeout, domain.FailureExecCancelled:
		return true
	default:
		return false
	}
}
