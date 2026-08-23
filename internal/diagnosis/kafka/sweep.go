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
	//
	// It is empty for an advertisement that named an address: that sweep
	// resolved nothing, so it has no DNS root to succeed or fail, and its whole
	// causal set is the connection beneath it (ADR 0059).
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
// # The two shapes it recognizes
//
//	kafka.broker_advertised -> dns.lookup -> tcp.connect -> tls.handshake
//	kafka.broker_advertised ->               tcp.connect -> tls.handshake
//
// The second is an advertisement that named an address rather than a name.
// Nothing was resolved, so no L1 node exists, and the discriminator is the
// child's own layer — a fact the producer wrote into the graph rather than
// anything inferred from a subject string (ADR 0059).
//
// It rejects, by returning wellFormed false, any shape the transport chain does
// not produce: a child of the advertisement that is neither a DNS lookup nor a
// TCP connection, a child of a lookup that is not a TCP connection, a child of a
// TCP connection that is not a handshake, more than one handshake under one
// connection, or an edge naming a node the graph does not hold. Each of those
// would leave the rule guessing what it was looking at, and a guess is the one
// thing a rule may not make.
func collectSweep(g domain.Graph, advertisement domain.EvidenceID) sweep {
	var s sweep
	var sawLookup, sawConnection bool

	for _, rootID := range g.Children(advertisement) {
		root, ok := g.Node(rootID)
		if !ok {
			return sweep{}
		}

		switch root.Layer() {
		case domain.LayerDNS:
			sawLookup = true
			s.nodes = append(s.nodes, root)
			if root.State() != domain.StatePass {
				// A lookup that did not pass resolved nothing, so nothing hangs
				// beneath it and the node itself carries the branch's outcome.
				s.lookupFailures = append(s.lookupFailures, root)
				continue
			}
			for _, connectionID := range g.Children(rootID) {
				if !s.readConnection(g, connectionID) {
					return sweep{}
				}
			}

		case domain.LayerTCP:
			// An advertisement that named an address rather than a name. There
			// was nothing to resolve, so the sweep has no L1 node and the
			// connection hangs straight off the advertisement (ADR 0059).
			//
			// **It is the same endpoint kind, not a lesser one.** A broker that
			// advertises 10.20.30.41 is measured exactly as one that advertises
			// broker-1.internal: TCP, then TLS if the plan required it, then a
			// reachability verdict from the same rules. Nothing here is
			// credential-bearing in either case — MeasureAdvertised has nowhere
			// to put a credential (ADR 0050) — so the two shapes differ only in
			// whether an L1 measurement occurred.
			sawConnection = true
			if !s.readConnection(g, rootID) {
				return sweep{}
			}

		default:
			return sweep{}
		}
	}

	// A mixed shape — a resolution *and* a resolution-free connection under one
	// advertisement — is a graph no producer makes. It is rejected rather than
	// partially read: an advertisement is either a name or an address, never
	// both, and a rule that read half of an unrecognized shape would eventually
	// publish the half it guessed at.
	if sawLookup && sawConnection {
		return sweep{}
	}

	s.wellFormed = true
	return s
}

// readConnection collects one TCP node and the handshake beneath it, if any.
//
// It returns false for a shape the transport chain does not produce: a node the
// graph does not hold, a child of the advertisement's transport level that is
// not a connection, a child of a connection that is not a handshake, or more
// than one handshake under one connection. Each would leave the rule guessing
// what it was looking at, and a guess is the one thing a rule may not make.
func (s *sweep) readConnection(g domain.Graph, connectionID domain.EvidenceID) bool {
	connection, ok := g.Node(connectionID)
	if !ok || connection.Layer() != domain.LayerTCP {
		return false
	}
	s.nodes = append(s.nodes, connection)

	path := transportPath{tcp: connection}
	for _, handshakeID := range g.Children(connectionID) {
		handshake, ok := g.Node(handshakeID)
		if !ok || handshake.Layer() != domain.LayerTLS || path.hasTLS {
			return false
		}
		path.handshake = handshake
		path.hasTLS = true
		s.nodes = append(s.nodes, handshake)
	}
	s.paths = append(s.paths, path)
	return true
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

// reachability is what a sweep can truthfully say about the transport the run
// required, and it exists so that the one thing the graph cannot know is
// unrepresentable rather than merely undocumented.
//
// A sweep whose lookup produced no address mints no TCP node and therefore no
// TLS node, so **its plan is unknowable** (ADR 0034 section 4). Only the
// resolving shape can reach that state: an advertisement that named an address
// always mints a connection node, so `measured` false still implies a lookup and
// the prose below may still name one. The verdict does
// not need it — nothing was reachable at L1 either way — but user-facing prose
// does, and naming a layer there would state a fact the evidence does not carry:
// a sweep that never resolved may well have required TLS. `measured` false means
// `terminal` must not be read.
type reachability struct {
	terminal domain.Layer
	measured bool
}

// reachabilityOf reads the sweep's transport requirement off its own shape.
func (s sweep) reachabilityOf() reachability {
	if len(s.paths) == 0 {
		return reachability{}
	}
	if s.terminalIsTLS() {
		return reachability{terminal: domain.LayerTLS, measured: true}
	}
	return reachability{terminal: domain.LayerTCP, measured: true}
}

// describe renders the sweep's transport outcome as a clause.
//
// The wording distinguishes two things the earlier phrasing ran together:
// *arriving at* a layer and *completing* it. "no path reached L2" beside a
// summary naming L2 as the failing layer reads as a contradiction, and on a
// sweep that resolved nothing it also asserted a terminal layer nobody can know.
// Both forms below are true of exactly the graphs that produce them.
func (r reachability) describe() string {
	if !r.measured {
		return "no transport path to it could be measured: the advertised hostname " +
			"yielded no address to connect to"
	}
	return "no measured path to it completed " + r.terminal.String() + " (" + r.terminal.Label() + ")"
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
