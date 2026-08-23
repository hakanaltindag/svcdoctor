package app

import (
	"context"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// incompleteKafkaRun reports that svcdoctor's own execution limit stopped this
// run short of the work it promised to do.
//
// It implements ADR 0051 section 4, and it is the Kafka counterpart of
// incompleteRun rather than a variation on it. The difference is a scope
// difference, not a protocol one.
//
// # Why Kafka has no `established` clause
//
// PostgreSQL's predicate short-circuits on a passing session: the run achieved
// its terminal purpose, and an unfinished alternate path was never the point.
// **Kafka BASIC promises two things**, a client journey to the bootstrap
// endpoint ending at `kafka.metadata`, and a transport assessment of every
// endpoint the cluster advertised. Both Kafka findings live in the second, so
// letting `kafka.metadata` PASS settle completeness would silently drop half the
// command and report a run that measured a third of the topology as complete
// (ADR 0051 section 1).
//
// # PASS is existential; FAIL is universal
//
// This asymmetry is the whole rule, and inverting it is the mistake ADR 0051's
// first draft made and its security review caught.
//
// The claim an advertised sweep supports is *"this endpoint was not reachable
// from this vantage"*, which is a universally quantified negative: it is true
// only when every selectable path was tried and none succeeded. So one PASS
// resolves an advertisement outright — reachability is existential and no
// further measurement can overturn a working path — while a FAIL resolves it
// only when nothing was left unmeasured. One address refused beside one address
// never measured does **not** prove the endpoint unreachable, because a client
// selecting the unmeasured address might have connected.
//
// It is the same rule ADR 0043 already applies to TCP.
//
// # The resolution unit is the advertisement, not the address
//
// An advertisement is resolved when the run learned whether that endpoint was
// reachable, and unresolved when svcdoctor's own budget stopped the measurement
// before that could be known. A per-address UNKNOWN beneath an advertisement a
// PASS already resolved does not count (ADR 0051 section 3).
//
// # What it reads, and what it must never read
//
// Graph accessors only: Nodes, Children, Step, State and FailureClass. No
// identifier parsing, no provenance, no execution scope, no subject matching, no
// hidden side table and no schema field. Everything it needs is an edge the
// producers already recorded.
func incompleteKafkaRun(ctx context.Context, graph domain.Graph) bool {
	if ctx.Err() != nil {
		// Cancellation, or the whole-run budget. Unconditional: nothing the
		// graph says can make a run that was cut short a finished one.
		return true
	}

	metadata, obtained := metadataNode(graph)
	if !obtained || metadata.State() != domain.StatePass {
		// The core journey did not finish, so there is no promised topology work
		// to enumerate. Fall back to ADR 0047's scan: an UNKNOWN carrying a local
		// class means svcdoctor stopped, not that the target failed.
		return anyUnknownExec(graph)
	}

	// Metadata was obtained, so every advertisement the run promised to measure
	// is nameable and each one needs a verdict.
	for _, node := range graph.Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		if node.State() != domain.StatePass {
			// An advertisement the cluster could not state usably is itself a
			// verdict: no sweep runs for it, and none was promised. The unusable
			// advertisement rule owns what it means.
			continue
		}
		if !advertisementResolved(graph, node.ID()) {
			return true
		}
	}
	return false
}

// metadataNode returns the run's `kafka.metadata` exchange node.
//
// A Kafka BASIC run performs at most one Metadata exchange, because it
// authenticates at most one path and Metadata consumes an authenticated session.
// The first match is therefore the only match; scanning for a second would
// suggest this predicate has a policy about a shape the composition cannot
// produce.
func metadataNode(graph domain.Graph) (domain.Evidence, bool) {
	for _, node := range graph.Nodes() {
		if node.Step() == servicekafka.StepMetadata {
			return node, true
		}
	}
	return domain.Evidence{}, false
}

// advertisementResolved reports whether the run learned if one advertised
// endpoint was reachable.
//
// It walks down from the advertisement through the shape
// `kafka.MeasureAdvertised` produces, and it answers false for every shape it
// does not recognize — an absent sweep, a lookup that never finished, a resolved
// name nothing was attempted against. **Unrecognized means unresolved, never
// resolved.** The failure this predicate exists to prevent is a run reporting
// itself finished when it is not, so the direction it errs in is the one that
// says so.
func advertisementResolved(graph domain.Graph, advertisement domain.EvidenceID) bool {
	lookup, ok := singleChild(graph, advertisement, vocabulary.StepDNSLookup)
	if !ok {
		// The budget stopped the run before this advertisement's sweep began.
		// Nothing about the endpoint was measured, and the advertisement node
		// alone claims nothing about reachability.
		return false
	}
	if unknownLocal(lookup) {
		return false
	}
	if lookup.State() == domain.StateFail {
		// Resolution produced nothing to connect to, which is a complete
		// negative on its own: there is no address a client could have selected
		// instead. The chain mints no TCP node under such a lookup, so there is
		// nothing further to inspect.
		return true
	}

	connections := children(graph, lookup.ID(), vocabulary.StepTCPConnect)
	if len(connections) == 0 {
		// The name resolved and nothing was attempted against it. That is not a
		// negative anybody proved.
		return false
	}

	paths := make([]transportPath, 0, len(connections))
	for _, connection := range connections {
		path, wellFormed := readPath(graph, connection)
		if !wellFormed {
			return false
		}
		paths = append(paths, path)
	}

	// Existential. One usable path resolves the advertisement outright, whatever
	// happened on its siblings.
	for _, path := range paths {
		if path.reachedTransport() {
			return true
		}
	}

	// No usable path, so the run is about to conclude a universal negative. It
	// may do so only if nothing was left unmeasured — on the connection itself,
	// or on the handshake the plan required over it.
	for _, path := range paths {
		if unknownLocal(path.connection) {
			return false
		}
		if path.requiresTLS && unknownLocal(path.handshake) {
			return false
		}
	}

	// Every path terminated in a positively observed failure. The negative is
	// complete.
	return true
}

// transportPath is one measured address, with the handshake the plan required
// over it when there was one.
type transportPath struct {
	connection domain.Evidence

	// handshake is meaningful only when requiresTLS is true.
	handshake   domain.Evidence
	requiresTLS bool
}

// readPath reads one connection and the handshake beneath it, and reports
// whether the shape is one `kafka.MeasureAdvertised` produces.
//
// **Absent and unrecognized are different, and conflating them is a real
// defect.** Zero handshakes means the plan was plaintext, so a passing
// connection is transport success. Two handshakes under one connection is a
// shape the chain cannot produce, and reading it as "no TLS plan" would turn an
// incomprehensible graph into a reachability claim — the opposite of the
// direction this predicate is required to err in.
func readPath(graph domain.Graph, connection domain.Evidence) (transportPath, bool) {
	handshakes := children(graph, connection.ID(), vocabulary.StepTLSHandshake)
	switch len(handshakes) {
	case 0:
		return transportPath{connection: connection}, true
	case 1:
		return transportPath{
			connection: connection, handshake: handshakes[0], requiresTLS: true,
		}, true
	default:
		return transportPath{}, false
	}
}

// reachedTransport reports whether this address completed the transport the run
// required.
//
// **TLS is part of transport success when the plan asked for it**, and the plan
// is read off the graph rather than passed in. The advertised sweep mints a
// `tls.handshake` node under every TCP node if and only if TLS was required
// (ADR 0034 section 4), so a handshake's presence is the plan and its absence is
// the plan too. A TCP PASS followed by a TLS FAIL is not transport success, and
// a TCP PASS followed by a TLS UNKNOWN-local leaves the path unresolved rather
// than reached.
//
// It is the same predicate ADR 0052's `topology` line counts with, so the count
// and the completeness rule cannot come to disagree.
func (p transportPath) reachedTransport() bool {
	if p.connection.State() != domain.StatePass {
		return false
	}
	if !p.requiresTLS {
		return true
	}
	return p.handshake.State() == domain.StatePass
}

// unknownLocal reports whether a node records svcdoctor stopping rather than the
// target answering.
//
// SKIPPED is deliberately excluded. A SKIPPED node under a sweep carries
// EXEC_SKIPPED_PREREQUISITE_FAILED and is a downstream restatement of a failure
// its blocker already owns, or it carries a local class because the caller's
// context was already done — and that case is caught by the first clause of
// incompleteKafkaRun, so counting it here would say nothing new.
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

// anyUnknownExec is ADR 0047's scan, reused verbatim in meaning.
//
// It is the fallback for a run whose core journey did not reach Metadata: with
// no topology to enumerate, the only question left is whether some step that was
// entered ended undetermined because svcdoctor's own budget expired.
func anyUnknownExec(graph domain.Graph) bool {
	for _, node := range graph.Nodes() {
		if unknownLocal(node) {
			return true
		}
	}
	return false
}

// children returns every child of a node that records the given step.
func children(graph domain.Graph, parent domain.EvidenceID, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, id := range graph.Children(parent) {
		node, ok := graph.Node(id)
		if !ok || node.Step() != step {
			continue
		}
		out = append(out, node)
	}
	return out
}

// singleChild returns the one child recording the given step, and whether there
// was exactly one.
//
// Exactly one, rather than the first of several. The shapes this predicate reads
// have a single lookup per advertisement and a single handshake per connection,
// and a graph with two of either is one this function does not recognize —
// which, per advertisementResolved's rule, must read as unresolved rather than
// as a verdict picked from whichever node happened to sort first.
func singleChild(
	graph domain.Graph, parent domain.EvidenceID, step domain.Step,
) (domain.Evidence, bool) {
	matches := children(graph, parent, step)
	if len(matches) != 1 {
		return domain.Evidence{}, false
	}
	return matches[0], true
}
