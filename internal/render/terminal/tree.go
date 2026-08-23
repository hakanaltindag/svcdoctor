package terminal

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// path is one concrete connection attempt and everything measured over it.
type path struct {
	// subject is the concrete endpoint the attempt reached, taken from the
	// connection node.
	subject domain.Subject

	// stages holds the evidence for each journey step present on this path.
	stages map[domain.Step]domain.Evidence

	// ordered holds every node of this path in canonical order, the connection
	// first. It is what makes the renderer total: whatever the journey does not
	// place is still shown, in the order the graph recorded it.
	ordered []domain.Evidence

	// continued reports that this path carried on past discovery.
	//
	// **Positive evidence only.** See collectPaths.
	continued bool
}

// advertisement is one discovered endpoint and the transport measured for it.
type advertisement struct {
	// node is the advertisement itself: what the cluster said, and whether it
	// said something usable.
	node domain.Evidence

	// lookup is the resolution of the advertised name, when a sweep ran.
	lookup   domain.Evidence
	resolved bool

	// paths are the concrete addresses the sweep measured.
	paths []path
}

// collectPaths groups the graph into the concrete bootstrap attempts it
// recorded.
//
// # The grouping is structural
//
// A path is a `tcp.connect` node and its descendants, walked through
// Graph.Children. Nothing here parses an EvidenceID, matches on a subject
// string, or assumes which stage follows which — the edges the producers wrote
// are the grouping, which is why the in-band TLS handshake lands under the
// negotiation that caused it without this file knowing that it should.
//
// # Why the advertisement boundary exists
//
// Before Kafka, every `tcp.connect` in a graph belonged to the endpoint the
// operator named, and promoting all of them was right. A Kafka graph has a
// second population: `kafka.MeasureAdvertised` mints a `dns.lookup` and its
// `tcp.connect` nodes beneath every `kafka.broker_advertised` node. Promoting
// those alongside the bootstrap paths would present a broker the cluster named
// as though the operator had named it, and `descendants` would *simultaneously*
// pull the same subtree into a bootstrap path's `extra` list — so one measured
// endpoint would be rendered twice, in two different meanings (ADR 0052 §5).
//
// So the advertisement step is a boundary in both directions: a connection at or
// below one is not a bootstrap path, and a bootstrap path's descendants stop
// there. A service with no advertisement step has no boundary and behaves
// exactly as before.
//
// # Canonical order comes free
//
// Graph.Nodes returns canonical order, so iterating it and keeping the
// connection nodes yields paths in that order. There is no address-family rule
// here, no sort by duration and no "the one that worked goes first": each of
// those would be the renderer inventing a ranking the report does not have.
//
// # `continued` is asserted, never inferred from absence
//
// A path is marked continued when it actually holds a node past the point where
// the run narrows to one — that is svcdoctor having carried on, recorded as
// evidence. It is never inferred from *other* paths lacking children, from
// sorting first, from the address family, from timing, or from which path holds
// a credential. ADR 0028 and ADR 0041 continue exactly one path, so on an
// ordinary multi-path run the others simply carry no marker, which is the
// truthful thing to show: they were measured, and nothing about them failed
// merely because the run went elsewhere.
func collectPaths(g domain.Graph, view serviceView) []path {
	blocked := advertisedSubtree(g, view)

	var out []path
	for _, node := range g.Nodes() {
		if node.Step() != vocabulary.StepTCPConnect || blocked[node.ID()] {
			continue
		}
		out = append(out, readPath(g, node, view, blocked))
	}
	return out
}

// collectAdvertisements groups the topology level of the graph.
//
// It returns nothing for a service with no advertisement step, and nothing for a
// run that recorded no advertisements — which is also how the topology line and
// the topology section decide to stay silent rather than print an empty heading.
func collectAdvertisements(g domain.Graph, view serviceView) []advertisement {
	if view.advertisementStep == "" {
		return nil
	}

	var out []advertisement
	for _, node := range g.Nodes() {
		if node.Step() != view.advertisementStep {
			continue
		}
		a := advertisement{node: node}
		// Exactly one lookup, never the first of several. The sweep mints one
		// per advertisement; two is a shape this renderer does not recognize,
		// and picking one would present an arbitrary half of the evidence.
		if lookups := childrenWithStep(g, node.ID(), vocabulary.StepDNSLookup); len(lookups) == 1 {
			a.lookup, a.resolved = lookups[0], true
			for _, connection := range childrenWithStep(g, a.lookup.ID(), vocabulary.StepTCPConnect) {
				a.paths = append(a.paths, readPath(g, connection, advertisedView(view), nil))
			}
		}
		out = append(out, a)
	}
	return out
}

// advertisedView is the service view a discovered endpoint's path renders under.
//
// The journey narrows to transport, and every other field is dropped: an
// advertisement has no outcome to restate, no narrowing point — the run
// continues nothing past it — and no topology of its own.
func advertisedView(view serviceView) serviceView {
	return serviceView{journey: view.advertisedJourney}
}

// readPath assembles one connection node and the stages recorded beneath it.
func readPath(
	g domain.Graph, connection domain.Evidence, view serviceView,
	stop map[domain.EvidenceID]bool,
) path {
	p := path{subject: connection.Subject(), stages: map[domain.Step]domain.Evidence{}}
	p.ordered = append([]domain.Evidence{connection}, descendants(g, connection.ID(), stop)...)

	for _, node := range p.ordered {
		// One node per step per path. A second would be a shape no producer
		// makes; keeping the first keeps this total, and the second still
		// appears through `ordered`.
		if _, seen := p.stages[node.Step()]; !seen {
			p.stages[node.Step()] = node
		}
	}

	p.continued = pathContinued(p, view)
	return p
}

// pathContinued reports whether this path holds a stage only the continued path
// can hold.
//
// # It is asserted from evidence, never inferred from a credential
//
// A run that presents no credential still continues exactly one path, records a
// truthful unattempted-authentication node on it, and that path is the one that
// carried on. Reading selection off "which path holds the secret" would leave
// that run with no marked path at all — and would put the credential in a
// renderer's reasoning, which is the one place it must never be.
//
// The steps that qualify come from the service table rather than from a rule
// derived here, because "the stages only one path reaches" is a property of each
// service's journey and ADR 0028 and ADR 0041 are what fixed it.
func pathContinued(p path, view serviceView) bool {
	for _, step := range view.narrowingSteps {
		if _, ok := p.stages[step]; ok {
			return true
		}
	}
	return false
}

// advertisedSubtree returns every node at or below an advertisement.
//
// It is computed once per report and consulted twice: to keep discovered
// connections out of the bootstrap path list, and to stop a bootstrap path's
// descendant walk at the boundary. Both readings need the same set, and
// computing it twice would let them disagree.
func advertisedSubtree(g domain.Graph, view serviceView) map[domain.EvidenceID]bool {
	if view.advertisementStep == "" {
		return nil
	}

	blocked := map[domain.EvidenceID]bool{}
	for _, node := range g.Nodes() {
		if node.Step() != view.advertisementStep {
			continue
		}
		blocked[node.ID()] = true
		for _, descendant := range descendants(g, node.ID(), nil) {
			blocked[descendant.ID()] = true
		}
	}
	return blocked
}

// descendants walks a node's subtree in canonical order, stopping at stop.
//
// Breadth-first from the node's own children, so a stage's evidence is reached
// through the edges its producer recorded rather than by guessing at depth.
// Graph.Children returns canonical order, and the visited set keeps a graph that
// is a DAG rather than a tree from producing a node twice.
//
// A node in stop is not visited and is not descended through. That is what makes
// the advertisement boundary hold in the downward direction: without it, a
// bootstrap path would absorb every discovered broker's transport sweep into its
// `extra` list and render it a second time.
func descendants(
	g domain.Graph, root domain.EvidenceID, stop map[domain.EvidenceID]bool,
) []domain.Evidence {
	var out []domain.Evidence
	seen := map[domain.EvidenceID]bool{root: true}
	queue := g.Children(root)

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] || stop[id] {
			continue
		}
		seen[id] = true

		node, ok := g.Node(id)
		if !ok {
			continue
		}
		out = append(out, node)
		queue = append(queue, g.Children(id)...)
	}
	return out
}

// childrenWithStep returns every direct child of a node recording one step.
func childrenWithStep(
	g domain.Graph, parent domain.EvidenceID, step domain.Step,
) []domain.Evidence {
	var out []domain.Evidence
	for _, id := range g.Children(parent) {
		node, ok := g.Node(id)
		if !ok || node.Step() != step {
			continue
		}
		out = append(out, node)
	}
	return out
}

// stageLine is one rendered row of a path.
type stageLine struct {
	// state is the glyph and word, or empty when no node exists.
	state string
	label string
	// note carries the failure class or the absence wording, verbatim.
	note     string
	duration string
}

// stageLines renders one path's journey in product order.
//
// # Absence is not SKIPPED, and the wording says which
//
// A SKIPPED node is svcdoctor recording that it intentionally did not run a step
// and why. An absent node is nothing at all — no measurement, no claim — and
// ADR 0041 relies on that distinction: an unselected path has no authentication
// node because the run continued elsewhere, and a `trust` endpoint has none
// because svcdoctor presented nothing. Rendering the two identically would put a
// claim in the output that no producer made.
//
// So an absent stage gets one of three phrasings, all derived from structure and
// none from a guess about cause:
//
//	an earlier stage did not pass    → "not reached"
//	a later stage on this path exists → "not attempted"
//	neither                          → "not attempted on this path"
//
// The middle case is what a `trust` path looks like: startup passed, no
// authentication happened, and a session followed anyway. It says what is true —
// nothing was attempted — and leaves *why* to the startup node's own attributes
// and to the findings, which are the authority for cause. In particular this
// never says "missing credential" or "wrong password": those claims belong to
// findings, and inferring either from absence is exactly what ADR 0046 removed.
//
// # The note is the failure class, verbatim
//
// A non-passing node shows its `FailureClass` as recorded — `EXEC_LOCAL_TIMEOUT`,
// `TLS_UNKNOWN_AUTHORITY`, `AUTH_CREDENTIALS_REJECTED`. Translating those into
// prose here would be a second, unreviewed vocabulary competing with the
// findings, and the class is already the word a reader can search for and match
// against the JSON. It also cannot overstate: `EXEC_LOCAL_TIMEOUT` says the
// budget ended, where "the endpoint timed out" would blame the peer.
//
// # A path whose service has no journey still renders
//
// Every node the path holds is emitted in canonical order. Nothing is dropped
// because a presentation table did not name the service.
func stageLines(p path, view serviceView) []stageLine {
	var out []stageLine
	seenPass := true

	for i, step := range view.journey {
		node, ok := p.stages[step]
		if ok {
			out = append(out, stageLine{
				state:    stateGlyph(node.State()),
				label:    stepLabel(step),
				note:     failureNote(node),
				duration: formatElapsed(node.Elapsed()),
			})
			seenPass = node.State() == domain.StatePass
			continue
		}

		out = append(out, stageLine{
			// A marker without a state word: there is no state, because there is
			// no node. The note carries the whole meaning.
			state: "·",
			label: stepLabel(step),
			note:  absenceNote(p, view, i, seenPass),
		})
	}

	// Anything the journey does not name still appears, after the named stages,
	// so a step added later is visible rather than silently dropped. For a
	// service with no journey at all, this is the whole path.
	for _, node := range unplacedStages(p, view) {
		out = append(out, stageLine{
			state:    stateGlyph(node.State()),
			label:    stepLabel(node.Step()),
			note:     failureNote(node),
			duration: formatElapsed(node.Elapsed()),
		})
	}

	return out
}

// unplacedStages returns the path's nodes the journey did not render, in
// canonical order.
//
// A step the journey names is placed by stageLines and skipped here. Everything
// else is emitted — a stage added later, a second node of one step, or, for a
// service this renderer has no table for, the whole path. That last case is the
// point: a service arriving before its table renders slightly ugly and
// completely truthful output rather than none.
func unplacedStages(p path, view serviceView) []domain.Evidence {
	placed := make(map[domain.EvidenceID]bool, len(view.journey))
	for _, step := range view.journey {
		if node, ok := p.stages[step]; ok {
			placed[node.ID()] = true
		}
	}

	var out []domain.Evidence
	for _, node := range p.ordered {
		if !placed[node.ID()] {
			out = append(out, node)
		}
	}
	return out
}

// failureNote returns the recorded class, or empty on a passing node.
func failureNote(node domain.Evidence) string {
	if node.State() == domain.StatePass || node.FailureClass() == domain.FailureNone {
		return ""
	}
	return node.FailureClass().String()
}

// absenceNote explains a stage with no evidence, structurally.
func absenceNote(p path, view serviceView, index int, previousPassed bool) string {
	if !previousPassed {
		return "not reached"
	}
	for _, later := range view.journey[index+1:] {
		if _, ok := p.stages[later]; ok {
			return "not attempted"
		}
	}
	return "not attempted on this path"
}

// outcomeReached reports whether the service's terminal node passed.
//
// # It reads the one node that proves it, and nothing else
//
// Not the summary status, which means "no target-side error was proven" and is
// `OK` on a run that never authenticated. Not the absence of findings, which is
// `OK` for the same reason. Not a passing authentication: for PostgreSQL
// `AuthenticationOk` is not success (ADR 0039), and for Kafka a passing
// SaslAuthenticate proves the credential was accepted and says nothing about
// authorization (ADR 0052 section 1).
//
// A service with no outcome step has no outcome to report, and writeResult omits
// the line rather than guessing.
func outcomeReached(g domain.Graph, view serviceView) bool {
	if view.outcomeStep == "" {
		return false
	}
	for _, node := range g.Nodes() {
		if node.Step() == view.outcomeStep && node.State() == domain.StatePass {
			return true
		}
	}
	return false
}

// targetStages returns the nodes that belong to the logical target rather than
// to one concrete path — today the lookup of the requested name.
//
// A discovered endpoint's lookup is excluded, because it is not a resolution of
// what the operator asked about. It is rendered inside its own advertisement.
func targetStages(g domain.Graph, view serviceView) []domain.Evidence {
	blocked := advertisedSubtree(g, view)

	var out []domain.Evidence
	for _, node := range g.Nodes() {
		if node.Step() == vocabulary.StepDNSLookup && !blocked[node.ID()] {
			out = append(out, node)
		}
	}
	return out
}
