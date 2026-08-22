package terminal

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// path is one concrete connection attempt and everything measured over it.
type path struct {
	// subject is the concrete endpoint the attempt reached, taken from the
	// connection node.
	subject domain.Subject

	// stages holds the evidence for each journey step present on this path.
	stages map[domain.Step]domain.Evidence

	// extra holds nodes below this path whose step the journey does not name,
	// so a stage added later still appears rather than vanishing.
	extra []domain.Evidence

	// continued reports that this path carried on past discovery.
	//
	// **Positive evidence only.** See collectPaths.
	continued bool
}

// collectPaths groups the graph into the concrete attempts it recorded.
//
// # The grouping is structural
//
// A path is a `tcp.connect` node and its descendants, walked through
// Graph.Children. Nothing here parses an EvidenceID, matches on a subject
// string, or assumes which stage follows which — the edges the producers wrote
// are the grouping, which is why the in-band TLS handshake lands under the
// negotiation that caused it without this file knowing that it should.
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
// A path is marked continued when it actually has an authentication or session
// node — that is svcdoctor having carried on past discovery, recorded as
// evidence. It is never inferred from *other* paths lacking children, from
// sorting first, from the address family or from timing. ADR 0041 continues
// exactly one path, so on an ordinary multi-path run the others simply carry no
// marker, which is the truthful thing to show: they were measured, and nothing
// about them failed merely because the run went elsewhere.
func collectPaths(g domain.Graph) []path {
	var out []path

	for _, node := range g.Nodes() {
		if node.Step() != vocabulary.StepTCPConnect {
			continue
		}

		p := path{subject: node.Subject(), stages: map[domain.Step]domain.Evidence{}}
		p.stages[vocabulary.StepTCPConnect] = node

		for _, descendant := range descendants(g, node.ID()) {
			step := descendant.Step()
			if _, named := labels[step]; named && step != vocabulary.StepTCPConnect {
				// One node per journey step per path. A second would be a shape
				// no producer makes; keeping the first keeps this total.
				if _, seen := p.stages[step]; !seen {
					p.stages[step] = descendant
					continue
				}
			}
			if _, named := labels[step]; !named {
				p.extra = append(p.extra, descendant)
			}
		}

		_, hasAuth := p.stages[servicepostgres.StepAuthentication]
		_, hasSession := p.stages[servicepostgres.StepSession]
		p.continued = hasAuth || hasSession

		out = append(out, p)
	}

	return out
}

// descendants walks a node's subtree in canonical order.
//
// Breadth-first from the node's own children, so a stage's evidence is reached
// through the edges its producer recorded rather than by guessing at depth.
// Graph.Children returns canonical order, and the visited set keeps a graph that
// is a DAG rather than a tree from producing a node twice.
func descendants(g domain.Graph, root domain.EvidenceID) []domain.Evidence {
	var out []domain.Evidence
	seen := map[domain.EvidenceID]bool{root: true}
	queue := g.Children(root)

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
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
// nothing was attempted — and leaves *why* to the startup node's own
// `postgres.auth_method` attribute and to the findings, which are the authority
// for cause. In particular this never says "missing credential": that claim
// belongs to POSTGRES_CREDENTIAL_NOT_CONFIGURED, which fires on an explicit
// SKIPPED node, and inferring it from absence is exactly what ADR 0046 removed.
//
// # The note is the failure class, verbatim
//
// A non-passing node shows its `FailureClass` as recorded — `EXEC_LOCAL_TIMEOUT`,
// `TLS_UNKNOWN_AUTHORITY`, `AUTH_CREDENTIALS_REJECTED`. Translating those into
// prose here would be a second, unreviewed vocabulary competing with the
// findings, and the class is already the word a reader can search for and match
// against the JSON. It also cannot overstate: `EXEC_LOCAL_TIMEOUT` says the
// budget ended, where "the endpoint timed out" would blame the peer.
func stageLines(p path) []stageLine {
	var out []stageLine
	seenPass := true

	for i, step := range journey {
		node, ok := p.stages[step]
		if ok {
			out = append(out, stageLine{
				state:    stateGlyph(node.State()),
				label:    stepLabel(step),
				note:     failureNote(node),
				duration: formatDuration(node.Duration()),
			})
			seenPass = node.State() == domain.StatePass
			continue
		}

		out = append(out, stageLine{
			// A marker without a state word: there is no state, because there is
			// no node. The note carries the whole meaning.
			state: "·",
			label: stepLabel(step),
			note:  absenceNote(p, i, seenPass),
		})
	}

	// Anything the journey does not name still appears, after the named stages,
	// so a step added later is visible rather than silently dropped.
	for _, node := range p.extra {
		out = append(out, stageLine{
			state:    stateGlyph(node.State()),
			label:    stepLabel(node.Step()),
			note:     failureNote(node),
			duration: formatDuration(node.Duration()),
		})
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
func absenceNote(p path, index int, previousPassed bool) string {
	if !previousPassed {
		return "not reached"
	}
	for _, later := range journey[index+1:] {
		if _, ok := p.stages[later]; ok {
			return "not attempted"
		}
	}
	return "not attempted on this path"
}

// sessionEstablished reports whether any path reached ReadyForQuery.
//
// # It reads the one node that proves it, and nothing else
//
// A passing `postgres.session` node is the only evidence that a PostgreSQL
// session was established. Not the summary status, which means "no target-side
// error was proven" and is `OK` on a run that never authenticated. Not the
// absence of findings, which is `OK` for the same reason. Not a passing startup
// or authentication, because `AuthenticationOk` is not success — `3D000` and
// `42501` arrive after it and before `ReadyForQuery`, which is why ADR 0039 made
// this node the boundary in the first place.
func sessionEstablished(g domain.Graph) bool {
	for _, node := range g.Nodes() {
		if node.Step() == servicepostgres.StepSession && node.State() == domain.StatePass {
			return true
		}
	}
	return false
}

// targetStages returns the nodes that belong to the logical target rather than
// to one concrete path — today the anchor and the lookup.
func targetStages(g domain.Graph) []domain.Evidence {
	var out []domain.Evidence
	for _, node := range g.Nodes() {
		if node.Step() == vocabulary.StepDNSLookup {
			out = append(out, node)
		}
	}
	return out
}
