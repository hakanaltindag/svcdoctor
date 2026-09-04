package diagnosis

import (
	"cmp"
	"slices"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Shared graph queries.
//
// Four, and no more. Each names the diagnostic scenario that requires it, and
// the ones that were considered and left out are named at the bottom of this
// file. A query with no caller is a guess about what reasoning will need, and
// this project has an explicit rule against speculative machinery.
//
// Every query in this file shares four properties, stated once here rather than
// repeated four times:
//
//   - **Cycles.** domain.Graph is a DAG by construction — GraphBuilder.Freeze
//     rejects a cycle — but every traversal below still carries a visited set.
//     A traversal whose termination depends on a *caller's* invariant is a hang
//     waiting for a bug elsewhere, and the fuzz targets drive these against
//     malformed structures on purpose.
//   - **Not measured.** No query treats UNKNOWN or SKIPPED as either PASS or
//     FAIL. Where a query counts outcomes it counts "not measured" as its own
//     category, because collapsing it into "not reached" is the error that
//     produces a stronger claim from less evidence.
//   - **Ordering.** Every result is in a total, content-derived order. Nothing
//     derives from map iteration, insertion order, or the order endpoints
//     happened to be discovered.
//   - **Complexity.** Every query is linear in the nodes and edges it visits.
//     None is quadratic, none is combinatorial, and none allocates per node pair.

// NodesForSubject returns the evidence about one subject, in layer order.
//
// Scenario: the failure boundary. "Where did observation stop succeeding for
// this endpoint" is a question about one subject's own chain, and the graph
// stores subjects on nodes rather than as an index, so this is the lookup.
//
// Ordering is (Layer, Step, EvidenceID). Layer is the ordering the domain
// already owns and documents — L0 through L6, with the comment on domain.Layer
// stating that first-broken-layer reporting depends on it — and Step then
// EvidenceID make it total when one subject has several nodes at one layer,
// which a multi-address endpoint does.
//
// Complexity: O(n log n) in the graph's node count, dominated by the sort.
func NodesForSubject(g domain.Graph, subject domain.Subject) []domain.Evidence {
	if subject.IsZero() {
		return nil
	}

	var out []domain.Evidence
	for _, node := range g.Nodes() {
		if node.Subject() == subject {
			out = append(out, node)
		}
	}
	sortByLayer(out)
	return out
}

// Subjects returns every subject the graph carries, in canonical order.
//
// Scenario: the failure boundary is per subject and never per run (ADR 0079
// section 2.2), so producing boundaries means enumerating subjects. A run with a
// healthy bootstrap and one unreachable discovered endpoint has two boundaries,
// and merging them would produce the false summary that record exists to
// prevent.
//
// Ordering is (SubjectKind, Ref). Complexity: O(n log n).
func Subjects(g domain.Graph) []domain.Subject {
	var out []domain.Subject
	for _, node := range g.Nodes() {
		subject := node.Subject()
		if subject.IsZero() || slices.Contains(out, subject) {
			continue
		}
		out = append(out, subject)
	}
	slices.SortFunc(out, compareSubjects)
	return out
}

// BlockedChain returns every node that did not run because of id, transitively.
//
// Scenario: the failure boundary again, and the claim discipline around it. When
// TCP fails, the TLS step below it is SKIPPED and the graph records why. A
// reader needs to know those steps were *not measured* rather than that they
// failed, and a rule needs to know it may not read them in either direction
// (ADR 0081 section 2.4). This is how both find them.
//
// It walks the recorded blocked-by relation, never derives one. Deciding that a
// DNS failure should block a TCP attempt is an execution decision made
// elsewhere; this reads the decision.
//
// The result excludes id itself. Ordering is EvidenceID lexical. Complexity:
// O(n + e) over the blocked-by relation, with a visited set.
func BlockedChain(g domain.Graph, id domain.EvidenceID) []domain.EvidenceID {
	// The relation is stored child-to-blocker, so reaching the descendants means
	// inverting it once rather than rescanning the graph per hop.
	blocks := map[domain.EvidenceID][]domain.EvidenceID{}
	for _, node := range g.Nodes() {
		for _, blocker := range g.BlockedBy(node.ID()) {
			blocks[blocker] = append(blocks[blocker], node.ID())
		}
	}

	visited := map[domain.EvidenceID]struct{}{id: {}}
	var out []domain.EvidenceID
	queue := []domain.EvidenceID{id}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, blocked := range blocks[current] {
			if _, seen := visited[blocked]; seen {
				continue
			}
			visited[blocked] = struct{}{}
			out = append(out, blocked)
			queue = append(queue, blocked)
		}
	}

	slices.Sort(out)
	return out
}

// SiblingOutcome counts what happened to the subjects reached from one node.
//
// Scenario: ADR 0079 section 2.6. "One of three brokers is unreachable" and "all
// three are" are materially different diagnoses, and the generic engine must be
// able to express the difference **without knowing what a broker is**. The
// generic notion is *child subjects of one node*, and the graph already carries
// it, because discovered endpoints are children of the node that discovered
// them.
//
// The counting is generic and stays generic. What "two of three reachable" means
// for a protocol is the service rule's business; this only counts.
//
// # The three categories are three, not two
//
// Passed, failed and not measured. A subject that was never attempted is not a
// subject that failed, and a run whose budget expired before two endpoints were
// tried must not produce "all endpoints unreachable". That collapse is the
// defect this project names explicitly, and keeping the third category is what
// makes it unavailable.
//
// A child subject with several nodes is classified by the worst outcome it
// recorded: any FAIL or DEGRADED makes it failed, otherwise any UNKNOWN or
// SKIPPED makes it not measured, otherwise it passed. That ordering is
// deliberate — a subject with one failure and one pass is not half-healthy.
//
// Complexity: O(c log c) in the number of children of id.
func SiblingOutcome(g domain.Graph, id domain.EvidenceID) SiblingCounts {
	var counts SiblingCounts

	bySubject := map[domain.Subject][]domain.Evidence{}
	var subjects []domain.Subject
	for _, child := range g.Children(id) {
		node, ok := g.Node(child)
		if !ok || node.Subject().IsZero() {
			continue
		}
		if _, seen := bySubject[node.Subject()]; !seen {
			subjects = append(subjects, node.Subject())
		}
		bySubject[node.Subject()] = append(bySubject[node.Subject()], node)
	}
	slices.SortFunc(subjects, compareSubjects)

	for _, subject := range subjects {
		switch classifySubject(bySubject[subject]) {
		case domain.StateFail:
			counts.failed = append(counts.failed, subject)
		case domain.StatePass:
			counts.passed = append(counts.passed, subject)
		default:
			counts.notMeasured = append(counts.notMeasured, subject)
		}
	}
	return counts
}

// classifySubject reduces one subject's nodes to a single outcome.
//
// It returns StateFail, StatePass, or StateUnknown standing for "not measured".
// DEGRADED folds into failed because ADR 0079 section 2.2 makes it one half of a
// failure boundary; nothing here needs to tell the two apart, and a fourth
// category with no consumer would be a distinction nobody reads.
func classifySubject(nodes []domain.Evidence) domain.State {
	sawPass := false
	for _, node := range nodes {
		switch node.State() {
		case domain.StateFail, domain.StateDegraded:
			return domain.StateFail
		case domain.StatePass:
			sawPass = true
		case domain.StateUnknown, domain.StateSkipped:
		}
	}
	for _, node := range nodes {
		if node.State() == domain.StateUnknown || node.State() == domain.StateSkipped {
			return domain.StateUnknown
		}
	}
	if sawPass {
		return domain.StatePass
	}
	return domain.StateUnknown
}

// SiblingCounts is what SiblingOutcome found.
//
// It holds subjects rather than integers so that a rule can cite what it counted.
// A claim about "one of three" that cannot name which one is a claim a reader
// cannot check.
//
// The zero SiblingCounts is valid and describes a node with no child subjects.
type SiblingCounts struct {
	passed      []domain.Subject
	failed      []domain.Subject
	notMeasured []domain.Subject
}

// Passed returns the child subjects whose evidence is entirely positive.
func (c SiblingCounts) Passed() []domain.Subject { return cloneSubjects(c.passed) }

// Failed returns the child subjects with at least one FAIL or DEGRADED node.
func (c SiblingCounts) Failed() []domain.Subject { return cloneSubjects(c.failed) }

// NotMeasured returns the child subjects that were attempted but reached no
// conclusion, and the ones never attempted at all.
//
// It is never merged into Failed. "Not measured" and "not reached" are two
// claims, and the second is stronger (ADR 0052).
func (c SiblingCounts) NotMeasured() []domain.Subject { return cloneSubjects(c.notMeasured) }

// Total returns how many child subjects were classified.
func (c SiblingCounts) Total() int {
	return len(c.passed) + len(c.failed) + len(c.notMeasured)
}

// sortByLayer orders evidence by (Layer, Step, EvidenceID).
func sortByLayer(nodes []domain.Evidence) {
	slices.SortFunc(nodes, func(a, b domain.Evidence) int {
		if c := cmp.Compare(a.Layer(), b.Layer()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Step(), b.Step()); c != 0 {
			return c
		}
		return cmp.Compare(a.ID(), b.ID())
	})
}

// compareSubjects orders subjects by (Kind, Ref).
func compareSubjects(a, b domain.Subject) int {
	if c := cmp.Compare(a.Kind(), b.Kind()); c != 0 {
		return c
	}
	return cmp.Compare(a.Ref(), b.Ref())
}

func cloneSubjects(in []domain.Subject) []domain.Subject {
	if len(in) == 0 {
		return nil
	}
	return slices.Clone(in)
}

// Queries considered and deliberately absent
//
// **Ancestors and descendants over parent edges.** Nothing in Phase 10.1a needs
// them: the boundary walks one subject's own nodes, and sibling comparison needs
// one hop. A general reachability walk would arrive with no caller to shape it,
// and the shape matters — "ancestors" over a DAG is a set, not a path, and which
// of several paths a rule meant is exactly the question a caller answers.
//
// **Last confirmed-good and first failing as standalone queries.** They exist,
// but as Boundary's two halves rather than as loose functions, because either
// one alone is not a boundary: ADR 0079 section 2.3 requires both to be cited,
// and a helper returning one invites a claim resting on half a contrast.
//
// **Branch divergence.** ADR 0079 section 2.5 lists divergent siblings as a
// boundary shape, and SiblingOutcome answers it by counting. A separate
// "divergence" query would have to decide what divergence *means*, which is a
// service judgement and not a graph fact.
