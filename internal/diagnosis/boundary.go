package diagnosis

import (
	"slices"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Boundary is where observation stopped succeeding, for one subject.
//
// It is the derived diagnostic property ADR 0079 defines, computed in the
// diagnosis layer and nowhere else. It is not a domain field, not a Graph API,
// and not something a renderer works out for itself — a renderer that computed a
// boundary would be reasoning, and two renderers would then hold two
// implementations of one conclusion.
//
// # It is internal in Phase 10.1a
//
// ADR 0079 section 2.3 expresses the boundary as a generic finding,
// DIAG_FAILURE_BOUNDARY, and ADR 0078 section 3 authorizes the finding-code
// count to move 60 to 61 "in the phase that implements it". That phase is 10.1b:
// docs/design/DIAGNOSTIC_INTELLIGENCE.md section P splits 10.1 into a half that
// changes no report and a half that does, and puts the boundary finding in the
// second. So this computes the boundary, is tested against all six shapes ADR
// 0079 section 2.5 requires, and emits nothing. The finding-code count is still
// 60.
//
// There is no conceptual circularity to resolve, which was worth checking before
// building it: a boundary is derived from **evidence**, never from findings.
// Nothing here reads a Finding, and no hypothesis is derived from another
// hypothesis (docs/design/DIAGNOSTIC_INTELLIGENCE.md section L). The chain stays
// evidence to boundary to finding, in one direction.
//
// # What it claims
//
// Where observation stopped succeeding, and nothing about why. "The failure is
// at TLS for this endpoint" is a contrast between two measured facts. "Therefore
// the certificate is wrong" is a hypothesis and belongs to a rule.
//
// The zero Boundary is invalid; Boundaries never returns one.
type Boundary struct {
	subject      domain.Subject
	lastGood     domain.EvidenceID
	firstFailure domain.EvidenceID
	blocked      []domain.EvidenceID
	notMeasured  []domain.EvidenceID
}

// Subject returns what the boundary is about. It is always set.
func (b Boundary) Subject() domain.Subject { return b.subject }

// LastConfirmedGood returns the deepest layer that passed before the failure,
// and whether there was one.
//
// There is none when the very first thing measured for this subject failed. That
// is a real shape and is reported as an absence rather than as a weaker
// boundary: saying "everything up to X worked" when nothing did would be the
// stronger claim from less evidence.
func (b Boundary) LastConfirmedGood() (domain.EvidenceID, bool) {
	return b.lastGood, b.lastGood != ""
}

// FirstEvidencedFailure returns the shallowest layer that failed.
//
// A Boundary always has one; it is what makes it a boundary. A subject whose
// evidence contains no FAIL and no DEGRADED has no boundary at all, and
// Boundaries returns none for it.
func (b Boundary) FirstEvidencedFailure() domain.EvidenceID { return b.firstFailure }

// Blocked returns the steps that did not run because of the failure.
//
// They are neither broken nor healthy. No rule may read them as evidence in
// either direction (ADR 0081 section 2.4), and none of them is ever the first
// failure — a blocked step is SKIPPED, and SKIPPED is not a failure.
func (b Boundary) Blocked() []domain.EvidenceID { return cloneIDs(b.blocked) }

// NotMeasured returns this subject's own steps that reached no conclusion.
//
// It includes both the ones a local budget cut short and the ones policy
// declined to run. They are recorded so that a reader can tell "we stopped
// knowing here" from "we know it is fine", which is the distinction a boundary
// exists to preserve.
func (b Boundary) NotMeasured() []domain.EvidenceID { return cloneIDs(b.notMeasured) }

// IsZero reports whether b is the invalid zero Boundary.
func (b Boundary) IsZero() bool { return b.subject.IsZero() && b.firstFailure == "" }

// Boundaries returns one boundary per subject that has one, in canonical order.
//
// # Per subject, never per run
//
// A run with a healthy bootstrap and one unreachable discovered endpoint has two
// boundaries. Merging them would produce "the service is unreachable", which is
// false and is the summary ADR 0079 exists to prevent. A caller that wants one
// sentence must choose which subject it is about; nothing here chooses for it.
//
// # How each half is found
//
// Both halves are read from the graph. Neither is inferred:
//
//   - **first evidenced failure** is the shallowest node for this subject whose
//     state is FAIL or DEGRADED;
//   - **last confirmed-good** is the deepest PASS node for this subject at a
//     layer above that failure.
//
// The second condition is what keeps the pair a contrast rather than two
// unrelated facts. A PASS recorded *below* the failure — a later step that
// somehow succeeded — is not "the last thing that worked before it broke", and
// citing it would describe a chain that did not happen.
//
// # SKIPPED and UNKNOWN are neither half
//
// A step that did not run is not a confirmed-good boundary and is not a failure.
// It terminates the walk in the direction of "we stopped knowing here", and it
// is recorded in NotMeasured. This is the property that makes cancellation safe:
// a run cut short leaves UNKNOWN tails, and an UNKNOWN tail produces no boundary
// and invents no failure.
//
// # Ordering and complexity
//
// Subjects in (Kind, Ref) order; within a subject, nodes in (Layer, Step, ID)
// order. Nothing derives from insertion order or map iteration — the boundary is
// found by walking a layer-ordered chain, not by taking an index into whatever
// order the evidence arrived in. Complexity is O(n log n) in the graph's nodes
// plus O(n + e) over the blocked-by relation.
func Boundaries(g domain.Graph) []Boundary {
	subjects := Subjects(g)
	out := make([]Boundary, 0, len(subjects))

	for _, subject := range subjects {
		if boundary, ok := boundaryFor(g, subject); ok {
			out = append(out, boundary)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return slices.Clip(out)
}

// BoundaryFor returns the boundary for one subject, and whether it has one.
//
// It is the single-subject form of Boundaries, for a rule that already knows
// which subject it is reasoning about and should not pay for the rest of the
// graph.
func BoundaryFor(g domain.Graph, subject domain.Subject) (Boundary, bool) {
	return boundaryFor(g, subject)
}

func boundaryFor(g domain.Graph, subject domain.Subject) (Boundary, bool) {
	nodes := NodesForSubject(g, subject)
	if len(nodes) == 0 {
		return Boundary{}, false
	}

	boundary := Boundary{subject: subject}

	failureIndex := -1
	for i, node := range nodes {
		if node.State() == domain.StateFail || node.State() == domain.StateDegraded {
			failureIndex = i
			boundary.firstFailure = node.ID()
			break
		}
	}
	if failureIndex < 0 {
		// Nothing failed. There is no boundary — not a weak one, and not one
		// standing at the last thing that passed. An all-PASS subject has
		// nowhere for observation to have stopped succeeding.
		return Boundary{}, false
	}

	// The last PASS strictly above the failure. Walking backwards from the
	// failure rather than forwards from the start is what makes it "the last
	// thing that worked before it broke" rather than "the first thing that
	// worked at all".
	failureLayer := nodes[failureIndex].Layer()
	for i := failureIndex - 1; i >= 0; i-- {
		if nodes[i].State() == domain.StatePass && nodes[i].Layer() < failureLayer {
			boundary.lastGood = nodes[i].ID()
			break
		}
	}

	for _, node := range nodes {
		if node.State() == domain.StateUnknown || node.State() == domain.StateSkipped {
			boundary.notMeasured = append(boundary.notMeasured, node.ID())
		}
	}
	slices.Sort(boundary.notMeasured)
	boundary.blocked = BlockedChain(g, boundary.firstFailure)

	return boundary, true
}
