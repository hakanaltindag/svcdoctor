package diagnosis

import (
	"errors"
	"fmt"
	"slices"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// ErrInvalidBasis reports that a described evidential basis is incoherent.
var ErrInvalidBasis = errors.New("invalid evidential basis")

// EvidenceRelation is how one piece of evidence stands to one claim.
//
// The four are frozen by ADR 0081 section 2.4 and they are **not**
// interchangeable. Collapsing any pair is the defect this whole vocabulary
// exists to prevent, and each collapse has a name:
//
//   - missing read as contradicting turns "we could not look" into "we looked
//     and it disagreed", which weakens a true claim with an absence;
//   - blocked read as contradicting blames a downstream layer for an upstream
//     failure — TLS was never attempted because TCP failed, so TLS is neither
//     broken nor healthy;
//   - blocked read as supporting is the same error pointing the other way, and
//     is how "all three brokers are unreachable" gets said about two that were
//     never tried.
//
// The zero EvidenceRelation is RelationUnspecified.
type EvidenceRelation uint8

const (
	// RelationUnspecified is the zero value and is not a relation.
	RelationUnspecified EvidenceRelation = iota

	// RelationSupporting means the evidence was observed and makes the claim
	// more credible.
	RelationSupporting

	// RelationContradicting means the evidence was observed and is inconsistent
	// with the claim.
	//
	// It is rule-internal. A rule that finds contradicting evidence emits
	// nothing, or emits a weaker claim, and says why in the finding's detail. No
	// contradictedBy field exists in the report, because a document full of
	// explicitly negated hypotheses is the negative explosion ADR 0079 section
	// 2.4 rejects.
	RelationContradicting

	// RelationMissing means the observation was never made, and making it would
	// discriminate between the explanations that remain.
	//
	// It is the reason Finding.Discriminator exists, and it is the input to a
	// next-evidence recommendation. It is never evidence against anything.
	RelationMissing

	// RelationBlocked means the observation was not made *because* an upstream
	// step failed. It is the graph's own BlockedBy, and it is neither support
	// nor contradiction.
	RelationBlocked
)

// relationNames is indexed by EvidenceRelation. Keep it aligned with the const
// block above; TestRelationNamesCoverAllRelations fails if the two drift apart.
var relationNames = [...]string{
	RelationUnspecified:   "UNSPECIFIED",
	RelationSupporting:    "SUPPORTING",
	RelationContradicting: "CONTRADICTING",
	RelationMissing:       "MISSING",
	RelationBlocked:       "BLOCKED",
}

// Valid reports whether r is a defined relation. RelationUnspecified is not.
func (r EvidenceRelation) Valid() bool {
	return r != RelationUnspecified && int(r) < len(relationNames)
}

// String returns the symbolic name. It never fails.
func (r EvidenceRelation) String() string {
	if int(r) >= len(relationNames) {
		return fmt.Sprintf("EvidenceRelation(%d)", uint8(r))
	}
	return relationNames[r]
}

// EvidenceBasis is what one claim rests on, with the four relations kept apart.
//
// It is an internal reasoning value. It is not serialized, it is not a report
// field, and it never leaves the diagnosis layer: only the supporting set
// reaches a report, as Finding.EvidenceRefs. The other three exist so that a
// rule's reasoning can be *checked* — that it did not treat an absence as a
// denial, that it did not read a blocked step in either direction, and that its
// confidence is admissible.
//
// The zero EvidenceBasis is valid and rests on nothing. AdmitConfidence refuses
// it, because a claim supported by no evidence is not a claim (ADR 0078 section
// 2.3 rule 1).
type EvidenceBasis struct {
	supporting    []domain.EvidenceID
	contradicting []domain.EvidenceID
	blocked       []domain.EvidenceID
	missing       []domain.Step
}

// Supporting returns a copy of the observed evidence that makes the claim more
// credible.
func (b EvidenceBasis) Supporting() []domain.EvidenceID { return cloneIDs(b.supporting) }

// Contradicting returns a copy of the observed evidence inconsistent with the
// claim.
func (b EvidenceBasis) Contradicting() []domain.EvidenceID { return cloneIDs(b.contradicting) }

// Blocked returns a copy of the steps that did not run because an upstream step
// failed.
func (b EvidenceBasis) Blocked() []domain.EvidenceID { return cloneIDs(b.blocked) }

// Missing returns a copy of the steps whose observation would discriminate and
// was never made.
//
// Missing observations are named by step rather than by evidence identifier
// because they have no identifier: nothing was recorded, so there is no node to
// point at. Steps are svcdoctor's own vocabulary and are never peer-supplied,
// which keeps ADR 0081 section 2.7 satisfied by construction — there is no way
// to name a missing observation using a string a server chose.
func (b EvidenceBasis) Missing() []domain.Step {
	if len(b.missing) == 0 {
		return nil
	}
	return slices.Clone(b.missing)
}

// IsZero reports whether the basis rests on nothing at all.
func (b EvidenceBasis) IsZero() bool {
	return len(b.supporting) == 0 && len(b.contradicting) == 0 &&
		len(b.blocked) == 0 && len(b.missing) == 0
}

// BasisBuilder accumulates the four relations and produces an EvidenceBasis.
//
// Builder and frozen value are separate for the same reason GraphBuilder and
// Graph are, and for one more: freezing takes the graph, so the coherence checks
// that make the relations trustworthy happen once, at a point where both the
// claim's evidence and the evidence's recorded state are in hand.
//
// The zero BasisBuilder is valid and empty; NewBasis is the ordinary way to get
// one.
type BasisBuilder struct {
	supporting    []domain.EvidenceID
	contradicting []domain.EvidenceID
	blocked       []domain.EvidenceID
	missing       []domain.Step
}

// NewBasis returns an empty basis builder.
func NewBasis() *BasisBuilder { return &BasisBuilder{} }

// Support records evidence that makes the claim more credible.
func (b *BasisBuilder) Support(ids ...domain.EvidenceID) *BasisBuilder {
	b.supporting = append(b.supporting, ids...)
	return b
}

// Contradict records observed evidence inconsistent with the claim.
func (b *BasisBuilder) Contradict(ids ...domain.EvidenceID) *BasisBuilder {
	b.contradicting = append(b.contradicting, ids...)
	return b
}

// Block records a step that did not run because an upstream step failed.
func (b *BasisBuilder) Block(ids ...domain.EvidenceID) *BasisBuilder {
	b.blocked = append(b.blocked, ids...)
	return b
}

// Miss records an observation that was never made and would discriminate.
func (b *BasisBuilder) Miss(steps ...domain.Step) *BasisBuilder {
	b.missing = append(b.missing, steps...)
	return b
}

// Freeze validates the basis against g and returns it.
//
// Five checks, and each is a defect this project has already made or has already
// written an ADR to prevent:
//
//  1. Every cited identifier resolves to a node in g. A claim resting on a node
//     that is not in the report is unverifiable by a reader (ADR 0014).
//  2. The three identifier sets are pairwise disjoint. One node cannot both
//     support and contradict one claim; if a rule believes it does, the rule has
//     two claims.
//  3. A node the graph records as blocked may not be cited as supporting or
//     contradicting. This is ADR 0081 section 2.4's sharpest case, stated
//     structurally: a step that never ran is evidence for nothing.
//  4. A node cited as blocked must actually be blocked in the graph. A rule
//     cannot label a node "blocked" to excuse it; the graph records blocking,
//     and the graph is what is read.
//  5. Every named missing step is a well-formed step.
//
// Deliberately *not* checked: that supporting evidence is conclusive. An UNKNOWN
// node is legitimate support for a claim *about not having measured something* —
// which is most of what svcdoctor says when a capability is unsupported — and a
// blanket rule would forbid the honest claim along with the dishonest one.
// The dishonest one is the blocked case, and that is check 3.
func (b *BasisBuilder) Freeze(g domain.Graph) (EvidenceBasis, error) {
	supporting, err := normalizeBasisIDs(g, "supporting", b.supporting)
	if err != nil {
		return EvidenceBasis{}, err
	}
	contradicting, err := normalizeBasisIDs(g, "contradicting", b.contradicting)
	if err != nil {
		return EvidenceBasis{}, err
	}
	blocked, err := normalizeBasisIDs(g, "blocked", b.blocked)
	if err != nil {
		return EvidenceBasis{}, err
	}

	for _, pair := range []struct {
		leftName, rightName string
		left, right         []domain.EvidenceID
	}{
		{"supporting", "contradicting", supporting, contradicting},
		{"supporting", "blocked", supporting, blocked},
		{"contradicting", "blocked", contradicting, blocked},
	} {
		for _, id := range pair.left {
			if slices.Contains(pair.right, id) {
				return EvidenceBasis{}, fmt.Errorf(
					"%w: evidence %q is both %s and %s",
					ErrInvalidBasis, id, pair.leftName, pair.rightName)
			}
		}
	}

	for _, id := range blocked {
		if len(g.BlockedBy(id)) == 0 {
			return EvidenceBasis{}, fmt.Errorf(
				"%w: evidence %q is cited as blocked, but the graph records nothing "+
					"blocking it; blocking is recorded by whoever decided not to run "+
					"the step, never inferred by a rule", ErrInvalidBasis, id)
		}
	}
	for _, name := range []struct {
		label string
		ids   []domain.EvidenceID
	}{{"supporting", supporting}, {"contradicting", contradicting}} {
		for _, id := range name.ids {
			if len(g.BlockedBy(id)) > 0 {
				return EvidenceBasis{}, fmt.Errorf(
					"%w: evidence %q did not run because an upstream step failed, so it "+
						"is neither %s nor contradicting; a blocked step is evidence for "+
						"nothing (ADR 0081 section 2.4)", ErrInvalidBasis, id, name.label)
			}
		}
	}

	missing, err := normalizeMissing(b.missing)
	if err != nil {
		return EvidenceBasis{}, err
	}

	return EvidenceBasis{
		supporting:    supporting,
		contradicting: contradicting,
		blocked:       blocked,
		missing:       missing,
	}, nil
}

// normalizeBasisIDs validates, deduplicates and sorts one relation's set.
//
// Sorting is what makes a basis order-independent: a rule that collected the
// same evidence in two orders has one basis, so nothing downstream can vary with
// how a rule happened to walk the graph.
func normalizeBasisIDs(
	g domain.Graph, label string, in []domain.EvidenceID,
) ([]domain.EvidenceID, error) {
	if len(in) == 0 {
		return nil, nil
	}

	out := make([]domain.EvidenceID, 0, len(in))
	for _, id := range in {
		if _, ok := g.Node(id); !ok {
			return nil, fmt.Errorf(
				"%w: %s evidence %q is not in the graph", ErrInvalidBasis, label, id)
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return slices.Clip(out), nil
}

// normalizeMissing validates, deduplicates and sorts the named missing steps.
func normalizeMissing(in []domain.Step) ([]domain.Step, error) {
	if len(in) == 0 {
		return nil, nil
	}

	out := make([]domain.Step, 0, len(in))
	for _, step := range in {
		if !step.Valid() {
			return nil, fmt.Errorf("%w: missing step %q is not a step", ErrInvalidBasis, step)
		}
		if !slices.Contains(out, step) {
			out = append(out, step)
		}
	}
	slices.Sort(out)
	return slices.Clip(out), nil
}

// cloneIDs returns an owned copy so a caller cannot edit a frozen basis.
func cloneIDs(ids []domain.EvidenceID) []domain.EvidenceID {
	if len(ids) == 0 {
		return nil
	}
	return slices.Clone(ids)
}
