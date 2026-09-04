package diagnosis

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// ErrCannotConverge reports that a set of findings cannot be merged.
var ErrCannotConverge = errors.New("cannot converge findings")

// SemanticIdentity is what makes two findings the same conclusion.
//
// It is the finding code and the subject, and nothing else — ADR 0081 section
// 2.1. Not the summary, not a hash of the prose, not a similarity score.
//
// # Why (Code, Subject) is enough
//
// The model already made it enough. A finding code is one independent claim
// (docs/FINDINGS.md section 3.1 rule 1) and a subject is the thing the claim is
// about, so two rules that reach one code about one endpoint from different
// evidence have reached one conclusion by two routes. ADR 0017 declined to
// deduplicate precisely because no document defined this; ADR 0081 section 2.1
// is that document.
//
// # Why not prose
//
// Prose is free to change (docs/FINDINGS.md section 3.1 rule 13). An identity
// derived from a summary would be unstable across a wording edit, so a typo fix
// would silently split one conclusion into two or merge two into one.
//
// A finding with no subject is a claim about the run as a whole. Its identity is
// the code with the zero subject, and there can be at most one of it.
//
// The zero SemanticIdentity is invalid.
type SemanticIdentity struct {
	code    domain.FindingCode
	subject domain.Subject
}

// IdentityOf returns the semantic identity of a finding.
func IdentityOf(f domain.Finding) SemanticIdentity {
	return SemanticIdentity{code: f.Code(), subject: f.Subject()}
}

// Code returns the finding code half of the identity.
func (i SemanticIdentity) Code() domain.FindingCode { return i.code }

// Subject returns the subject half, which may be the zero Subject.
func (i SemanticIdentity) Subject() domain.Subject { return i.subject }

// IsZero reports whether i is the invalid zero identity.
func (i SemanticIdentity) IsZero() bool {
	return i.code == "" && i.subject.IsZero()
}

// String returns a readable rendering for tests and failure messages.
func (i SemanticIdentity) String() string {
	if i.subject.IsZero() {
		return string(i.code) + "@<run>"
	}
	return string(i.code) + "@" + i.subject.String()
}

// compare orders two identities deterministically.
//
// It exists so that convergence never depends on map iteration: identities are
// collected into a slice and sorted, and the sort is total because a code and a
// subject are both strings plus a small enumeration.
func (i SemanticIdentity) compare(other SemanticIdentity) int {
	if c := cmp.Compare(i.code, other.code); c != 0 {
		return c
	}
	if c := cmp.Compare(i.subject.Kind(), other.subject.Kind()); c != 0 {
		return c
	}
	return cmp.Compare(i.subject.Ref(), other.subject.Ref())
}

// AttributedFinding is one finding and the rule that produced it.
//
// Convergence needs the attribution for one reason only: the tie-break. When two
// rules reach one conclusion, the merged finding takes its prose from one of
// them, and ADR 0081 section 2.6 breaks that tie by RuleID ascending. The
// alternative — "whichever rule ran first" — would make wiring order observable
// in a report, which is the property every determinism guarantee here rests on.
type AttributedFinding struct {
	// Rule is the identity the finding's producer was wired in under.
	Rule RuleID

	// Finding is what the rule concluded.
	Finding domain.Finding
}

// Converge merges findings that share a semantic identity.
//
// It is the mechanism ADR 0081 section 2.2 froze, and it is **not wired into
// Engine.Evaluate in Phase 10.1a**. Merging changes reports — fewer, richer
// findings — and 10.1a is the half of the split that changes none
// (docs/design/DIAGNOSTIC_INTELLIGENCE.md section P). It lands, tested, so that
// 10.1b's diff is the wiring rather than the semantics.
//
// # The merge, field by field
//
//	EvidenceRefs      union, deduplicated, sorted — the claim rests on both routes
//	Confidence        the maximum, which is not the same as accumulation
//	Kind              CONFIRMED wins: a proof and a guess about one thing is a proof
//	Severity          the maximum
//	Summary/Detail    the winner's
//	Layer             the winner's
//	Recommendations   union by action text, the winner's order first
//	Discriminator     the winner's, and empty once Kind is CONFIRMED
//	VantageDependent  logical OR
//
// # Confidence does not add up
//
// Two MEDIUM routes to one conclusion produce MEDIUM. Independent convergence is
// what ADR 0081 section 2.3 already calls MEDIUM, so promoting on count would be
// a vote — arithmetic scoring wearing an ordinal costume — and would let three
// weak rules manufacture a strong claim. Taking the maximum gives exactly the
// frozen property: a merged finding reaches HIGH only if one of its inputs
// independently qualified for HIGH.
//
// # Determinism
//
// The result is the same for any input order: every merged field is either
// order-independent (max, union, OR) or taken from a winner chosen by a total
// order over (RuleID, Summary, Detail). Merging is therefore commutative and
// associative, which is what ADR 0081 section 7 asks to be proven.
//
// # The ADR is silent on Layer, and this is the choice made
//
// The merge table does not mention it. The winner's layer is taken, because
// summary, detail and discriminator already come from the winner and a finding
// whose prose came from one rule and whose layer came from another would
// describe a claim neither rule made. Recorded in
// docs/validation/PHASE101A_DIAGNOSTIC_CORE_VALIDATION.md as a clarification.
//
// The returned findings are in the canonical order domain.SortFindings defines.
func Converge(in []AttributedFinding) ([]domain.Finding, error) {
	if len(in) == 0 {
		return nil, nil
	}

	groups := make(map[SemanticIdentity][]AttributedFinding, len(in))
	order := make([]SemanticIdentity, 0, len(in))
	for _, af := range in {
		if af.Finding.IsZero() {
			return nil, fmt.Errorf("%w: the zero Finding cannot be merged", ErrCannotConverge)
		}
		if !af.Rule.Valid() {
			return nil, fmt.Errorf(
				"%w: finding %s is attributed to %q, which is not a rule identity; the "+
					"merge tie-break is defined on it (ADR 0081 section 2.6)",
				ErrCannotConverge, af.Finding.Code(), af.Rule)
		}
		id := IdentityOf(af.Finding)
		if _, seen := groups[id]; !seen {
			order = append(order, id)
		}
		groups[id] = append(groups[id], af)
	}

	// The identity list is sorted rather than kept in arrival order, so that the
	// map above cannot influence anything even indirectly. The output is sorted
	// again at the end; this is belt and braces because a merge failure's error
	// message would otherwise name whichever group happened to be visited first.
	slices.SortFunc(order, SemanticIdentity.compare)

	out := make([]domain.Finding, 0, len(order))
	for _, id := range order {
		merged, err := mergeGroup(groups[id])
		if err != nil {
			return nil, err
		}
		out = append(out, merged)
	}

	domain.SortFindings(out)
	return out, nil
}

// mergeGroup merges findings that already share an identity.
func mergeGroup(group []AttributedFinding) (domain.Finding, error) {
	if len(group) == 1 {
		return group[0].Finding, nil
	}

	winner := slices.MinFunc(group, func(a, b AttributedFinding) int {
		if c := cmp.Compare(a.Rule, b.Rule); c != 0 {
			return c
		}
		// One rule may legitimately produce two findings with one identity, and
		// then RuleID does not discriminate. Falling through to the prose keeps
		// the choice total and deterministic; it is arbitrary, and being stable
		// is the whole requirement.
		if c := cmp.Compare(a.Finding.Summary(), b.Finding.Summary()); c != 0 {
			return c
		}
		return cmp.Compare(a.Finding.Detail(), b.Finding.Detail())
	})

	in := domain.FindingInput{
		Code:             winner.Finding.Code(),
		Kind:             winner.Finding.Kind(),
		Severity:         winner.Finding.Severity(),
		Confidence:       winner.Finding.Confidence(),
		Layer:            winner.Finding.Layer(),
		Subject:          winner.Finding.Subject(),
		Summary:          winner.Finding.Summary(),
		Detail:           winner.Finding.Detail(),
		VantageDependent: winner.Finding.VantageDependent(),
		Discriminator:    winner.Finding.Discriminator(),
	}

	refs := make([]domain.EvidenceID, 0, len(group)*2)
	recommendations := make([]domain.Recommendation, 0, len(group))
	seenActions := make(map[string]struct{}, len(group))

	// The winner's recommendations come first so that its order is preserved,
	// then the rest in the deterministic order below.
	rest := slices.Clone(group)
	slices.SortFunc(rest, func(a, b AttributedFinding) int {
		if c := cmp.Compare(a.Rule, b.Rule); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Finding.Summary(), b.Finding.Summary()); c != 0 {
			return c
		}
		return cmp.Compare(a.Finding.Detail(), b.Finding.Detail())
	})

	for _, af := range rest {
		f := af.Finding
		refs = append(refs, f.EvidenceRefs()...)
		in.Severity = max(in.Severity, f.Severity())
		in.Confidence = max(in.Confidence, f.Confidence())
		in.VantageDependent = in.VantageDependent || f.VantageDependent()
		if f.Kind() == domain.FindingKindConfirmed {
			in.Kind = domain.FindingKindConfirmed
		}
		for _, r := range f.Recommendations() {
			if _, dup := seenActions[r.Action()]; dup {
				continue
			}
			seenActions[r.Action()] = struct{}{}
			recommendations = append(recommendations, r)
		}
	}

	// A proof and a guess about one thing is a proof, and a proof has no open
	// question left to settle — which domain.NewFinding also refuses.
	if in.Kind == domain.FindingKindConfirmed {
		in.Discriminator = ""
	}

	in.EvidenceRefs = refs
	in.Recommendations = recommendations

	merged, err := domain.NewFinding(in)
	if err != nil {
		return domain.Finding{}, fmt.Errorf(
			"%w: merging %s: %w", ErrCannotConverge, IdentityOf(winner.Finding), err)
	}
	return merged, nil
}
