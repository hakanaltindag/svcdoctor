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
// # Semantic identity does not imply mergeability
//
// Two findings sharing an identity are candidates for merging. Whether they may
// actually be merged is a second question, and answering it "yes, always" is how
// a merged claim acquires a value no rule stated. See mergeable.
//
// # The merge, field by field
//
//	Code              MUST_EQUAL                — identity
//	Subject           MUST_EQUAL                — identity
//	Layer             MUST_EQUAL                — a merge precondition; see below
//	Discriminator     MUST_EQUAL when both set  — a merge precondition; see below
//	EvidenceRefs      DETERMINISTIC_UNION       — deduplicated and sorted
//	Confidence        ADMISSION_RECONCILIATION  — the maximum, never accumulation
//	Severity          the maximum               — ordinal, order-independent
//	Kind              CONFIRMED absorbs HYPOTHESIS
//	VantageDependent  BOOLEAN_JOIN              — logical OR
//	Recommendations   SEMANTIC_DEDUP_UNION      — by action text, winner's order first
//	Summary/Detail    the winner's              — ADR 0081 section 2.2, explicitly
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
// # Why Summary and Detail may come from a winner and Layer may not
//
// Prose is explicitly not identity (ADR 0081 section 4) and is explicitly free
// to be reworded (docs/FINDINGS.md section 3.1 rule 13), and ADR 0081 section
// 2.2 assigns it to the tie-break winner on purpose. Once Code, Subject and
// Layer all match, the two routes are stating one claim at one layer, so which
// wording survives changes nothing a consumer parses.
//
// Layer is the opposite: it is structured metadata a consumer reads, and it is
// one of the keys domain.SortFindings orders by. ADR 0081's table does not
// mention it at all. Phase 10.1a filled that silence with "the winner's" and
// Phase 10.1b measured what that does — see mergeable.
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
		// One identity may yield more than one finding. Findings that share an
		// identity but disagree about a MUST_EQUAL field are not one conclusion,
		// and each surviving group is merged on its own.
		for _, compatible := range partitionByCompatibility(groups[id]) {
			merged, err := mergeGroup(compatible)
			if err != nil {
				return nil, err
			}
			out = append(out, merged)
		}
	}

	domain.SortFindings(out)
	return out, nil
}

// mergeKey is everything two findings must agree on before they may be merged.
//
// It is deliberately *not* the semantic identity. Identity answers "are these
// about the same thing"; this answers "may the answer be stated as one finding
// without inventing a value neither rule stated".
type mergeKey struct {
	layer         domain.Layer
	discriminator string
}

// mergeable returns the compatibility key for a finding.
//
// # Layer
//
// Layer is MUST_EQUAL, and the reason is measured rather than argued.
//
// `POSTGRES_CONNECTION_NOT_PERMITTED` is produced by two rules about one
// endpoint at two layers, deliberately: `postgres/startup` anchors it at L4 and
// `postgres/authentication` at L5, and internal/diagnosis/postgres/shared.go
// says so in as many words — "the claim's layer is the anchor's own and the two
// anchors sit at different ones". Under a tie-break the merged finding would
// have claimed L5 while citing the startup node, because "postgres/a…" sorts
// before "postgres/s…". A refusal observed at the protocol stage would have been
// published as an authentication-stage claim, decided by an alphabet.
//
// So a differing layer means the two rules did not observe one thing, and the
// honest result is two findings rather than one with a layer neither measured.
// Semantic identity stays (Code, Subject); what changes is that identity is a
// *candidacy* test rather than a licence.
//
// # Discriminator
//
// Same rule, same reason. A discriminator names the observation that would
// settle a hypothesis, and two hypotheses asking different questions are not one
// question. It is measured to be constant across every construction site in the
// tree today, so this precondition fires nowhere and exists to keep it that way.
//
// An unset discriminator is compatible with a set one: silence is not a second,
// conflicting question, and the merged finding then carries the only question
// anybody asked. A CONFIRMED merge clears it entirely, so no conflict survives
// there either.
//
// # What is not in this key, and why
//
// Severity, Confidence, Kind and VantageDependent are all reconciled by an
// order-independent operation — maximum, maximum, absorption, logical OR — so
// none of them can inherit a value because a rule sorted first. EvidenceRefs and
// Recommendations are unions. Summary and Detail come from the winner, which
// ADR 0081 section 2.2 decides explicitly and which is safe precisely because
// everything a consumer parses now has to match.
func mergeable(f domain.Finding) mergeKey {
	return mergeKey{layer: f.Layer(), discriminator: f.Discriminator()}
}

// partitionByCompatibility splits one identity's findings into groups that may
// each be merged into a single finding.
//
// Groups are returned in a deterministic order derived from the findings
// themselves — layer, then discriminator — so that neither map iteration nor
// arrival order can decide which of two surviving findings is emitted first.
// The canonical sort at the end of Converge reorders them anyway; this makes the
// intermediate step reproducible so a failure is reproducible with it.
//
// The discriminator rule is asymmetric: an unset discriminator joins a set one
// rather than forming its own group. That is done by a second pass, because
// whether an empty-discriminator finding has a home depends on how many distinct
// non-empty discriminators exist at its layer.
func partitionByCompatibility(group []AttributedFinding) [][]AttributedFinding {
	if len(group) <= 1 {
		return [][]AttributedFinding{group}
	}

	buckets := map[mergeKey][]AttributedFinding{}
	var keys []mergeKey
	for _, af := range group {
		key := mergeable(af.Finding)
		if _, seen := buckets[key]; !seen {
			keys = append(keys, key)
		}
		buckets[key] = append(buckets[key], af)
	}

	// An unset discriminator folds into the one non-empty discriminator at its
	// layer, when there is exactly one. With none it is already its own group;
	// with two it must stay separate, because joining either would be choosing.
	for _, key := range keys {
		if key.discriminator != "" {
			continue
		}
		var host mergeKey
		hosts := 0
		for _, other := range keys {
			if other.layer == key.layer && other.discriminator != "" {
				host = other
				hosts++
			}
		}
		if hosts != 1 {
			continue
		}
		buckets[host] = append(buckets[host], buckets[key]...)
		delete(buckets, key)
	}

	remaining := make([]mergeKey, 0, len(buckets))
	for _, key := range keys {
		if _, alive := buckets[key]; alive {
			remaining = append(remaining, key)
		}
	}
	slices.SortFunc(remaining, func(a, b mergeKey) int {
		if c := cmp.Compare(a.layer, b.layer); c != 0 {
			return c
		}
		return cmp.Compare(a.discriminator, b.discriminator)
	})

	out := make([][]AttributedFinding, 0, len(remaining))
	for _, key := range remaining {
		out = append(out, buckets[key])
	}
	return out
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

	// Layer is a merge precondition, so every member already agrees. Rechecking
	// costs one comparison and turns a partitioning defect into a refusal rather
	// than into a published layer nobody measured.
	for _, af := range group {
		if af.Finding.Layer() != winner.Finding.Layer() {
			return domain.Finding{}, fmt.Errorf(
				"%w: %s spans layers %s and %s; a layer is not chosen by a tie-break "+
					"(ADR 0081 section 2.2, clarified in Phase 10.1b)",
				ErrCannotConverge, IdentityOf(winner.Finding),
				winner.Finding.Layer(), af.Finding.Layer())
		}
	}

	// The discriminator is the group's one non-empty value, not the winner's.
	// The winner is chosen by RuleID, and the rule that sorts first may be the
	// one that asked no question — taking its silence would drop the only open
	// question in the group.
	discriminator := ""
	for _, af := range group {
		if got := af.Finding.Discriminator(); got != "" {
			if discriminator != "" && discriminator != got {
				return domain.Finding{}, fmt.Errorf(
					"%w: %s carries two different discriminators; two hypotheses asking "+
						"different questions are not one hypothesis",
					ErrCannotConverge, IdentityOf(winner.Finding))
			}
			discriminator = got
		}
	}

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
		Discriminator:    discriminator,
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
