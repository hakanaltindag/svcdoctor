package diagnosis

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

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
// # The attribution no longer decides anything
//
// It used to. Until Phase 10.2a the merged finding took its prose from a winner
// chosen by RuleID ascending, and the attribution existed to break that tie.
// ADR 0081 section 2.2b removed the tie: prose is now a merge **precondition**,
// so every member of a group already agrees about it and there is nothing left
// to choose. See mergeGroup.
//
// The field stays for two reasons that are not tie-breaking. It is validated —
// a finding attributed to something that is not a rule identity is a defect in
// the caller, and refusing it here is cheaper than discovering it in a report.
// And it is what a debugger and a test failure message need in order to answer
// "which rule said this", which no report field answers (ADR 0080 section 2.5).
//
// **Nothing downstream may read it.** TestC06ARuleIDRenameCannotChangeAnything
// permutes every Rule in an input and requires byte-identical output, which is
// the structural form of the property ADR 0081 section 2.6a states.
type AttributedFinding struct {
	// Rule is the identity the finding's producer was wired in under. It is
	// validated and then ignored.
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
//	Summary           MUST_EQUAL                — a merge precondition since 10.2a
//	Detail            MUST_EQUAL                — a merge precondition since 10.2a
//	Recommendations   SEMANTIC_DEDUP_UNION      — by action text, content order
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
// # Determinism, and why nothing is chosen any more
//
// The result is the same for any input order, and it no longer depends on a
// winner at all: every field is either a precondition every member already
// agrees about, or reconciled by an order-independent operation — maximum,
// absorption, logical OR, a sorted union. Merging is therefore commutative and
// associative, which is what ADR 0081 section 7 asks to be proven, and it is
// additionally invariant under renaming the rules that produced the input.
//
// # Why prose is a precondition and not a reconciled field
//
// Phase 10.1a and 10.1b took ADR 0081 section 2.2 at its word and let the prose
// come from a tie-break winner, on the argument that once Code, Subject and
// Layer match the two routes state one claim and only the wording differs.
// Phase 10.2a measured three production shapes where the argument fails,
// because a rule may name in its prose something that is not in its subject —
// a Kafka broker node identifier, for instance, under a subject that is only
// the endpoint. Merging then published one broker's sentence over two brokers'
// evidence, and in the worst shape promoted a hypothesis about an unmeasured
// broker into a confirmed claim. See mergeable for the three, and ADR 0081
// section 2.2b for the decision that replaced the row.
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
	summary       string
	detail        string
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
// # Summary and Detail, added in Phase 10.2a
//
// They are MUST_EQUAL, and this reverses the one row of ADR 0081 section 2.2
// that assigned them to a tie-break winner. ADR 0081 section 2.2b records the
// supersession; what forced it was measurement, not argument.
//
// The row was defended on the grounds that once Code, Subject and Layer all
// match, two routes state one claim at one layer and only the wording differs.
// **That premise is false for a rule that names something in its prose which is
// not in its subject.** Three production shapes proved it, all reachable:
//
//   - Two brokers advertised at one endpoint. `KAFKA_ADVERTISED_ENDPOINT_
//     UNREACHABLE` names the broker node identifier in its summary and the
//     endpoint in its subject, so the two findings shared an identity and a
//     layer while describing different brokers. Merging published *"for broker
//     node 2"* over evidence from nodes 2 and 7, and node 7's claim vanished.
//     ADR 0034 section 10 had already decided the opposite in as many words —
//     *"two advertisements naming one endpoint are two facts and produce two
//     findings"* — so the merge silently overrode an Accepted decision.
//   - The same shape for `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE`.
//   - The same endpoint carrying a CONFIRMED claim about one broker and a
//     HYPOTHESIS about another. Absorption promoted the hypothesis, dropped its
//     discriminator, and published *"could not be reached"* about a broker whose
//     paths were never finished measuring. Less evidence produced a stronger
//     claim, which is the failure this project names by name.
//
// So prose joins the preconditions rather than the reconciled fields. It is a
// **strict narrowing**: a group that used to merge either still merges byte for
// byte, or becomes two findings that each state exactly what their rule stated.
// Convergence can now produce more findings than before and never a different
// one. Where two rules genuinely mean one claim, they already write one sentence
// — `KAFKA_AUTH_MECHANISM_NOT_OFFERED` reaches one endpoint from two protocol
// steps with byte-identical summary, detail and recommendations, and still
// merges into one finding citing both nodes.
//
// **No fuzzy matching, and that is deliberate.** Byte equality is the only
// comparison a test can state and a rule author can predict. If two rules mean
// the same thing they can share a constant; if they cannot share a constant they
// did not mean the same thing (ADR 0081 section 2.2b).
//
// # What is not in this key, and why
//
// Severity, Confidence, Kind and VantageDependent are all reconciled by an
// order-independent operation — maximum, maximum, absorption, logical OR — so
// none of them can inherit a value because a rule sorted first. EvidenceRefs and
// Recommendations are unions, and Phase 10.2a made the union's order
// content-derived so that it cannot depend on a rule's name either.
func mergeable(f domain.Finding) mergeKey {
	return mergeKey{
		layer:         f.Layer(),
		summary:       f.Summary(),
		detail:        f.Detail(),
		discriminator: f.Discriminator(),
	}
}

// sameClaimAs reports whether two keys agree about everything but the
// discriminator.
func (k mergeKey) sameClaimAs(other mergeKey) bool {
	return k.layer == other.layer && k.summary == other.summary && k.detail == other.detail
}

// compare orders two keys totally, from their own content.
func (k mergeKey) compare(other mergeKey) int {
	if c := cmp.Compare(k.layer, other.layer); c != 0 {
		return c
	}
	if c := cmp.Compare(k.summary, other.summary); c != 0 {
		return c
	}
	if c := cmp.Compare(k.detail, other.detail); c != 0 {
		return c
	}
	return cmp.Compare(k.discriminator, other.discriminator)
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

	// An unset discriminator folds into the one non-empty discriminator that
	// agrees with it about everything else, when there is exactly one. With none
	// it is already its own group; with two it must stay separate, because
	// joining either would be choosing.
	//
	// "Everything else" is the whole key minus the discriminator — layer and
	// prose since Phase 10.2a. A silent finding may only join a question asked
	// about the same claim at the same layer; folding it into a differently
	// worded one would reintroduce the choice this key exists to remove.
	for _, key := range keys {
		if key.discriminator != "" {
			continue
		}
		var host mergeKey
		hosts := 0
		for _, other := range keys {
			if other.discriminator != "" && other.sameClaimAs(key) {
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
	slices.SortFunc(remaining, mergeKey.compare)

	out := make([][]AttributedFinding, 0, len(remaining))
	for _, key := range remaining {
		out = append(out, buckets[key])
	}
	return out
}

// mergeGroup merges findings that already share an identity and a merge key.
//
// # There is no winner
//
// Until Phase 10.2a this function chose one member by RuleID and copied its
// prose. It no longer chooses anything: Code, Subject, Layer, Summary and Detail
// are all merge preconditions, so every member already agrees about every field
// that is *taken* rather than *reconciled*, and the representative below could
// be any member without changing a byte.
//
// That is what makes ADR 0081 section 2.6a's rename property structural rather
// than tested-and-hoped-for. Renaming a rule cannot alter a merged finding,
// because no merged field is derived from a rule's name.
func mergeGroup(group []AttributedFinding) (domain.Finding, error) {
	if len(group) == 1 {
		return group[0].Finding, nil
	}

	// The first member is the representative, and which one it is cannot matter.
	// Every field read from it below is a merge precondition, and the two checks
	// that follow turn a partitioning defect into a refusal rather than into a
	// published value nobody measured.
	rep := group[0]

	for _, af := range group {
		if af.Finding.Layer() != rep.Finding.Layer() {
			return domain.Finding{}, fmt.Errorf(
				"%w: %s spans layers %s and %s; a layer is not chosen by a tie-break "+
					"(ADR 0081 section 2.2, clarified in Phase 10.1b)",
				ErrCannotConverge, IdentityOf(rep.Finding),
				rep.Finding.Layer(), af.Finding.Layer())
		}
		if af.Finding.Summary() != rep.Finding.Summary() ||
			af.Finding.Detail() != rep.Finding.Detail() {
			return domain.Finding{}, fmt.Errorf(
				"%w: %s carries two different claims in prose; a sentence a reader acts "+
					"on is not chosen by a tie-break (ADR 0081 section 2.2b)",
				ErrCannotConverge, IdentityOf(rep.Finding))
		}
	}

	// The discriminator is the group's one non-empty value, not the
	// representative's: a silent member may sit beside a member that asked a
	// question, and taking the silence would drop the only open question in the
	// group.
	discriminator := ""
	for _, af := range group {
		if got := af.Finding.Discriminator(); got != "" {
			if discriminator != "" && discriminator != got {
				return domain.Finding{}, fmt.Errorf(
					"%w: %s carries two different discriminators; two hypotheses asking "+
						"different questions are not one hypothesis",
					ErrCannotConverge, IdentityOf(rep.Finding))
			}
			discriminator = got
		}
	}

	in := domain.FindingInput{
		Code:             rep.Finding.Code(),
		Kind:             rep.Finding.Kind(),
		Severity:         rep.Finding.Severity(),
		Confidence:       rep.Finding.Confidence(),
		Layer:            rep.Finding.Layer(),
		Subject:          rep.Finding.Subject(),
		Summary:          rep.Finding.Summary(),
		Detail:           rep.Finding.Detail(),
		VantageDependent: rep.Finding.VantageDependent(),
		Discriminator:    discriminator,
	}

	refs := make([]domain.EvidenceID, 0, len(group)*2)
	recommendations := make([]domain.Recommendation, 0, len(group))
	// Keyed on the **whole recommendation**, not on its action.
	//
	// Until Phase 10.4B a recommendation was its action, so deduplicating on the
	// action deduplicated the value. It is now five fields, and two of them —
	// kind and safety — are the difference between "look at this" and "change
	// this". Keying on the action alone would silently keep whichever copy
	// arrived first and drop a differently classified one, publishing a safety
	// class no rule attached to that sentence. That is the Phase 10.2A defect
	// exactly: a merged field with a value nobody stated.
	//
	// domain.Recommendation is comparable — five comparable fields, no slices,
	// no pointers — so the value is its own key and equality is total. Two
	// recommendations that differ in any field now coexist, and a reader sees
	// both classifications rather than one of them chosen by arrival order.
	seen := make(map[domain.Recommendation]struct{}, len(group))

	// The members are visited in an order derived from their own content, never
	// from a rule's name. Only the recommendation union can see this order at
	// all — every other fold below is a maximum, an absorption or a logical OR —
	// but a recommendation list is user-visible output, so an order that moved
	// when a rule was renamed would violate ADR 0081 section 2.6a just as surely
	// as a changed sentence would.
	rest := slices.Clone(group)
	slices.SortFunc(rest, func(a, b AttributedFinding) int {
		return compareByContent(a.Finding, b.Finding)
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
			if _, dup := seen[r]; dup {
				continue
			}
			seen[r] = struct{}{}
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
			"%w: merging %s: %w", ErrCannotConverge, IdentityOf(rep.Finding), err)
	}
	return merged, nil
}

// compareByContent orders two findings of one merge group from their own values.
//
// Code, Subject, Layer, Summary and Detail are equal by precondition, so the
// order is decided by what remains: the evidence each cites, then the reconciled
// fields, then the advice. Two findings that tie on all of it are
// indistinguishable to every consumer, so any order between them yields the same
// merged finding.
//
// It exists so that no merged field is a function of a rule's identity. See
// TestC06ARuleIDRenameCannotChangeAnything.
func compareByContent(a, b domain.Finding) int {
	if c := cmp.Compare(joinRefs(a), joinRefs(b)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Kind(), b.Kind()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Severity(), b.Severity()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Confidence(), b.Confidence()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Discriminator(), b.Discriminator()); c != 0 {
		return c
	}
	if a.VantageDependent() != b.VantageDependent() {
		if a.VantageDependent() {
			return 1
		}
		return -1
	}
	return cmp.Compare(joinAdvice(a), joinAdvice(b))
}

// joinRefs renders a finding's evidence references as one comparable string.
// domain.NewFinding already sorted and deduplicated them.
func joinRefs(f domain.Finding) string {
	var b strings.Builder
	for _, ref := range f.EvidenceRefs() {
		b.WriteString(string(ref))
		b.WriteByte(0)
	}
	return b.String()
}

// joinAdvice renders a finding's advice as one comparable string, in the order
// the rule wrote it.
//
// **Every field, not just the action.** This string is the last tie-break in
// compareByContent, which orders the members of a merge group so that the
// recommendation union is built in an order derived from content rather than
// from a rule's name (ADR 0081 section 2.6a). Since Phase 10.4B a recommendation
// carries five fields, and two findings differing only in a recommendation's
// kind would compare equal here — leaving their relative order to the sort's
// stability and therefore to input order. Including every field keeps the
// comparison total over the values it is comparing.
//
// The NUL separators keep the concatenation unambiguous: no field may contain
// one, because validateIdentifier rejects control characters.
func joinAdvice(f domain.Finding) string {
	var b strings.Builder
	for _, r := range f.Recommendations() {
		b.WriteString(r.Action())
		b.WriteByte(0)
		b.WriteString(r.Kind().String())
		b.WriteByte(0)
		b.WriteString(r.Safety().String())
		b.WriteByte(0)
		b.WriteString(r.Rationale())
		b.WriteByte(0)
		if r.SelfCollectable() {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
		b.WriteByte(0)
	}
	return b.String()
}
