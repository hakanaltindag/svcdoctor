package postgres

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// CodeAdmissionScope states the measured scope of host-based admission across
// the addresses one requested target resolved to.
//
// # What was already here, and why this is not it
//
// `POSTGRES_CONNECTION_NOT_PERMITTED` answers *"was this one address refused
// before any credential was evaluated"*, once per address, and has since Phase
// 4.6b. It is ERROR, it is `vantageDependent: true`, and it is right.
//
// Two facts are **not** in the conjunction of those findings, and neither can be
// recovered from it. They are the same two ADR 0084 reopened ADR 0034 section 10
// for, arriving in a second service:
//
//   - **whether the set was complete.** Two refused addresses beside a third
//     svcdoctor never reached look exactly like two out of two. The conjunction
//     is two findings either way.
//   - **the contrast.** "One address was refused and the other completed the
//     startup exchange" is a different diagnosis from "every address was
//     refused", and neither per-address finding states it. The first says the
//     endpoint's admission decision differs between two addresses of one name —
//     which is what `pg_hba.conf` does, because its rules match the source and
//     destination address — and the second says this client is refused wherever
//     it connects.
//
// The composition root measures every resolved address through the credential-
// free stages precisely so this is observable: its own doc comment records that
// "one family may be offered SCRAM while another is refused outright". A target
// with an A record covered by a host-based rule and an AAAA record that is not
// is the ordinary shape of it, and today svcdoctor reports one ERROR and exit 1
// for a run whose selected path succeeded completely, with nothing saying so.
//
// # It is an observation, not a verdict
//
// It counts three categories — refused, admitted, undetermined — and says which
// addresses are in each. It attributes no cause, applies no threshold, names no
// configuration file, and never says an admission policy is wrong: a policy that
// refuses one address may be exactly what its operator intended, and svcdoctor
// has no expectation to compare it against (ADR 0083 section 2.6).
//
// It is INFO for the reason ADR 0034 section 13 gives and Phase 10.2 re-applied:
// **severity is never a count-derived verdict.** The impact of a refusal is
// already carried, at ERROR, once per address, by
// `POSTGRES_CONNECTION_NOT_PERMITTED`. Escalating on how many addresses were
// refused would be this finding grading the target, and it would move an exit
// code on arithmetic.
const CodeAdmissionScope domain.FindingCode = "POSTGRES_ADMISSION_SCOPE"

// The prose, held as constants so no part of it can come from anywhere else.
//
// **Nothing a peer chose is interpolated into any of it.** The only values that
// reach these strings are integers this rule counted off the graph's own
// structure. Every hostname and address travels on the subject and on the
// referenced evidence, where redaction transforms it (ADR 0081 section 2.7,
// docs/FINDINGS.md section 3.1 rule 15).
const (
	summaryAdmissionAll = "This PostgreSQL endpoint refused the connection before evaluating " +
		"any credential at all %d addresses this target resolved to"

	summaryAdmissionSome = "This PostgreSQL endpoint refused the connection before evaluating " +
		"any credential at %d of the %d addresses this target resolved to; the startup " +
		"exchange completed at the other %d"

	summaryAdmissionIncomplete = "This PostgreSQL endpoint refused the connection before " +
		"evaluating any credential at %d of the %d addresses this target resolved to; the " +
		"startup exchange completed at %d and no admission decision was observed at %d"

	detailAdmissionMeaning = "This counts what was measured about each address the target " +
		"resolved to, at the stage before any credential is presented. It attributes no " +
		"cause, and it states nothing about why any address answered as it did.\n" +
		"A refusal at this stage is a decision about the connecting role and the address it " +
		"connected from, so it is relative to this vantage point: host-based access rules " +
		"match on the source address, and the same role may be permitted from elsewhere."

	detailAdmissionContrast = "\nThe addresses did not answer alike. That is consistent with " +
		"one endpoint whose admission rules select on the address reached, and equally " +
		"consistent with the addresses being served by different endpoints; svcdoctor " +
		"measured the difference and not its cause."

	detailAdmissionUniform = "\nEvery address this target resolved to was measured and every " +
		"one refused, so the counts above account for the whole set."

	detailAdmissionIncomplete = "\nSome addresses reached no admission decision, so nothing is " +
		"claimed about them and no count here is a total. An address whose decision was not " +
		"observed is not an address that was refused."

	// The next observation for the contrast case.
	//
	// It is a comparison and never a change. "Add a host-based access rule" is
	// refused permanently: an admission policy that refuses an address may be
	// exactly what it was written to do, and widening one is a security-relevant
	// edit svcdoctor is not entitled to suggest from a connection attempt
	// (ADR 0082 section 2.3, ADR 0085 section 5).
	recommendAdmissionContrast = "Compare this endpoint's host-based access rules for the " +
		"addresses that refused the connection with the rules for the addresses that " +
		"accepted it, for the role this run used"

	rationaleAdmissionContrast = "The role and the database were the same on every address, " +
		"so what differed is something only the endpoint's own admission rules and the " +
		"addresses themselves can account for; which of the two it is decides whether this " +
		"is one endpoint with a gap in its rules or two endpoints with different ones."

	// The next observation when the set is partial. Self-collectable in the
	// sense ADR 0082 section 2.4 defines: a differently configured run could take
	// it. Diagnosis still collects nothing.
	recommendAdmissionUnmeasured = "Re-run with a larger execution budget so the addresses " +
		"that reached no admission decision are attempted"

	rationaleAdmissionUnmeasured = "The counts above are partial while any address is " +
		"undetermined, and a complete set is what separates \"one address was refused\" from " +
		"\"every address was refused\"."
)

// admissionVerdict is what a run learned about admission at one address.
//
// Three, never two. An address that reached no decision is not an address that
// was refused, and collapsing the third category is how "every address refused
// this client" gets said about an address nobody finished measuring.
type admissionVerdict uint8

const (
	// admissionRefused is a positively observed negative: the endpoint answered
	// the startup message by refusing on who was connecting and from where,
	// before any credential was evaluated.
	//
	// It is read from the failure class and never from a SQLSTATE. The adapter
	// already decided, per step, what a code proves there, and a rule that
	// re-read the five characters would be building the shared SQLSTATE
	// dictionary ADR 0039 section 7.1 forbids.
	admissionRefused admissionVerdict = iota

	// admissionAccepted is a positively observed positive: the startup exchange
	// completed, so the endpoint carried the connection to the point where it
	// either demanded a credential or stated it wanted none.
	admissionAccepted

	// admissionUndetermined is neither, and it is never merged into
	// admissionRefused.
	//
	// It covers an address whose startup failed for a reason that is not an
	// admission decision, one whose startup was cancelled or timed out, one
	// whose startup was skipped because an earlier layer failed, and one that
	// never reached the startup stage at all. Those are four ways of not having
	// an answer, and none of them is an answer.
	admissionUndetermined
)

// AdmissionScope reports the measured scope of host-based admission for one
// requested target.
//
// It is a diagnosis.Rule. The signature is not stated as one here for the reason
// the sibling rules give: the assertion lives in the package's own boundary test.
//
// # The three conditions, and why each is load-bearing
//
//  1. **Exactly one requested-target anchor.** The claim is about the target the
//     operator named, and its subject is that anchor's own. A graph offering two
//     has no defensible answer to which one this is about, and a rule that
//     picked one would make the output depend on traversal order.
//  2. **At least two addresses were classified.** With one address there is no
//     contrast and no completeness question the per-address finding does not
//     already settle, so the aggregate would be pure duplication. This is the
//     gate that keeps every single-address run — which is nearly all of them —
//     byte-identical to what it produced before Phase 10.3.
//  3. **At least one address was positively refused.** A target where nothing
//     was refused has no admission scope worth stating: the per-address findings
//     are silent, the boundary reports whatever else happened, and a finding
//     here would be an "all good" line in a document nobody reads to the end.
func AdmissionScope(ctx diagnosis.RuleContext) []domain.Finding {
	scope, ok := admissionScopeOf(ctx)
	if !ok || len(scope.refused) == 0 {
		return nil
	}
	finding, ok := scope.finding()
	if !ok {
		return nil
	}
	return []domain.Finding{finding}
}

// admissionScope is one requested target and what became of admission at each
// address beneath it.
type admissionScope struct {
	anchor domain.Evidence

	refused      []domain.Evidence
	accepted     []domain.Evidence
	undetermined []domain.Evidence

	// complete reports that every classified address reached a decision and that
	// svcdoctor's own budget did not stop the run.
	//
	// Both halves are required and neither implies the other.
	// RuleContext.Incomplete is svcdoctor's statement about its own execution
	// (ADR 0080 section 2.1); the empty undetermined set is a statement about
	// this target's own startup nodes. A run cancelled after the last startup
	// exchange finished has the second without the first.
	complete bool
}

// admissionScopeOf classifies every startup node in the graph against the run's
// one requested target.
//
// # Why it does not walk the graph downward from the anchor
//
// It reads the startup nodes directly. Walking children would mean reading
// absence — "this address has no startup node" — and a PostgreSQL rule never
// does: `TestNoRuleInfersAMissingCredentialFromAbsence` makes it a build
// failure, because a run cancelled before a stage and a run whose stage was
// never reachable produce identical graphs. An address with no startup node
// therefore contributes nothing at all rather than an undetermined verdict, and
// the run's own `Incomplete` is what says the set may be partial.
//
// A PostgreSQL run measures exactly one logical target, so every startup node in
// the graph belongs to it. That is a property of the composition root
// (`internal/app/postgres.go`), and condition 1 above is what makes the rule
// withhold rather than guess if it ever stops being true.
func admissionScopeOf(ctx diagnosis.RuleContext) (admissionScope, bool) {
	g := ctx.Graph

	var (
		anchor  domain.Evidence
		anchors int
	)
	for _, node := range g.Nodes() {
		if node.Step() == vocabulary.StepTargetRequested {
			anchor = node
			anchors++
		}
	}
	if anchors != 1 || anchor.Subject().IsZero() {
		return admissionScope{}, false
	}

	scope := admissionScope{anchor: anchor}
	for _, node := range g.Nodes() {
		if node.Step() != servicepostgres.StepStartup {
			continue
		}
		switch classifyAdmission(node) {
		case admissionRefused:
			scope.refused = append(scope.refused, node)
		case admissionAccepted:
			scope.accepted = append(scope.accepted, node)
		case admissionUndetermined:
			scope.undetermined = append(scope.undetermined, node)
		}
	}
	if scope.total() < 2 {
		return admissionScope{}, false
	}
	scope.complete = len(scope.undetermined) == 0 && !ctx.Incomplete
	return scope, true
}

// classifyAdmission decides one startup node's admission verdict.
//
// PASS and a refusal are the two answers; everything else is the absence of one.
// The refusal test is the failure class and nothing else, which is what keeps
// this rule reading the same fact `POSTGRES_CONNECTION_NOT_PERMITTED` reads —
// so the aggregate can never count an address the per-address finding did not
// also name.
func classifyAdmission(node domain.Evidence) admissionVerdict {
	switch {
	case node.State() == domain.StatePass:
		return admissionAccepted
	case node.State() == domain.StateFail &&
		node.FailureClass() == domain.FailureAuthzNotPermitted:
		return admissionRefused
	default:
		return admissionUndetermined
	}
}

// total returns how many addresses were classified.
func (s admissionScope) total() int {
	return len(s.refused) + len(s.accepted) + len(s.undetermined)
}

// finding builds the observation.
func (s admissionScope) finding() (domain.Finding, bool) {
	summary, detail := s.prose()

	finding, err := domain.NewFinding(domain.FindingInput{
		Code: CodeAdmissionScope,
		// It restates measured states and infers nothing: every number in it is
		// a count of nodes the graph already holds, so it is true by
		// construction from the evidence it cites. That is also why it carries
		// no discriminator — domain.NewFinding refuses one on a CONFIRMED
		// finding, and there is no open question for one to settle.
		Kind: domain.FindingKindConfirmed,
		// Never a count-derived escalation. See the note on the code.
		Severity:   domain.SeverityInfo,
		Confidence: domain.ConfidenceHigh,
		// The stage the counted observations were made at. Not L1: this is not a
		// claim about resolution, and the addresses are where they came from
		// rather than what is being said about them.
		Layer: domain.LayerProtocol,
		// The target the operator asked about, taken from the anchor's own
		// subject. It is deliberately not one of the addresses: this claim is
		// about the set rather than about a member of it, and borrowing a
		// member's subject would put a set-level count under an address-level
		// identity — and would collide with the per-address finding that is
		// already there.
		Subject: s.anchor.Subject(),
		Summary: summary,
		Detail:  detail,
		// Every refusal counted here is a decision keyed on the source address,
		// which is the definition of the property. It is the one ground ADR 0040
		// section 6.1 calls proved rather than merely unassertable.
		VantageDependent: true,
		EvidenceRefs:     s.refs(),
		Recommendations:  s.recommendations(),
	})
	if err != nil {
		// Unreachable. Every value is a constant, a domain value taken from a
		// node the graph already validated, or a decimal integer.
		// TestEveryAdmissionShapeBuildsAValidFinding drives the matrix and fails
		// if this branch is ever taken.
		return domain.Finding{}, false
	}
	return finding, true
}

// prose chooses the sentence the counts support.
//
// Three shapes, and the third exists because of the one claim this rule must
// never make. With anything undetermined, "1 of 2 refused" would assert a total
// nobody established; the incomplete form states all three counts and calls none
// of them complete.
func (s admissionScope) prose() (string, string) {
	if !s.complete {
		return fmt.Sprintf(summaryAdmissionIncomplete,
				len(s.refused), s.total(), len(s.accepted), len(s.undetermined)),
			detailAdmissionMeaning + detailAdmissionIncomplete
	}
	if len(s.accepted) == 0 {
		return fmt.Sprintf(summaryAdmissionAll, s.total()),
			detailAdmissionMeaning + detailAdmissionUniform
	}
	return fmt.Sprintf(summaryAdmissionSome, len(s.refused), s.total(), len(s.accepted)),
		detailAdmissionMeaning + detailAdmissionContrast
}

// refs is the minimal sufficient proof of the counts.
//
// Every reference is load-bearing, which is the test ADR 0078 section 2.3 rule 1
// states: delete any one of them from the graph and a count changes.
//
//   - the anchor, because it is what makes this a statement about one target
//     rather than about some addresses that happen to be in a graph;
//   - every classified startup node, because they are the set, its size and each
//     address's verdict.
//
// An undetermined node is cited too, including one the graph records as
// blocked, and that is not the error ADR 0081 section 2.4 warns about. That
// record forbids reading a blocked node as evidence *for or against the
// subject's health*; here it is cited as support for the claim that **its
// decision was not observed**, which is one of the three counts this finding
// states and is precisely what `BlockedBy` records. `BasisBuilder.Freeze`'s own
// doc comment draws the same line — "an UNKNOWN node is legitimate support for
// a claim about not having measured something" — and
// `POSTGRES_CREDENTIAL_WITHHELD` already cites a blocked anchor for the same
// reason. What no reference here ever does is join the refused count.
func (s admissionScope) refs() []domain.EvidenceID {
	refs := []domain.EvidenceID{s.anchor.ID()}
	for _, group := range [][]domain.Evidence{s.refused, s.accepted, s.undetermined} {
		for _, node := range group {
			refs = append(refs, node.ID())
		}
	}
	return refs
}

// recommendations returns the next observations the counts support.
//
// Ordered by construction rather than collected from a map, and both entries are
// NEXT_EVIDENCE: there is no remediation here at any confidence, because the
// only changes this evidence could point at are edits to an admission policy
// svcdoctor has not read and has no expectation for.
func (s admissionScope) recommendations() []domain.Recommendation {
	var out []domain.Recommendation

	if len(s.accepted) > 0 {
		out = append(out, projectAdvice(diagnosis.AdviceInput{
			Kind:      diagnosis.AdviceKindNextEvidence,
			Safety:    diagnosis.SafetyCompare,
			Action:    recommendAdmissionContrast,
			Rationale: rationaleAdmissionContrast,
			// svcdoctor cannot take it in any run: it reads no server
			// configuration and holds no model of what this target's rules are
			// meant to permit.
			SelfCollectable: false,
		}, domain.FindingKindConfirmed, domain.ConfidenceHigh)...)
	}
	if !s.complete {
		out = append(out, projectAdvice(diagnosis.AdviceInput{
			Kind:            diagnosis.AdviceKindNextEvidence,
			Safety:          diagnosis.SafetyObserve,
			Action:          recommendAdmissionUnmeasured,
			Rationale:       rationaleAdmissionUnmeasured,
			SelfCollectable: true,
		}, domain.FindingKindConfirmed, domain.ConfidenceHigh)...)
	}
	return out
}
