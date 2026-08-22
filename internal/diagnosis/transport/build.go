package transport

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// buildInput carries the parts of a finding that differ between the three codes.
//
// Everything the three share — kind, severity, confidence, vantage dependence —
// is applied in build and is not a parameter, so the shared semantics cannot
// drift apart one rule at a time.
type buildInput struct {
	code           domain.FindingCode
	layer          domain.Layer
	subject        domain.Subject
	refs           []domain.EvidenceID
	summary        string
	detail         string
	recommendation string
}

// build assembles a generic transport finding.
//
// # Why all three share kind, severity, confidence and vantage
//
// Not for symmetry. Each falls out of the same reasoning applied to three claims
// that happen to answer alike:
//
//   - **CONFIRMED.** Every claim restates a positively evidenced FAIL node with
//     no inferential step. Nothing is left open, so there is no discriminator and
//     the model would reject one.
//   - **ERROR.** Severity is the impact of the finding's claim about its own
//     subject (ADR 0034 section 13). A target that cannot be resolved or
//     connected to cannot be used from here, and the run could learn nothing
//     further about it. It is not ERROR because the evidence state is FAIL —
//     that reasoning would make severity a synonym for the state.
//   - **HIGH.** The claim is exactly what was measured. "The resolver returned no
//     usable address" and "no connection completed" are the observations
//     themselves, not indirect signals agreeing.
//   - **vantageDependent: true.** Resolution depends on which resolver this host
//     uses, and connectivity on source address, routing and filtering.
//     Split-horizon DNS and per-network firewalls are routine, and a false here
//     would invite a reader to conclude the target is broken everywhere.
//
// # The severity tension, recorded rather than smoothed
//
// docs/SCOPE.md maps an ERROR finding to exit code 1, which means "svcdoctor
// worked and found a target-side problem" — and a resolver that times out may be
// a defect on this side. WARN was rejected because it maps to exit 0, "no problem
// found", and a run that learned nothing about the target would then report
// itself clean. That is the failure this package exists to fix. The claim's
// wording and the vantage flag carry the nuance instead. See ADR 0043 section 4.
func build(in buildInput) (domain.Finding, bool) {
	finding, err := domain.NewFinding(domain.FindingInput{
		Code:             in.code,
		Kind:             domain.FindingKindConfirmed,
		Severity:         domain.SeverityError,
		Confidence:       domain.ConfidenceHigh,
		Layer:            in.layer,
		Subject:          in.subject,
		Summary:          in.summary,
		Detail:           in.detail,
		EvidenceRefs:     in.refs,
		Recommendations:  recommendations(in.recommendation),
		VantageDependent: true,
	})
	if err != nil {
		// Unreachable: the subject comes from a node the graph validated, the
		// references come from that graph, and the prose is a package constant.
		// TestEveryAuthorizedShapeBuildsAValidFinding drives the whole producer
		// matrix and fails if this branch is ever taken.
		return domain.Finding{}, false
	}
	return finding, true
}

// recommendations wraps one action, or none if it cannot be constructed.
func recommendations(action string) []domain.Recommendation {
	recommendation, err := domain.NewRecommendation(action)
	if err != nil {
		// Unreachable: every action is a non-empty, trimmed,
		// control-character-free constant. Pinned by
		// TestRecommendationTextIsValid.
		return nil
	}
	return []domain.Recommendation{recommendation}
}
