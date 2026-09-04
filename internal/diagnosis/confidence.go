package diagnosis

import (
	"errors"
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// ErrUnsupportedClaim reports that a claim's basis does not admit it at all.
var ErrUnsupportedClaim = errors.New("unsupported claim")

// Authority is why a claim could be strong.
//
// ADR 0081 section 2.3 admits `HIGH` on exactly two grounds and no others. This
// type is those two grounds, made nameable so that a rule declares which one it
// is standing on and a reviewer can reject the declaration.
//
// The zero Authority is AuthorityNone, which is the honest default: most claims
// have neither.
type Authority uint8

const (
	// AuthorityNone means neither admission test applies. The claim rests on
	// consistency with what was observed, and alternatives remain.
	AuthorityNone Authority = iota

	// AuthorityDirect means the peer stated the condition in its own protocol,
	// in a field whose meaning that protocol defines.
	//
	// This is the only ground on which a HYPOTHESIS may be HIGH, and the reason
	// is that it is not really an inference: the peer said so, and svcdoctor is
	// repeating it.
	AuthorityDirect

	// AuthorityCompleteContrast means every alternative explanation svcdoctor
	// can distinguish has been measured and excluded, and the exclusions are
	// cited.
	//
	// It is incompatible with a missing discriminating observation: if something
	// that would separate the explanations was never observed, the contrast is
	// not complete, and AdmitConfidence refuses the combination rather than
	// quietly downgrading it. A rule that means "several things agree" means
	// AuthorityNone.
	AuthorityCompleteContrast
)

// authorityNames is indexed by Authority. Keep it aligned with the const block
// above; TestAuthorityNamesCoverAllGrounds fails if the two drift apart.
var authorityNames = [...]string{
	AuthorityNone:             "NONE",
	AuthorityDirect:           "DIRECT",
	AuthorityCompleteContrast: "COMPLETE_CONTRAST",
}

// Valid reports whether a is a defined ground. AuthorityNone is one: "neither
// test applies" is a real answer, not an unset field.
func (a Authority) Valid() bool { return int(a) < len(authorityNames) }

// String returns the symbolic name. It never fails.
func (a Authority) String() string {
	if !a.Valid() {
		return fmt.Sprintf("Authority(%d)", uint8(a))
	}
	return authorityNames[a]
}

// AdmitConfidence returns the strongest confidence a claim may carry.
//
// It is the confidence ladder of ADR 0081 section 2.3 written as a function, so
// that "why is this HIGH?" has an answer a test can check rather than an
// adjective a reviewer has to weigh.
//
// # The ladder
//
//	HIGH    the peer stated it (AuthorityDirect), or every distinguishable
//	        alternative was measured and excluded (AuthorityCompleteContrast)
//	        and the claim is CONFIRMED — and in both cases nothing contradicts it
//	MEDIUM  several independent observations converge, alternatives remain
//	LOW     compatible with the observations, and with a realistic alternative too
//
// # The four properties that make it honest
//
//   - **Confidence is never arithmetic.** There is no score, no weight and no
//     count that crosses a threshold. Two supporting observations are the
//     difference between LOW and MEDIUM because "several independent
//     observations converge" is what MEDIUM *means*; a third does not move it,
//     and no number of them reaches HIGH. That is the vote this project refuses.
//   - **Contradiction only ever lowers.** Observed evidence inconsistent with a
//     claim caps it at LOW, and a rule holding contradicting evidence should
//     usually emit nothing at all.
//   - **Absence never raises, and never lowers either.** A missing observation
//     is not a denial (ADR 0081 section 2.4). It bears on confidence in exactly
//     one way: it makes AuthorityCompleteContrast a false declaration, which is
//     an error rather than a downgrade, because "I excluded everything" and "I
//     could not look" are different sentences.
//   - **Blocked evidence bears on nothing.** EvidenceBasis.Freeze already
//     refuses to let a blocked node into either observed set, so it cannot reach
//     this function in a position to matter.
//
// # The ceiling
//
// A HYPOTHESIS may not be HIGH on complete contrast alone. If alternatives
// remain and svcdoctor cannot discriminate them, the claim is at most MEDIUM,
// and if nothing distinguishes it from the alternatives at all it is LOW — or,
// per ADR 0083 section 2.2 rule 2, not emitted.
//
// # Errors
//
// It returns ErrUnsupportedClaim when the basis has no supporting evidence: a
// claim whose citations would all be decoration is not a claim (ADR 0078 section
// 2.3 rule 1). It returns ErrInvalidBasis when the declared authority
// contradicts the basis. In both cases the returned confidence is
// ConfidenceUnspecified, so a caller that ignores the error cannot accidentally
// emit a LOW claim it was refused.
func AdmitConfidence(
	kind domain.FindingKind, authority Authority, basis EvidenceBasis,
) (domain.Confidence, error) {
	if !kind.Valid() {
		return domain.ConfidenceUnspecified,
			fmt.Errorf("%w: finding kind %s", domain.ErrInvalidValue, kind)
	}
	if !authority.Valid() {
		return domain.ConfidenceUnspecified,
			fmt.Errorf("%w: authority %s", domain.ErrInvalidValue, authority)
	}
	if len(basis.supporting) == 0 {
		return domain.ConfidenceUnspecified, fmt.Errorf(
			"%w: nothing supports it; a claim no remaining citation supports must not "+
				"be emitted (ADR 0078 section 2.3 rule 1)", ErrUnsupportedClaim)
	}
	if authority == AuthorityCompleteContrast && len(basis.missing) > 0 {
		return domain.ConfidenceUnspecified, fmt.Errorf(
			"%w: complete contrast is declared while %d discriminating observation(s) "+
				"were never made; \"I excluded every alternative\" and \"I could not "+
				"look\" are different claims (ADR 0081 sections 2.3 and 2.4)",
			ErrInvalidBasis, len(basis.missing))
	}

	// Contradiction caps, and it caps hard. A rule that reaches here holding
	// evidence inconsistent with its own claim is usually a rule that should
	// have emitted nothing; LOW is the strongest thing left to say.
	if len(basis.contradicting) > 0 {
		return domain.ConfidenceLow, nil
	}

	switch authority {
	case AuthorityDirect:
		// The peer said so, in its own protocol, in a field that protocol
		// defines. A hypothesis may be HIGH here and only here.
		return domain.ConfidenceHigh, nil

	case AuthorityCompleteContrast:
		if kind == domain.FindingKindConfirmed {
			return domain.ConfidenceHigh, nil
		}
		// The ceiling: alternatives were excluded by measurement, but the claim
		// still presents itself as one candidate explanation among others, and
		// those two statements cannot both be at full strength.
		return domain.ConfidenceMedium, nil

	case AuthorityNone:
		// "Several independent observations converge" is the definition of
		// MEDIUM, not a count that grows into something stronger.
		if len(basis.supporting) >= 2 {
			return domain.ConfidenceMedium, nil
		}
		return domain.ConfidenceLow, nil
	}

	// Unreachable while Authority is the three constants above; Valid already
	// rejected anything else. Returning rather than panicking keeps a future
	// member from becoming a crash.
	return domain.ConfidenceUnspecified,
		fmt.Errorf("%w: authority %s", domain.ErrInvalidValue, authority)
}
