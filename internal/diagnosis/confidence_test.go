package diagnosis

import (
	"errors"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a, ADR 0081 section 2.3: the confidence ladder.
//
// The point of testing an admission function rather than reviewing adjectives is
// that "why is this HIGH?" becomes a question with an answer a build can check.

func TestAuthorityNamesCoverAllGrounds(t *testing.T) {
	for a := Authority(0); int(a) < len(authorityNames); a++ {
		if authorityNames[a] == "" {
			t.Errorf("Authority(%d) has no name", a)
		}
		if !a.Valid() {
			t.Errorf("%s reports invalid; AuthorityNone is a real answer", a)
		}
	}
	// Two grounds admit HIGH, plus "neither". A third would be a new way to be
	// certain, and ADR 0081 section 2.3 lists exactly two.
	if len(authorityNames) != 3 {
		t.Errorf("%d authorities are defined, want 3", len(authorityNames))
	}
	if Authority(99).Valid() {
		t.Error("an out-of-range authority reports valid")
	}
	if got := Authority(99).String(); got != "Authority(99)" {
		t.Errorf("out-of-range String() = %q", got)
	}
}

func basisOf(t *testing.T, g domain.Graph, build func(*BasisBuilder) *BasisBuilder) EvidenceBasis {
	t.Helper()
	basis, err := build(NewBasis()).Freeze(g)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return basis
}

// TestDIAG027TheLadder walks every rung ADR 0081 section 2.3 defines.
func TestDIAG027TheLadder(t *testing.T) {
	g, _ := linearGraph(t)

	one := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder { return b.Support("a-tcp") })
	two := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder { return b.Support("a-tcp", "a-dns") })

	cases := []struct {
		name      string
		kind      domain.FindingKind
		authority Authority
		basis     EvidenceBasis
		want      domain.Confidence
		reasonWhy string
	}{
		{
			"the peer said so, confirmed", domain.FindingKindConfirmed, AuthorityDirect, one,
			domain.ConfidenceHigh, "direct protocol authority is not really an inference",
		},
		{
			"the peer said so, hypothesis", domain.FindingKindHypothesis, AuthorityDirect, one,
			domain.ConfidenceHigh, "the only ground on which a hypothesis may be HIGH",
		},
		{
			"complete contrast, confirmed", domain.FindingKindConfirmed, AuthorityCompleteContrast, two,
			domain.ConfidenceHigh, "every distinguishable alternative was measured and excluded",
		},
		{
			"complete contrast, hypothesis", domain.FindingKindHypothesis, AuthorityCompleteContrast, two,
			domain.ConfidenceMedium, "the ceiling: alternatives remain by the claim's own admission",
		},
		{
			"two observations converge", domain.FindingKindHypothesis, AuthorityNone, two,
			domain.ConfidenceMedium, "several independent observations converge is the definition",
		},
		{
			"one weakly discriminating observation", domain.FindingKindHypothesis, AuthorityNone, one,
			domain.ConfidenceLow, "the evidence would look the same under a realistic alternative",
		},
	}

	for _, c := range cases {
		got, err := AdmitConfidence(c.kind, c.authority, c.basis)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: confidence = %s, want %s (%s)", c.name, got, c.want, c.reasonWhy)
		}
	}
}

// TestP09MultipleWeakSupportsCannotVoteToHigh is property P09 and mutation M06.
//
// This is the one that keeps confidence ordinal. A vote is arithmetic scoring
// wearing an ordinal costume, and it is what would let a rule set manufacture
// certainty by adding observations.
func TestP09MultipleWeakSupportsCannotVoteToHigh(t *testing.T) {
	s := newSpec(t)
	for _, ref := range []string{"n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8"} {
		s.endpoint(ref, "many.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	}
	g := s.freeze()

	build := NewBasis()
	for _, ref := range []domain.EvidenceID{"n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8"} {
		build = build.Support(ref)
		basis, err := build.Freeze(g)
		if err != nil {
			t.Fatalf("Freeze: %v", err)
		}

		for _, kind := range []domain.FindingKind{
			domain.FindingKindConfirmed, domain.FindingKindHypothesis,
		} {
			got, err := AdmitConfidence(kind, AuthorityNone, basis)
			if err != nil {
				t.Fatalf("AdmitConfidence: %v", err)
			}
			if got == domain.ConfidenceHigh {
				t.Fatalf("%d supporting observations with no authority reached HIGH; "+
					"convergence is MEDIUM and never accumulates (ADR 0081 section 2.2)",
					len(basis.Supporting()))
			}
		}
	}
}

// TestP07ContradictionCannotRaiseConfidence is property P07 and mutation M05.
func TestP07ContradictionCannotRaiseConfidence(t *testing.T) {
	s := newSpec(t)
	s.endpoint("p-a", "c.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	s.endpoint("p-b", "c.example:5432", domain.LayerTCP, "tcp.connect", domain.StatePass)
	s.endpoint("p-c", "c.example:5432", domain.LayerTLS, "tls.handshake", domain.StateFail)
	g := s.freeze()

	for _, authority := range []Authority{AuthorityNone, AuthorityDirect, AuthorityCompleteContrast} {
		clean := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder { return b.Support("p-a", "p-b") })
		dirty := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder {
			return b.Support("p-a", "p-b").Contradict("p-c")
		})

		without, err := AdmitConfidence(domain.FindingKindConfirmed, authority, clean)
		if err != nil {
			t.Fatalf("AdmitConfidence: %v", err)
		}
		with, err := AdmitConfidence(domain.FindingKindConfirmed, authority, dirty)
		if err != nil {
			t.Fatalf("AdmitConfidence: %v", err)
		}

		if with > without {
			t.Errorf("%s: contradicting evidence raised confidence %s -> %s",
				authority, without, with)
		}
		if with != domain.ConfidenceLow {
			t.Errorf("%s: contradicting evidence left confidence at %s, want LOW",
				authority, with)
		}
	}
}

// TestP08MissingEvidenceCannotRaiseConfidence is property P08.
//
// Absence bears on confidence in exactly one way: it makes a declaration of
// complete contrast false, which is an error rather than a downgrade. "I
// excluded every alternative" and "I could not look" are different sentences.
func TestP08MissingEvidenceCannotRaiseConfidence(t *testing.T) {
	g, _ := linearGraph(t)

	for _, authority := range []Authority{AuthorityNone, AuthorityDirect} {
		without := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder { return b.Support("a-dns", "a-tcp") })
		with := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder {
			return b.Support("a-dns", "a-tcp").Miss(step(t, "tls.handshake"))
		})

		before, err := AdmitConfidence(domain.FindingKindHypothesis, authority, without)
		if err != nil {
			t.Fatalf("AdmitConfidence: %v", err)
		}
		after, err := AdmitConfidence(domain.FindingKindHypothesis, authority, with)
		if err != nil {
			t.Fatalf("AdmitConfidence: %v", err)
		}
		if after != before {
			t.Errorf("%s: a missing observation moved confidence %s -> %s",
				authority, before, after)
		}
	}
}

// TestCompleteContrastIsRefusedWhileSomethingIsMissing is the other half of P08,
// and the more interesting one.
func TestCompleteContrastIsRefusedWhileSomethingIsMissing(t *testing.T) {
	g, _ := linearGraph(t)

	basis := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder {
		return b.Support("a-dns", "a-tcp").Miss(step(t, "tls.handshake"))
	})

	got, err := AdmitConfidence(domain.FindingKindConfirmed, AuthorityCompleteContrast, basis)
	if !errors.Is(err, ErrInvalidBasis) {
		t.Fatalf("error = %v, want ErrInvalidBasis", err)
	}
	if got != domain.ConfidenceUnspecified {
		t.Errorf("a refused claim returned confidence %s; a caller ignoring the error "+
			"must not end up emitting something", got)
	}
}

// TestAClaimWithNoSupportIsRefused is ADR 0078 section 2.3 rule 1: if no
// remaining reference supports the claim, the claim is unsupported and must not
// be emitted.
func TestAClaimWithNoSupportIsRefused(t *testing.T) {
	g, _ := linearGraph(t)

	basis := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder { return b.Block("a-tls") })

	got, err := AdmitConfidence(domain.FindingKindConfirmed, AuthorityDirect, basis)
	if !errors.Is(err, ErrUnsupportedClaim) {
		t.Fatalf("error = %v, want ErrUnsupportedClaim", err)
	}
	if got != domain.ConfidenceUnspecified {
		t.Errorf("confidence = %s, want unspecified", got)
	}

	if _, err := AdmitConfidence(domain.FindingKindConfirmed, AuthorityDirect, EvidenceBasis{}); err == nil {
		t.Error("the zero basis admitted a claim")
	}
}

func TestAdmitConfidenceRejectsMalformedArguments(t *testing.T) {
	g, _ := linearGraph(t)
	basis := basisOf(t, g, func(b *BasisBuilder) *BasisBuilder { return b.Support("a-tcp") })

	if _, err := AdmitConfidence(domain.FindingKind(0), AuthorityNone, basis); err == nil {
		t.Error("an unspecified finding kind was accepted")
	}
	if _, err := AdmitConfidence(domain.FindingKindConfirmed, Authority(99), basis); err == nil {
		t.Error("an out-of-range authority was accepted")
	}
}

// TestConfidenceIsNeverArithmetic is the negative structural half of ADR 0081
// section 2.3, checked where a number could enter.
//
// domain.Confidence is an enumeration precisely so no arithmetic is possible on
// it, and the admission function returns one of the three constants rather than
// anything computed. If a future edit introduced a score, the natural way to do
// it would be to return a value outside the three.
func TestConfidenceIsNeverArithmetic(t *testing.T) {
	g, _ := linearGraph(t)

	for _, authority := range []Authority{AuthorityNone, AuthorityDirect, AuthorityCompleteContrast} {
		for _, kind := range []domain.FindingKind{
			domain.FindingKindConfirmed, domain.FindingKindHypothesis,
		} {
			for _, basis := range []EvidenceBasis{
				basisOf(t, g, func(b *BasisBuilder) *BasisBuilder { return b.Support("a-tcp") }),
				basisOf(t, g, func(b *BasisBuilder) *BasisBuilder { return b.Support("a-tcp", "a-dns") }),
			} {
				got, err := AdmitConfidence(kind, authority, basis)
				if err != nil {
					t.Fatalf("AdmitConfidence: %v", err)
				}
				switch got {
				case domain.ConfidenceLow, domain.ConfidenceMedium, domain.ConfidenceHigh:
				default:
					t.Fatalf("AdmitConfidence returned %v, which is not one of the three "+
						"ordinal levels", got)
				}
			}
		}
	}
}
