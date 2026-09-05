package diagnosis

import (
	"errors"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a, ADR 0082: recommendation safety.
//
// It reaches a report since Phase 10.4B. What the guardrails bought before that
// is that they existed before the first rule tempted by them — a diagnostic tool
// that says "restart the broker" on weak evidence is worse than one that says
// nothing, and the pressure to emit remediation grows exactly as the reasoning
// improves.

// The assignability half of the alias property, asserted by the compiler in both
// directions: each declaration takes its type from one vocabulary and its value
// from the other, so it builds only while the two are one type.
//
// It is written with the blank identifier deliberately. On a *named* variable the
// same four declarations are what staticcheck reports as ST1023 / QF1011 — and it
// is right that the type is redundant *to the compiler*, because for an alias it
// is. Here the left-hand type is the entire assertion, so it must be stated
// rather than inferred, and `var _ T = v` is the idiom that states it. Inferring
// it instead — `var kind = AdviceKindNextEvidence` — would compile whether or not
// the alias survived, which is the assertion silently disappearing.
var (
	_ AdviceKind                = domain.RecommendationKindNextEvidence
	_ domain.RecommendationKind = AdviceKindNextEvidence
	_ SafetyClass               = domain.SafetyCompare
	_ domain.SafetyClass        = SafetyCompare
)

// TestAdviceVocabularyIsTheDomainVocabulary is what replaced the old name-table
// walk, and it is a stronger property than the one it replaced.
//
// Phase 10.4B moved AdviceKind and SafetyClass into internal/domain and left
// **aliases** behind. The completeness of the name tables is now domain's test;
// what matters here is that no second vocabulary exists — because a distinct
// diagnosis-side enum plus a mapping is exactly the thing that drifts, and an
// alias makes "every AdviceKind maps exactly" true by identity.
//
// A Go type alias is transparent, so assigning across the two directions in both
// directions compiles only if they are one type. If someone reintroduces a
// distinct type with a conversion, this file stops compiling, which is the
// loudest available failure. The assignability half of that is asserted at
// package scope, just above; the comparability half is asserted here.
func TestAdviceVocabularyIsTheDomainVocabulary(t *testing.T) {
	// Comparing across the two vocabularies compiles only if they are one type,
	// and the two constants must also hold the same value. The four assertions
	// above cover assignment; this covers comparison and the values themselves.
	if AdviceKindNextEvidence != domain.RecommendationKindNextEvidence ||
		SafetyCompare != domain.SafetyCompare {
		t.Fatal("the alias does not round-trip; a mapping has appeared where identity was")
	}

	// The paired values, asserted rather than assumed, so a renumbering of one
	// side is caught here as well as in domain.
	for _, tc := range []struct {
		got  AdviceKind
		want domain.RecommendationKind
	}{
		{AdviceKindUnspecified, domain.RecommendationKindUnspecified},
		{AdviceKindNextEvidence, domain.RecommendationKindNextEvidence},
		{AdviceKindRemediation, domain.RecommendationKindRemediation},
	} {
		if tc.got != tc.want {
			t.Errorf("AdviceKind %s is not %s", tc.got, tc.want)
		}
	}
	for _, tc := range []struct {
		got  SafetyClass
		want domain.SafetyClass
	}{
		{SafetyUnspecified, domain.SafetyUnspecified},
		{SafetyObserve, domain.SafetyObserve},
		{SafetyVerify, domain.SafetyVerify},
		{SafetyCompare, domain.SafetyCompare},
		{SafetyConfigChange, domain.SafetyConfigChange},
		{SafetyRestart, domain.SafetyRestart},
		{SafetyDisruptive, domain.SafetyDisruptive},
		{SafetySecurityWeakening, domain.SafetySecurityWeakening},
	} {
		if tc.got != tc.want {
			t.Errorf("SafetyClass %s is not %s", tc.got, tc.want)
		}
	}

	if AdviceKindUnspecified.Valid() {
		t.Error("the zero AdviceKind reports valid")
	}
	if SafetyUnspecified.Valid() {
		t.Error("the zero SafetyClass reports valid")
	}
}

// TestDIAG034ThreeClassesAreUnreachable is ADR 0082 section 2.3 rule 2 and
// section 5.
//
// The three exist in the vocabulary so the prohibition is nameable and testable
// rather than merely absent, and so a future phase that genuinely needs one has
// to add it against a record. SECURITY_WEAKENING is the sharpest: svcdoctor must
// never recommend disabling the verification it exists to perform.
func TestDIAG034ThreeClassesAreUnreachable(t *testing.T) {
	for _, class := range []SafetyClass{
		SafetyRestart, SafetyDisruptive, SafetySecurityWeakening,
	} {
		if class.Producible() {
			t.Errorf("%s reports producible", class)
		}
		_, err := NewAdvice(AdviceInput{
			Kind:      AdviceKindRemediation,
			Safety:    class,
			Action:    "a plainly worded suggestion",
			Rationale: "because the evidence says so",
		})
		if !errors.Is(err, ErrUnsafeAdvice) {
			t.Errorf("NewAdvice(%s) = %v, want ErrUnsafeAdvice", class, err)
		}
	}

	for _, class := range []SafetyClass{
		SafetyObserve, SafetyVerify, SafetyCompare, SafetyConfigChange,
	} {
		if !class.Producible() {
			t.Errorf("%s reports unproducible", class)
		}
	}
	if SafetyUnspecified.Producible() {
		t.Error("the zero SafetyClass reports producible")
	}
}

// TestDIAG035RemediationRequiresConfirmedAndHigh is ADR 0082 section 2.3 rule 1
// and mutation M14.
func TestDIAG035RemediationRequiresConfirmedAndHigh(t *testing.T) {
	remediation, err := NewAdvice(AdviceInput{
		Kind:      AdviceKindRemediation,
		Safety:    SafetyConfigChange,
		Action:    "correct the configured address so it is reachable from this network",
		Rationale: "the address was advertised and no connection to it succeeded",
	})
	if err != nil {
		t.Fatalf("NewAdvice: %v", err)
	}

	if err := AdmitAdvice(domain.FindingKindConfirmed, domain.ConfidenceHigh, remediation); err != nil {
		t.Errorf("a CONFIRMED HIGH finding was refused a remediation: %v", err)
	}

	for _, c := range []struct {
		kind       domain.FindingKind
		confidence domain.Confidence
	}{
		{domain.FindingKindConfirmed, domain.ConfidenceMedium},
		{domain.FindingKindConfirmed, domain.ConfidenceLow},
		{domain.FindingKindHypothesis, domain.ConfidenceHigh},
		{domain.FindingKindHypothesis, domain.ConfidenceMedium},
		{domain.FindingKindHypothesis, domain.ConfidenceLow},
	} {
		if err := AdmitAdvice(c.kind, c.confidence, remediation); !errors.Is(err, ErrUnsafeAdvice) {
			t.Errorf("a %s finding at %s was allowed a remediation: %v", c.kind, c.confidence, err)
		}
	}
}

// TestNextEvidenceIsAlwaysAdmissible pins the other half: the correct output
// while a cause is ambiguous is the observation that would separate the
// explanations, and it must never be gated behind the confidence a rule does not
// have.
func TestNextEvidenceIsAlwaysAdmissible(t *testing.T) {
	advice, err := NewAdvice(AdviceInput{
		Kind:            AdviceKindNextEvidence,
		Safety:          SafetyCompare,
		Action:          "compare the advertised address with one routable from this network",
		Rationale:       "it separates an unreachable endpoint from an unsuitable advertisement",
		SelfCollectable: false,
	})
	if err != nil {
		t.Fatalf("NewAdvice: %v", err)
	}

	for _, kind := range []domain.FindingKind{
		domain.FindingKindConfirmed, domain.FindingKindHypothesis,
	} {
		for _, confidence := range []domain.Confidence{
			domain.ConfidenceLow, domain.ConfidenceMedium, domain.ConfidenceHigh,
		} {
			if err := AdmitAdvice(kind, confidence, advice); err != nil {
				t.Errorf("%s at %s was refused next-evidence advice: %v", kind, confidence, err)
			}
		}
	}
}

// TestNextEvidenceMustChangeNothing pins ADR 0082 section 2.4: a next-evidence
// class is always one of the three read-only ones.
func TestNextEvidenceMustChangeNothing(t *testing.T) {
	_, err := NewAdvice(AdviceInput{
		Kind:      AdviceKindNextEvidence,
		Safety:    SafetyConfigChange,
		Action:    "change the configuration and see what happens",
		Rationale: "an observation that alters the target is a remediation",
	})
	if !errors.Is(err, ErrUnsafeAdvice) {
		t.Fatalf("a CONFIG_CHANGE next-evidence recommendation was accepted: %v", err)
	}

	for _, class := range []SafetyClass{SafetyObserve, SafetyVerify, SafetyCompare} {
		if !class.ChangesNothing() {
			t.Errorf("%s reports that it changes something", class)
		}
	}
	for _, class := range []SafetyClass{
		SafetyConfigChange, SafetyRestart, SafetyDisruptive, SafetySecurityWeakening,
	} {
		if class.ChangesNothing() {
			t.Errorf("%s reports that it changes nothing", class)
		}
	}
}

// TestDIAG037SelfCollectableIsHonestAndBounded covers ADR 0082 section 2.4.
func TestDIAG037SelfCollectableIsHonestAndBounded(t *testing.T) {
	advice, err := NewAdvice(AdviceInput{
		Kind:            AdviceKindNextEvidence,
		Safety:          SafetyObserve,
		Action:          "re-run with a larger execution budget",
		Rationale:       "the step reached no conclusion before the local budget expired",
		SelfCollectable: true,
	})
	if err != nil {
		t.Fatalf("NewAdvice: %v", err)
	}
	if !advice.SelfCollectable() {
		t.Error("SelfCollectable was dropped")
	}

	// It is meaningless on a remediation: svcdoctor takes none at all, so
	// "svcdoctor could collect this" has nothing to describe.
	if _, err := NewAdvice(AdviceInput{
		Kind:            AdviceKindRemediation,
		Safety:          SafetyConfigChange,
		Action:          "correct the configured address",
		Rationale:       "the evidence names both halves",
		SelfCollectable: true,
	}); !errors.Is(err, ErrUnsafeAdvice) {
		t.Errorf("a self-collectable remediation was accepted: %v", err)
	}
}

// TestDIAG036NoRecommendationIsAnExecutableCommand is ADR 0082 section 2.3
// rule 3, made enforceable.
//
// A command in a report is a command someone pastes, and it matters most in the
// shareable projection where the reader may not be the operator who ran it.
func TestDIAG036NoRecommendationIsAnExecutableCommand(t *testing.T) {
	rejected := []string{
		"kubectl get pods",
		"psql -h host -U user",
		"openssl s_client -connect host:443",
		"systemctl restart the-service",
		"SELECT * FROM pg_stat_activity",
		"select count(*) from something",
		"DROP TABLE things",
		"GRANT ALL ON things TO someone",
		"check the listeners | grep advertised",
		"read the config && restart",
		"look at $HOME/config",
		"run `something`",
		"read the log > /tmp/out",
		"read the config\nthen restart",
		"sudo something",
		"",
		"   ",
		" leading space",
		"trailing space ",
	}
	for _, action := range rejected {
		if err := ValidateActionText(action); err == nil {
			t.Errorf("ValidateActionText(%q) was accepted", action)
		}
	}

	accepted := []string{
		"compare the advertised address with one routable from this client network",
		"confirm the certificate's subject alternative names cover the name used",
		"read the broker's configured listeners",
		"re-run with a larger execution budget",
		"check whether the credential is authorized for the named virtual host",
		"correct the advertised address to one clients can reach",
		// The shapes the validator was narrowed to admit, each of which appears
		// in a recommendation this tree already ships. See
		// TestDIAG036EveryProducedRecommendationIsAlreadySafe.
		"Supply --username together with --password-file to diagnose authentication",
		"Grant the diagnostic identity permission to run the command",
		"Verify the credential configured for this endpoint; the endpoint's own log " +
			"is the only place a wrong secret and an unknown role are distinguished",
	}
	for _, action := range accepted {
		if err := ValidateActionText(action); err != nil {
			t.Errorf("ValidateActionText(%q) = %v, want it accepted", action, err)
		}
	}
}

// TestTheActionValidatorsResidualGapIsWhereItWasPutOnPurpose records what the
// generic validator does not catch, as an assertion rather than as a comment.
//
// A bare "<service-tool> <subcommand>" carries no flag, no metacharacter and no
// generic command word, so nothing in this package sees it. Catching it needs
// the tool's name, and the only layer entitled to know that is the service's own
// rule package — the Phase 10.1a vocabulary guard rejected an earlier version of
// commandWords for holding two of them.
//
// The gap is real and it is bounded: one such string exists in the tree today,
// inside a longer English sentence about virtual-host permissions, and it is
// prose rather than an invocation. Writing the gap down here means a future
// reader finds a decision instead of an oversight.
func TestTheActionValidatorsResidualGapIsWhereItWasPutOnPurpose(t *testing.T) {
	for _, action := range []string{"redis-cli INFO", "rabbitmqctl status"} {
		if err := ValidateActionText(action); err != nil {
			t.Errorf("ValidateActionText(%q) = %v.\n\n"+
				"If the generic validator now catches a service tool by name, it has "+
				"learned a service's vocabulary, which ADR 0080 section 2.3 forbids "+
				"and TestDIAG019TheGenericCoreNamesNoService enforces. Delete this "+
				"test only together with that decision.", action, err)
		}
	}
}

func TestAdviceRequiresARationale(t *testing.T) {
	if _, err := NewAdvice(AdviceInput{
		Kind:   AdviceKindNextEvidence,
		Safety: SafetyObserve,
		Action: "read the configured listeners",
	}); err == nil {
		t.Error("advice with no stated reason was accepted; it could not be reviewed")
	}
}

func TestAdviceRejectsMalformedVocabulary(t *testing.T) {
	base := AdviceInput{
		Kind:      AdviceKindNextEvidence,
		Safety:    SafetyObserve,
		Action:    "read the configured listeners",
		Rationale: "it names the addresses this client would be asked to use",
	}

	unspecifiedKind := base
	unspecifiedKind.Kind = AdviceKindUnspecified
	if _, err := NewAdvice(unspecifiedKind); err == nil {
		t.Error("an unspecified advice kind was accepted")
	}

	unspecifiedSafety := base
	unspecifiedSafety.Safety = SafetyUnspecified
	if _, err := NewAdvice(unspecifiedSafety); err == nil {
		t.Error("an unspecified safety class was accepted")
	}

	if err := AdmitAdvice(domain.FindingKindConfirmed, domain.ConfidenceHigh, Advice{}); err == nil {
		t.Error("the zero Advice was admitted")
	}
	if !(Advice{}).IsZero() {
		t.Error("the zero Advice does not report zero")
	}
}

func TestAdviceKeepsWhatItWasGiven(t *testing.T) {
	advice, err := NewAdvice(AdviceInput{
		Kind:      AdviceKindNextEvidence,
		Safety:    SafetyVerify,
		Action:    "confirm the certificate's subject alternative names cover the name used",
		Rationale: "the handshake reported an identity mismatch and named both",
	})
	if err != nil {
		t.Fatalf("NewAdvice: %v", err)
	}

	if advice.Kind() != AdviceKindNextEvidence {
		t.Errorf("Kind() = %s", advice.Kind())
	}
	if advice.Safety() != SafetyVerify {
		t.Errorf("Safety() = %s", advice.Safety())
	}
	if advice.Action() == "" || advice.Rationale() == "" {
		t.Error("the text was dropped")
	}
	if advice.SelfCollectable() {
		t.Error("SelfCollectable defaulted to true")
	}
	if advice.IsZero() {
		t.Error("a constructed Advice reports zero")
	}
}
