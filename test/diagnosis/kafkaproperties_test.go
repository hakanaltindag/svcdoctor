package diagnosis_test

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.2, level L2: the Kafka reasoning invariants, K-P01 through K-P15.
//
// Each property is stated over many graphs rather than one, because the
// scenarios these rules will actually meet are combinations nobody enumerated.
// A unit test says "this graph produces this finding"; a property says "no graph
// produces this claim", and only the second survives a rule author adding a
// branch.

// topologyClaims returns the two Phase 10.2 findings a run produced.
func topologyClaims(r run) (observation []domain.Finding, hypothesis []domain.Finding) {
	return r.findingsWithCode(diagnosiskafka.CodeAdvertisedTopologyReachability),
		r.findingsWithCode(diagnosiskafka.CodeAdvertisedTopologyUnsuitable)
}

// everyAdvertisedOutcome is the alphabet the property tests generate over.
func everyAdvertisedOutcome() []advertisedOutcome {
	return []advertisedOutcome{
		advReachedPlain, advReachedTLS, advTCPRefused, advDNSFails,
		advTLSIdentityMismatch, advNotMeasured, advCancelled, advUnusable,
	}
}

// outcomeName labels a generated case.
func outcomeName(o advertisedOutcome) string {
	switch o {
	case advReachedPlain:
		return "reached"
	case advReachedTLS:
		return "reachedTLS"
	case advTCPRefused:
		return "refused"
	case advDNSFails:
		return "dnsFails"
	case advTLSIdentityMismatch:
		return "tlsMismatch"
	case advNotMeasured:
		return "notMeasured"
	case advCancelled:
		return "cancelled"
	case advUnusable:
		return "unusable"
	}
	return "?"
}

// topologyRun builds a healthy bootstrap, advertises one endpoint per outcome,
// and diagnoses it.
func topologyRun(t *testing.T, incomplete bool, outcomes ...advertisedOutcome) run {
	t.Helper()

	s := healthyThroughMetadata(t)
	for i, o := range outcomes {
		s.advertise(i+1, fmt.Sprintf("b%d.example", i+1), 9092, o)
	}
	return diagnoseKafka(t, s.freeze(), incomplete)
}

// everyTriple enumerates the 512 three-endpoint advertised sets.
func everyTriple(fn func(name string, outcomes []advertisedOutcome)) {
	all := everyAdvertisedOutcome()
	for _, a := range all {
		for _, b := range all {
			for _, c := range all {
				fn(outcomeName(a)+"/"+outcomeName(b)+"/"+outcomeName(c),
					[]advertisedOutcome{a, b, c})
			}
		}
	}
}

// --- K-P01 and K-P02: nothing downstream of a bootstrap that did not finish --

// TestKP01BootstrapFailureProducesNoTopologyClaim.
//
// Without a completed Metadata exchange there is no advertised set, so a
// topology claim has nothing to be about. This drives every place the bootstrap
// journey can stop.
func TestKP01BootstrapFailureProducesNoTopologyClaim(t *testing.T) {
	stops := []struct {
		name  string
		build func(t *testing.T) domain.Graph
	}{
		{"dns", func(t *testing.T) domain.Graph {
			s := newKafkaGraph(t)
			s.bootstrapPath(domain.StateFail, domain.StatePass, domain.StatePass)
			return s.freeze()
		}},
		{"tcp", func(t *testing.T) domain.Graph {
			s := newKafkaGraph(t)
			s.bootstrapPath(domain.StatePass, domain.StateFail, domain.StatePass)
			return s.freeze()
		}},
		{"tls", func(t *testing.T) domain.Graph {
			s := newKafkaGraph(t)
			s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StateFail)
			return s.freeze()
		}},
		{"apiversions", func(t *testing.T) domain.Graph {
			s := newKafkaGraph(t)
			s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
			s.protocolStage("k-apiversions", domain.LayerProtocol, kafkaStepAPIVersions,
				domain.StateFail, domain.FailureProtocolUnexpectedResponse)
			return s.freeze()
		}},
		{"sasl-handshake", func(t *testing.T) domain.Graph {
			s := newKafkaGraph(t)
			s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
			s.protocolStage("k-apiversions", domain.LayerProtocol, kafkaStepAPIVersions,
				domain.StatePass, domain.FailureNone)
			s.protocolStage("k-handshake", domain.LayerAuth, kafkaStepSASLHandshake,
				domain.StateFail, domain.FailureAuthMechanismNotOffered)
			return s.freeze()
		}},
		{"authentication", func(t *testing.T) domain.Graph {
			s := newKafkaGraph(t)
			s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
			s.protocolStage("k-apiversions", domain.LayerProtocol, kafkaStepAPIVersions,
				domain.StatePass, domain.FailureNone)
			s.protocolStage("k-auth", domain.LayerAuth, kafkaStepSASLAuthenticate,
				domain.StateFail, domain.FailureAuthCredentialsRejected)
			return s.freeze()
		}},
	}

	for _, stop := range stops {
		for _, incomplete := range []bool{false, true} {
			t.Run(stop.name+"/incomplete="+strconv.FormatBool(incomplete), func(t *testing.T) {
				r := diagnoseKafka(t, stop.build(t), incomplete)
				requireFindings(t, r, 1)

				observation, hypothesis := topologyClaims(r)
				if len(observation) != 0 || len(hypothesis) != 0 {
					t.Errorf("a run that stopped at %s produced %d topology observations "+
						"and %d topology hypotheses; there is no advertised set to be "+
						"about", stop.name, len(observation), len(hypothesis))
				}
			})
		}
	}
}

// TestKP02MetadataFailureProducesNoCompletenessClaim.
//
// The exchange is reached and does not complete, so the cluster named no broker.
// A claim about the completeness of a set that does not exist is the strongest
// form of the error this phase is built around.
func TestKP02MetadataFailureProducesNoCompletenessClaim(t *testing.T) {
	for _, class := range []domain.FailureClass{
		domain.FailureProtocolUnexpectedResponse,
		domain.FailureProtocolMalformedResponse,
		domain.FailureProtocolPeerClosed,
		domain.FailureAuthzDenied,
	} {
		t.Run(class.String(), func(t *testing.T) {
			s := newKafkaGraph(t)
			s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
			s.protocolStage("k-apiversions", domain.LayerProtocol, kafkaStepAPIVersions,
				domain.StatePass, domain.FailureNone)
			s.protocolStage("k-auth", domain.LayerAuth, kafkaStepSASLAuthenticate,
				domain.StatePass, domain.FailureNone)
			s.metadata(domain.StateFail, class)
			r := diagnoseKafka(t, s.freeze(), false)

			observation, hypothesis := topologyClaims(r)
			if len(observation) != 0 || len(hypothesis) != 0 {
				t.Errorf("a failed Metadata exchange produced %d observations and %d "+
					"hypotheses about a topology it never learned",
					len(observation), len(hypothesis))
			}
			assertRefuses(t, r, []forbiddenClaim{
				{"broker endpoints this cluster", "no broker was named"},
				{"were reached", "no broker endpoint was measured"},
				{"not measured", "an absent set is not an unmeasured one"},
			})
		})
	}
}

// --- K-P03, K-P04 and K-P06: three categories, never two --------------------

// TestKP03AndKP04UnmeasuredEndpointsAreNeverCountedAsFailures drives all 512
// three-endpoint sets and checks the counts against the fixture's own
// intention.
//
// The properties are stated on the numbers in the sentence, which is what a
// reader acts on, rather than on an internal verdict a refactor could rename.
func TestKP03AndKP04UnmeasuredEndpointsAreNeverCountedAsFailures(t *testing.T) {
	checked := 0
	everyTriple(func(name string, outcomes []advertisedOutcome) {
		t.Run(name, func(t *testing.T) {
			// Any unmeasured endpoint makes the run incomplete, exactly as
			// internal/app's own predicate would.
			incomplete := slices.Contains(outcomes, advNotMeasured) ||
				slices.Contains(outcomes, advCancelled)
			r := topologyRun(t, incomplete, outcomes...)

			observation, _ := topologyClaims(r)
			if len(observation) == 0 {
				return
			}
			checked++
			notReached, reached, notMeasured := parseCounts(t, observation[0].Summary())

			wantNotMeasured := 0
			wantReached := 0
			wantNotReached := 0
			for _, o := range outcomes {
				switch o {
				case advNotMeasured, advCancelled:
					wantNotMeasured++
				case advReachedPlain, advReachedTLS:
					wantReached++
				case advTCPRefused, advDNSFails, advTLSIdentityMismatch, advUnusable:
					wantNotReached++
				}
			}
			if notMeasured != wantNotMeasured {
				t.Errorf("%q counted %d unmeasured, want %d", observation[0].Summary(),
					notMeasured, wantNotMeasured)
			}
			if reached != wantReached {
				t.Errorf("%q counted %d reached, want %d", observation[0].Summary(),
					reached, wantReached)
			}
			if notReached != wantNotReached {
				t.Errorf("%q counted %d not reached, want %d.\n\nAn endpoint svcdoctor "+
					"never measured is not one that refused; collapsing the two is how "+
					"less evidence produces a stronger claim.",
					observation[0].Summary(), notReached, wantNotReached)
			}
		})
	})
	if checked == 0 {
		t.Fatal("no generated set produced an observation; this property is vacuous")
	}
	t.Logf("%d of 512 generated sets produced a topology observation", checked)
}

// parseCounts reads the three numbers back out of a topology summary.
//
// It is a test-only reader and it exists precisely because docs/FINDINGS.md
// section 3.1 rule 13 forbids a *renderer* from doing this. A test may parse
// prose to check the prose; a consumer may not, and nothing in production does.
func parseCounts(t *testing.T, summary string) (notReached, reached, notMeasured int) {
	t.Helper()

	switch {
	case strings.HasPrefix(summary, "None of the "):
		var total int
		if _, err := fmt.Sscanf(summary, "None of the %d broker endpoints", &total); err != nil {
			t.Fatalf("parsing %q: %v", summary, err)
		}
		return total, 0, 0
	case strings.HasPrefix(summary, "The one broker endpoint"):
		return 1, 0, 0
	case strings.Contains(summary, "the other"):
		var total int
		if _, err := fmt.Sscanf(summary, "%d of the %d broker endpoints", &notReached, &total); err != nil {
			t.Fatalf("parsing %q: %v", summary, err)
		}
		return notReached, total - notReached, 0
	}

	var total int
	if _, err := fmt.Sscanf(summary, "%d of the %d broker endpoints", &notReached, &total); err != nil {
		t.Fatalf("parsing %q: %v", summary, err)
	}
	tail := summary[strings.Index(summary, "; ")+2:]
	if _, err := fmt.Sscanf(tail, "%d", &reached); err != nil {
		t.Fatalf("parsing the reached count of %q: %v", summary, err)
	}
	rest := tail[strings.Index(tail, " and ")+len(" and "):]
	if _, err := fmt.Sscanf(rest, "%d", &notMeasured); err != nil {
		t.Fatalf("parsing the unmeasured count of %q: %v", summary, err)
	}
	return notReached, reached, notMeasured
}

// TestKP06AndKP07APartialSetProducesNoTotalAndNoIsolation.
//
// Two claims are forbidden on an incomplete set and they point in opposite
// directions. "None of them" over-reports the failure; "only this one" over-
// reports the health of everything else. Both need the same missing fact.
func TestKP06AndKP07APartialSetProducesNoTotalAndNoIsolation(t *testing.T) {
	checked := 0
	everyTriple(func(name string, outcomes []advertisedOutcome) {
		partial := slices.Contains(outcomes, advNotMeasured) ||
			slices.Contains(outcomes, advCancelled)
		if !partial {
			return
		}
		t.Run(name, func(t *testing.T) {
			r := topologyRun(t, true, outcomes...)
			observation, hypothesis := topologyClaims(r)
			if len(hypothesis) != 0 {
				t.Errorf("a partial set produced a suitability hypothesis; the claim is " +
					"about the whole set and the whole set was not measured")
			}
			if len(observation) == 0 {
				return
			}
			checked++
			summary := observation[0].Summary()
			for _, forbidden := range []string{"None of the", "the other", "The one broker endpoint"} {
				if strings.Contains(summary, forbidden) {
					t.Errorf("a partial set produced %q, which contains %q — a total "+
						"nobody established", summary, forbidden)
				}
			}
			if !strings.Contains(summary, "not measured") {
				t.Errorf("a partial set produced %q without naming the unmeasured "+
					"endpoints", summary)
			}
		})
	})
	if checked == 0 {
		t.Fatal("no partial set produced an observation; this property is vacuous")
	}
}

// --- K-P05: a withheld credential is not a rejected one ---------------------

// TestKP05AWithheldCredentialIsNeverAnAuthenticationFailure.
//
// svcdoctor's own channel policy declining to present a credential is a decision
// svcdoctor made, and reporting it as the endpoint refusing one would send an
// operator to rotate a credential nobody evaluated. The same holds for a run that
// had no credential to present.
func TestKP05AWithheldCredentialIsNeverAnAuthenticationFailure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class domain.FailureClass
		want  domain.FindingCode
	}{
		{"policy withheld it", domain.FailureExecSkippedByPolicy, diagnosiskafka.CodeCredentialWithheld},
		{"the run had none", domain.FailureExecRequiredInputMissing, diagnosiskafka.CodeCredentialNotConfigured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newKafkaGraph(t)
			s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
			s.protocolStage("k-apiversions", domain.LayerProtocol, kafkaStepAPIVersions,
				domain.StatePass, domain.FailureNone)
			s.protocolStage("k-auth", domain.LayerAuth, kafkaStepSASLAuthenticate,
				domain.StateSkipped, tc.class)
			r := diagnoseKafka(t, s.freeze(), false)

			if len(r.findingsWithCode(tc.want)) != 1 {
				t.Fatalf("codes = %v, want one %s", r.codes(), tc.want)
			}
			if got := r.findingsWithCode(diagnosiskafka.CodeCredentialsRejected); len(got) != 0 {
				t.Error("a credential nobody presented was reported as rejected")
			}
			if got := r.findingsWithCode(diagnosiskafka.CodeAuthenticationNotCompleted); len(got) != 0 {
				t.Error("a deliberate refusal was reported as a negotiation that broke down")
			}
			observation, hypothesis := topologyClaims(r)
			if len(observation) != 0 || len(hypothesis) != 0 {
				t.Error("no topology was learned, and a topology claim was made anyway")
			}
			assertRefuses(t, r, []forbiddenClaim{
				{"rejected", "nothing was presented for anyone to reject"},
				{"invalid", "no credential was evaluated"},
				{"broadening", "widening a credential's authority is never advised"},
				{"reuse the", "a bootstrap credential does not travel to a discovered endpoint"},
			})
		})
	}
}

// --- K-P08 and K-P09: address shape is not an incident ----------------------

// TestKP08AndKP09AReachableAddressIsNeverAConfigurationClaim.
//
// The heuristic this refuses is genuinely tempting: an advertised loopback
// address is the single most common Kafka misconfiguration in the wild. It is
// also correct when the client and the broker share a host, and svcdoctor cannot
// tell the two apart. The failure is the evidence; the shape of the address
// is not.
func TestKP08AndKP09AReachableAddressIsNeverAConfigurationClaim(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1", "10.30.0.1", "192.168.44.7", "broker.example",
	} {
		t.Run(host, func(t *testing.T) {
			s := healthyThroughMetadata(t)
			s.advertise(1, host, 9092, advReachedPlain)
			r := diagnoseKafka(t, s.freeze(), false)

			if len(r.report.Findings()) != 0 {
				t.Errorf("a reachable advertisement produced %v; a working endpoint is "+
					"not an incident whatever its address looks like", r.codes())
			}
		})
	}
}

// TestKP08AndKP09AnUnreachableAddressIsDiagnosedByItsFailureNotItsShape.
//
// The mirror image: when the endpoint really is unreachable, the claim must be
// identical whatever the address looks like. A rule that said more about
// 127.0.0.1 than about broker.example would be reasoning from a shape.
func TestKP08AndKP09AnUnreachableAddressIsDiagnosedByItsFailureNotItsShape(t *testing.T) {
	var summaries []string
	for _, host := range []string{"127.0.0.1", "10.30.0.1", "192.168.44.7", "broker.example"} {
		s := healthyThroughMetadata(t)
		s.advertise(1, host, 9092, advTCPRefused)
		r := diagnoseKafka(t, s.freeze(), false)

		observation, hypothesis := topologyClaims(r)
		if len(observation) != 1 || len(hypothesis) != 1 {
			t.Fatalf("%s produced %d observations and %d hypotheses, want 1 and 1",
				host, len(observation), len(hypothesis))
		}
		summaries = append(summaries, observation[0].Summary()+"|"+hypothesis[0].Summary())
		assertRefuses(t, r, []forbiddenClaim{
			{"loopback", "the address shape is never the claim"},
			{"private address", "the same"},
			{"rfc1918", "the same"},
			{"should advertise", "svcdoctor states no intended configuration"},
		})
	}
	for i := 1; i < len(summaries); i++ {
		if summaries[i] != summaries[0] {
			t.Errorf("the claim varies with the address shape:\n  %s\n  %s",
				summaries[0], summaries[i])
		}
	}
}

// --- K-P10 and K-P11: monotonicity ------------------------------------------

// TestKP10PeerSuccessNeverStrengthensASetWideClaim is contradiction
// monotonicity, and it is the property the suitability hypothesis lives or dies
// by.
//
// Adding a reachable endpoint is evidence *against* "the advertised set is
// unusable from here". It must weaken or remove the claim, and it must never
// strengthen it.
func TestKP10PeerSuccessNeverStrengthensASetWideClaim(t *testing.T) {
	failing := topologyRun(t, false, advTCPRefused, advTCPRefused, advTCPRefused)
	_, hypothesis := topologyClaims(failing)
	if len(hypothesis) != 1 {
		t.Fatalf("the all-failed set produced %d hypotheses, want 1", len(hypothesis))
	}
	before := hypothesis[0].Confidence()

	for _, reachable := range []advertisedOutcome{advReachedPlain, advReachedTLS} {
		t.Run(outcomeName(reachable), func(t *testing.T) {
			mixed := topologyRun(t, false, advTCPRefused, advTCPRefused, reachable)
			_, after := topologyClaims(mixed)
			if len(after) != 0 {
				t.Fatalf("a reachable peer left the set-wide hypothesis standing at %s "+
					"(was %s); observed evidence inconsistent with a claim suppresses "+
					"it rather than qualifying it", after[0].Confidence(), before)
			}
		})
	}
}

// TestKP11RemovingEvidenceNeverStrengthensAnything is epistemic monotonicity in
// its general form: less evidence, a same-or-weaker claim.
//
// It works by degrading each endpoint in turn from a positively observed
// outcome to an unmeasured one, and requiring every claim to weaken or vanish.
func TestKP11RemovingEvidenceNeverStrengthensAnything(t *testing.T) {
	base := []advertisedOutcome{advTCPRefused, advTCPRefused, advTCPRefused}
	full := topologyRun(t, false, base...)
	_, fullHypothesis := topologyClaims(full)
	if len(fullHypothesis) != 1 {
		t.Fatalf("the complete set produced %d hypotheses, want 1", len(fullHypothesis))
	}

	for i := range base {
		t.Run("endpoint-"+strconv.Itoa(i), func(t *testing.T) {
			degraded := slices.Clone(base)
			degraded[i] = advNotMeasured
			r := topologyRun(t, true, degraded...)

			_, hypothesis := topologyClaims(r)
			if len(hypothesis) != 0 {
				t.Errorf("degrading one endpoint to unmeasured left a set-wide "+
					"hypothesis at %s", hypothesis[0].Confidence())
			}

			observation, _ := topologyClaims(r)
			if len(observation) == 1 && strings.Contains(observation[0].Summary(), "None of the") {
				t.Errorf("degrading one endpoint to unmeasured preserved a universal "+
					"negative: %q", observation[0].Summary())
			}
		})
	}

	// And the sharpest form: removing the Metadata success removes the whole
	// topology surface rather than leaving a claim behind.
	s := newKafkaGraph(t)
	s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
	s.protocolStage("k-auth", domain.LayerAuth, kafkaStepSASLAuthenticate,
		domain.StatePass, domain.FailureNone)
	s.metadata(domain.StateUnknown, domain.FailureExecLocalTimeout)
	r := diagnoseKafka(t, s.freeze(), true)
	observation, hypothesis := topologyClaims(r)
	if len(observation) != 0 || len(hypothesis) != 0 {
		t.Error("an unmeasured Metadata exchange left a topology claim behind")
	}
}

// --- K-P12 and K-P13: determinism -------------------------------------------

// TestKP12RegistrationOrderDoesNotAffectTheOutput.
//
// Wiring order is a property of the composition root and must not reach a
// report. This shuffles the Kafka rule set by rotation and requires the encoded
// findings to be byte-identical.
func TestKP12RegistrationOrderDoesNotAffectTheOutput(t *testing.T) {
	s := healthyThroughMetadata(t)
	s.advertise(1, "b1.example", 9092, advReachedPlain)
	s.advertise(2, "b2.example", 9092, advTCPRefused)
	s.advertise(3, "b3.example", 9092, advTLSIdentityMismatch)
	g := s.freeze()

	rules := kafkaRules()
	var want string
	for rotation := range rules {
		rotated := slices.Concat(rules[rotation:], rules[:rotation])

		set := diagnosis.NewRuleSet().Add("diag/failure-boundary", diagnosis.FailureBoundary)
		for _, r := range rotated {
			set.Add(r.id, r.rule)
		}
		registry, err := set.Freeze()
		if err != nil {
			t.Fatalf("freezing rotation %d: %v", rotation, err)
		}
		outcome := diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{Graph: g})
		got := encode(t, outcome.Findings())
		if rotation == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("rotation %d produced different findings:\n got %s\nwant %s",
				rotation, got, want)
		}
	}
}

// TestKP13BrokerDiscoveryOrderDoesNotAffectTheOutput.
//
// A cluster chooses the order brokers appear in a Metadata response and is free
// to change it between calls. A report that varied with it would be
// non-deterministic for reasons entirely outside svcdoctor.
func TestKP13BrokerDiscoveryOrderDoesNotAffectTheOutput(t *testing.T) {
	outcomes := []advertisedOutcome{advReachedPlain, advTCPRefused, advNotMeasured}

	build := func(order []int) string {
		s := healthyThroughMetadata(t)
		for _, i := range order {
			s.advertise(i+1, fmt.Sprintf("b%d.example", i+1), 9092, outcomes[i])
		}
		r := diagnoseKafka(t, s.freeze(), true)
		observation, _ := topologyClaims(r)
		if len(observation) != 1 {
			t.Fatalf("order %v produced %d observations, want 1", order, len(observation))
		}
		return observation[0].Summary() + "|" + encode(t, observation[0].EvidenceRefs())
	}

	want := build([]int{0, 1, 2})
	for _, order := range [][]int{{2, 1, 0}, {1, 0, 2}, {0, 2, 1}, {2, 0, 1}, {1, 2, 0}} {
		if got := build(order); got != want {
			t.Errorf("discovery order %v changed the claim:\n got %s\nwant %s", order, got, want)
		}
	}
}

// --- K-P14: hostile metadata -------------------------------------------------

// TestKP14HostileMetadataNeverReachesTrustedProse is ADR 0081 section 2.7 for
// this phase.
//
// A broker chooses its advertised hostname, and a Metadata response is
// attacker-controlled if the peer is. The endpoint reaches the report as a
// subject and as evidence, where it is typed, bounded and redactable; it must
// never be interpolated into a summary, a detail, a discriminator or a
// recommendation, where a reader would trust it and a Markdown or terminal
// consumer would render it.
func TestKP14HostileMetadataNeverReachesTrustedProse(t *testing.T) {
	hostile := []string{
		"evil.example",
		"a-very-long-name-that-goes-on-and-on-and-on-and-on-and-on.example",
		"UPPERCASE.EXAMPLE",
		"xn--e1afmkfd.example",
		"b1.example.b2.example.b3.example",
	}

	for _, host := range hostile {
		t.Run(host, func(t *testing.T) {
			s := healthyThroughMetadata(t)
			s.advertise(1, host, 9092, advTCPRefused)
			r := diagnoseKafka(t, s.freeze(), false)

			observation, hypothesis := topologyClaims(r)
			for _, f := range slices.Concat(observation, hypothesis) {
				prose := f.Summary() + "\n" + f.Detail() + "\n" + f.Discriminator()
				for _, rec := range f.Recommendations() {
					prose += "\n" + rec.Action()
				}
				if strings.Contains(strings.ToLower(prose), strings.ToLower(host)) {
					t.Errorf("%s interpolated the advertised hostname into its prose:\n%s",
						f.Code(), prose)
				}
				assertProseIsInert(t, f.Code(), prose)
			}
		})
	}
}

// TestKP14TheProseIsIdenticalWhateverTheAdvertisedNameIs is the same property
// stated positively, and it is the stronger of the two.
//
// A substring check can be defeated by an encoding; byte equality across
// completely different advertised names cannot.
func TestKP14TheProseIsIdenticalWhateverTheAdvertisedNameIs(t *testing.T) {
	var want string
	for i, host := range []string{"a.example", "zzzz.example", "10.30.0.9", "127.0.0.1"} {
		s := healthyThroughMetadata(t)
		s.advertise(1, host, 9092, advTCPRefused)
		r := diagnoseKafka(t, s.freeze(), false)

		observation, hypothesis := topologyClaims(r)
		var prose strings.Builder
		for _, f := range slices.Concat(observation, hypothesis) {
			prose.WriteString(f.Summary())
			prose.WriteString(f.Detail())
			prose.WriteString(f.Discriminator())
			for _, rec := range f.Recommendations() {
				prose.WriteString(rec.Action())
			}
		}
		if i == 0 {
			want = prose.String()
			if want == "" {
				t.Fatal("no prose was produced; this property is vacuous")
			}
			continue
		}
		if prose.String() != want {
			t.Errorf("advertising %q changed the trusted prose:\n got %q\nwant %q",
				host, prose.String(), want)
		}
	}
}

// assertProseIsInert checks that a claim cannot act on the surfaces it is
// rendered into.
func assertProseIsInert(t *testing.T, code domain.FindingCode, prose string) {
	t.Helper()

	for _, bad := range []struct {
		what      string
		substring string
	}{
		{"a carriage return", "\r"},
		{"a tab", "\t"},
		{"an ANSI escape", "\x1b"},
		{"a NUL", "\x00"},
		{"a backtick fence", "```"},
		{"a Markdown link", "]("},
		{"a JSON brace", "{\""},
	} {
		if strings.Contains(prose, bad.substring) {
			t.Errorf("%s prose contains %s, which the terminal, Markdown and JSON "+
				"projections would each read differently", code, bad.what)
		}
	}
}

// --- K-P15: protocol compatibility, not implementation identity -------------

// TestKP15NoClaimNamesAKafkaImplementation.
//
// Redpanda speaks the Kafka protocol and is graded in docs/COMPATIBILITY.md; so
// might anything else. Every claim these rules make rests on a protocol exchange
// and a transport result, neither of which identifies an implementation, so no
// claim may name one or imply one.
func TestKP15NoClaimNamesAKafkaImplementation(t *testing.T) {
	implementationWords := []string{
		"apache", "confluent", "redpanda", "warpstream", "msk", "aiven",
		"broker process", "java", "jvm", "kraft", "zookeeper",
	}

	seen := 0
	everyTriple(func(name string, outcomes []advertisedOutcome) {
		r := topologyRun(t, true, outcomes...)
		observation, hypothesis := topologyClaims(r)
		for _, f := range slices.Concat(observation, hypothesis) {
			seen++
			prose := strings.ToLower(f.Summary() + " " + f.Detail() + " " + f.Discriminator())
			for _, rec := range f.Recommendations() {
				prose += " " + strings.ToLower(rec.Action())
			}
			for _, word := range implementationWords {
				if strings.Contains(prose, word) {
					t.Errorf("%s names %q; svcdoctor observed a Kafka-protocol endpoint "+
						"and not an implementation", f.Code(), word)
				}
			}
		}
	})
	if seen == 0 {
		t.Fatal("no claim was examined; this property is vacuous")
	}
}

// --- the renderer, the redaction and the exit contract ----------------------

// TestTheTopologyCountsMatchTheRenderedTopologyLine is the cross-implementation
// agreement ADR 0084 section 4 requires.
//
// `internal/app`, `internal/render/terminal` and `internal/diagnosis/kafka` each
// hold ADR 0051's classification, and depguard forbids any two of them sharing
// an implementation. So the agreement is proven at the output boundary: one
// graph, one report, and the finding's numbers compared against the terminal's.
//
// A divergence here is a report whose finding and whose summary line contradict
// each other three lines apart, which is worse than either being wrong alone.
func TestTheTopologyCountsMatchTheRenderedTopologyLine(t *testing.T) {
	compared := 0
	everyTriple(func(name string, outcomes []advertisedOutcome) {
		t.Run(name, func(t *testing.T) {
			incomplete := slices.Contains(outcomes, advNotMeasured) ||
				slices.Contains(outcomes, advCancelled)
			r := topologyRun(t, incomplete, outcomes...)

			observation, _ := topologyClaims(r)
			if len(observation) == 0 {
				return
			}
			notReached, reached, notMeasured := parseCounts(t, observation[0].Summary())

			line := topologyLineOf(t, r.terminal(t))
			if line == "" {
				t.Fatalf("the terminal rendered no topology line for %v", outcomes)
			}
			var renderedReached, renderedTotal, renderedNotMeasured int
			if _, err := fmt.Sscanf(line, "%d of %d advertised broker endpoints reached",
				&renderedReached, &renderedTotal); err != nil {
				t.Fatalf("parsing %q: %v", line, err)
			}
			if idx := strings.Index(line, ", "); idx >= 0 {
				if _, err := fmt.Sscanf(line[idx+2:], "%d not measured", &renderedNotMeasured); err != nil {
					t.Fatalf("parsing the unmeasured clause of %q: %v", line, err)
				}
			}
			compared++

			if renderedReached != reached {
				t.Errorf("the finding says %d reached and the terminal says %d:\n  %q\n  %q",
					reached, renderedReached, observation[0].Summary(), line)
			}
			if renderedNotMeasured != notMeasured {
				t.Errorf("the finding says %d not measured and the terminal says %d:\n  %q\n  %q",
					notMeasured, renderedNotMeasured, observation[0].Summary(), line)
			}
			if got := renderedTotal - renderedReached - renderedNotMeasured; got != notReached {
				t.Errorf("the finding says %d not reached and the terminal implies %d:\n  %q\n  %q",
					notReached, got, observation[0].Summary(), line)
			}
		})
	})
	if compared == 0 {
		t.Fatal("no scenario compared the two; this agreement test is vacuous")
	}
	t.Logf("%d scenarios compared the finding against the rendered line", compared)
}

// topologyLineOf pulls the terminal's topology count line out of a rendering.
func topologyLineOf(t *testing.T, rendered string) string {
	t.Helper()
	for _, line := range strings.Split(rendered, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "topology") &&
			strings.Contains(trimmed, "advertised broker endpoints reached") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "topology"))
		}
	}
	return ""
}

// TestTheTopologyClaimsSurvivePseudonymization is docs/FINDINGS.md section 3.1
// rule 16 and ADR 0018.
//
// Read the finding with every host and address replaced and it must still make
// sense, the subject relationship must survive, and no explanation may
// reconstruct the raw identity.
func TestTheTopologyClaimsSurvivePseudonymization(t *testing.T) {
	s := healthyThroughMetadata(t)
	s.advertise(1, "b1.example", 9092, advTCPRefused)
	s.advertise(2, "b2.example", 9092, advTCPRefused)
	r := diagnoseKafka(t, s.freeze(), false)

	shareable := r.shareableJSON(t)
	for _, secret := range []string{"b1.example", "b2.example", "bootstrap.example", "10.30.0.1"} {
		if strings.Contains(shareable, secret) {
			t.Errorf("the shareable report still carries %q", secret)
		}
	}

	// The counts survive, because they carry no identity.
	if !strings.Contains(shareable, "None of the 2 broker endpoints") {
		t.Errorf("the shareable report lost the topology claim:\n%s", shareable)
	}
	if !strings.Contains(shareable, "may not be usable from this client") {
		t.Errorf("the shareable report lost the suitability hypothesis:\n%s", shareable)
	}

	// And the two claims still name one subject between them, so a reader can
	// still tell they are about the same exchange.
	var subjects []string
	for _, f := range r.shareable.Findings() {
		switch f.Code() {
		case diagnosiskafka.CodeAdvertisedTopologyReachability,
			diagnosiskafka.CodeAdvertisedTopologyUnsuitable:
			subjects = append(subjects, f.Subject().Ref())
		}
	}
	if len(subjects) != 2 {
		t.Fatalf("the shareable report carries %d topology claims, want 2", len(subjects))
	}
	if subjects[0] != subjects[1] {
		t.Errorf("pseudonymization split one exchange into two subjects: %q and %q",
			subjects[0], subjects[1])
	}
}

// TestTheTopologyObservationCannotChangeAnExitCode is the exit contract.
//
// `deriveSummary` sets PROBLEMS_FOUND only on ERROR or CRITICAL. The observation
// is INFO and the hypothesis is WARN, so neither can promote an otherwise clean
// run — which matters because a scenario with an unreachable advertised endpoint
// already exits 1 on the per-endpoint ERROR, and nothing here may change that in
// either direction.
func TestTheTopologyObservationCannotChangeAnExitCode(t *testing.T) {
	for _, f := range slices.Concat(
		func() []domain.Finding {
			r := topologyRun(t, false, advTCPRefused, advTCPRefused)
			observation, hypothesis := topologyClaims(r)
			return slices.Concat(observation, hypothesis)
		}(),
	) {
		switch f.Code() {
		case diagnosiskafka.CodeAdvertisedTopologyReachability:
			if f.Severity() != domain.SeverityInfo {
				t.Errorf("the observation is %s; INFO is what keeps it out of the exit "+
					"contract", f.Severity())
			}
		case diagnosiskafka.CodeAdvertisedTopologyUnsuitable:
			if f.Severity() != domain.SeverityWarn {
				t.Errorf("the hypothesis is %s, want WARN", f.Severity())
			}
		}
		if f.Severity() == domain.SeverityCritical {
			t.Errorf("%s is CRITICAL; no Phase 10.2 claim carries that impact", f.Code())
		}
	}
}

// --- performance -------------------------------------------------------------

// TestTheTopologyRulesScaleLinearlyInTheAdvertisedSet is section 50's budget.
//
// A managed cluster can advertise hundreds of endpoints. The rules walk each
// advertisement's own sweep once and never compare a pair of them, so the cost
// is linear in nodes and edges; this measures that the wall-clock cost grows
// with the set rather than with its square, and records the numbers rather than
// asserting a threshold nobody can hold across machines.
func TestTheTopologyRulesScaleLinearlyInTheAdvertisedSet(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling measurement")
	}

	var previous time.Duration
	for _, n := range []int{3, 10, 50, 100, 500} {
		s := healthyThroughMetadata(t)
		for i := 0; i < n; i++ {
			outcome := advReachedPlain
			if i%3 == 0 {
				outcome = advTCPRefused
			}
			s.advertise(i+1, fmt.Sprintf("b%d.example", i+1), 9092, outcome)
		}
		g := s.freeze()
		ctx := diagnosis.RuleContext{Graph: g}

		start := time.Now()
		for i := 0; i < 20; i++ {
			diagnosiskafka.AdvertisedTopologyReachability(ctx)
			diagnosiskafka.AdvertisedTopologyUnsuitable(ctx)
		}
		elapsed := time.Since(start) / 20

		t.Logf("%3d advertised endpoints (%4d nodes): %v", n, g.Len(), elapsed)
		if previous > 0 && n >= 100 && elapsed > previous*25 {
			t.Errorf("%d endpoints took %v against %v for the previous step; the growth "+
				"is steeper than the set and suggests pairwise work", n, elapsed, previous)
		}
		previous = elapsed
	}
}

// TestTheTopologyRulesTerminateOnALargeSet is the bound the fuzz targets rely
// on: no traversal here depends on a caller's invariant.
func TestTheTopologyRulesTerminateOnALargeSet(t *testing.T) {
	s := healthyThroughMetadata(t)
	for i := 0; i < 500; i++ {
		s.advertise(i+1, fmt.Sprintf("b%d.example", i+1), 9092, advTCPRefused)
	}
	r := diagnoseKafka(t, s.freeze(), false)

	observation, hypothesis := topologyClaims(r)
	if len(observation) != 1 || len(hypothesis) != 1 {
		t.Fatalf("500 endpoints produced %d observations and %d hypotheses, want 1 and 1",
			len(observation), len(hypothesis))
	}
	if !strings.Contains(observation[0].Summary(), "None of the 500 broker endpoints") {
		t.Errorf("summary = %q", observation[0].Summary())
	}
}
