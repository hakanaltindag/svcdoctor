package kafka

import (
	"slices"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// protocolNode records one Kafka protocol node at the layer its step requires.
func (b *builder) protocolNode(
	step domain.Step, state domain.State, class domain.FailureClass,
	attributes map[domain.AttributeKey]domain.AttrValue,
) domain.EvidenceID {
	b.t.Helper()

	layer, ok := protocolLayers[step]
	if !ok {
		b.t.Fatalf("step %s is not a Kafka protocol step", step)
	}
	// The identifier carries the class as well as the step, so a fixture holding
	// several outcomes of one step does not collide. Production identifiers do
	// not need this — one run performs a step once per path — but a table-driven
	// test builds every outcome side by side.
	return b.node(
		string(step)+"/primary.internal:9092/10.0.0.1/"+class.String(), "10.0.0.1:9092",
		layer, step, state, class, "", attributes)
}

// findingsFor runs the rule over a graph holding exactly one protocol node.
func findingsFor(
	t *testing.T, step domain.Step, state domain.State, class domain.FailureClass,
) []domain.Finding {
	t.Helper()

	b := newBuilder(t)
	b.protocolNode(step, state, class, nil)
	return Protocol(rctx(b.freeze()))
}

// codeFor asserts exactly one finding and returns it.
func codeFor(
	t *testing.T, step domain.Step, state domain.State, class domain.FailureClass,
) domain.Finding {
	t.Helper()

	found := findingsFor(t, step, state, class)
	if len(found) != 1 {
		t.Fatalf("%s %s/%s produced %d findings, want exactly 1",
			step, state, class, len(found))
	}
	return found[0]
}

// assertSilent asserts the rule claims nothing.
func assertSilent(
	t *testing.T, step domain.Step, state domain.State, class domain.FailureClass, why string,
) {
	t.Helper()

	if found := findingsFor(t, step, state, class); len(found) != 0 {
		t.Errorf("%s %s/%s produced %d findings, want 0: %s",
			step, state, class, len(found), why)
	}
}

// --- the authorized table, outcome by outcome --------------------------------

// TestEveryAuthorizedOutcomeProducesItsCode walks the whole table.
//
// It is driven from protocolClaims rather than from a hand-written list, so a
// mapping added without a test cannot exist: the loop covers whatever the table
// holds, and the count assertion below pins the table's size.
func TestEveryAuthorizedOutcomeProducesItsCode(t *testing.T) {
	for key, want := range protocolClaims {
		t.Run(string(key.step)+"/"+key.state.String()+"/"+key.failure.String(), func(t *testing.T) {
			finding := codeFor(t, key.step, key.state, key.failure)

			if got := finding.Code(); got != want.code {
				t.Errorf("code = %s, want %s", got, want.code)
			}
			if got := finding.Severity(); got != want.severity {
				t.Errorf("severity = %s, want %s", got, want.severity)
			}
			if got := finding.VantageDependent(); got != want.vantageDependent {
				t.Errorf("vantageDependent = %v, want %v", got, want.vantageDependent)
			}
			if got := finding.Kind(); got != domain.FindingKindConfirmed {
				t.Errorf("kind = %s, want CONFIRMED: every claim restates a recorded outcome", got)
			}
			if got := finding.Confidence(); got != domain.ConfidenceHigh {
				t.Errorf("confidence = %s, want HIGH", got)
			}
			if got := finding.Layer(); got != protocolLayers[key.step] {
				t.Errorf("layer = %s, want %s", got, protocolLayers[key.step])
			}
			if got := finding.Subject().Ref(); got != "10.0.0.1:9092" {
				t.Errorf("subject = %q, want the concrete endpoint the exchange ran against", got)
			}
			if len(finding.Recommendations()) != 1 {
				t.Errorf("recommendations = %d, want 1", len(finding.Recommendations()))
			}
		})
	}
}

// TestTheAuthorizedTableIsExactlyTheProducedOutcomes is the ADR 0054 gate in
// executable form.
//
// The want list is derived by reading internal/adapter/kafka: each classify
// function, each error-code mapping, and the three record* helpers on the
// authenticate path. If a producer gains an outcome, this test fails until the
// table gains an owner — which is the whole invariant, since an unowned FAIL is
// what stopped Phase 6.1c.
//
// UNKNOWN with EXEC_LOCAL_TIMEOUT or EXEC_CANCELLED is deliberately excluded at
// every step; those are Result.Incomplete's, not a finding's.
func TestTheAuthorizedTableIsExactlyTheProducedOutcomes(t *testing.T) {
	want := []outcome{
		// internal/adapter/kafka/apiversions.go classify + protocolFailure.
		{servicekafka.StepAPIVersions, domain.StateFail, domain.FailureProtocolUnsupportedVersion},
		{servicekafka.StepAPIVersions, domain.StateFail, domain.FailureProtocolUnexpectedResponse},
		{servicekafka.StepAPIVersions, domain.StateFail, domain.FailureProtocolMalformedResponse},
		{servicekafka.StepAPIVersions, domain.StateFail, domain.FailureProtocolPeerClosed},

		// saslhandshake.go classify + handshakeFailure, which falls through to
		// protocolFailure for every code but UNSUPPORTED_SASL_MECHANISM.
		{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureAuthMechanismNotOffered},
		{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureProtocolUnsupportedVersion},
		{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureProtocolUnexpectedResponse},
		{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureProtocolMalformedResponse},
		{servicekafka.StepSASLHandshake, domain.StateFail, domain.FailureProtocolPeerClosed},

		// saslauthenticate.go classify + authenticationFailure, which falls
		// through to handshakeFailure — so AUTH_MECHANISM_NOT_OFFERED is
		// reachable here too — plus the three record* helpers.
		{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureAuthCredentialsRejected},
		{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureAuthMechanismNotOffered},
		{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureProtocolUnsupportedVersion},
		{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureProtocolUnexpectedResponse},
		{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureProtocolMalformedResponse},
		{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureProtocolPeerClosed},
		{servicekafka.StepSASLAuthenticate, domain.StateUnknown, domain.FailureAuthMechanismUnsupported},
		// Phase 6.2. SCRAM authenticates both parties, so the wire package can
		// now report that the *broker* failed to prove it knows the credential —
		// the opposite direction from a rejection, and a different claim.
		{servicekafka.StepSASLAuthenticate, domain.StateFail, domain.FailureAuthPeerVerificationFailed},
		// Phase 6.2. An identity or password outside the printable-ASCII range
		// svcdoctor can prepare for SCRAM, an iteration count above the ceiling,
		// or a local derivation fault. All are gaps in svcdoctor.
		{servicekafka.StepSASLAuthenticate, domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor},
		{servicekafka.StepSASLAuthenticate, domain.StateSkipped, domain.FailureExecSkippedByPolicy},
		{servicekafka.StepSASLAuthenticate, domain.StateSkipped, domain.FailureExecRequiredInputMissing},

		// metadata.go classify. It consults no broker error code, so
		// PROTOCOL_UNSUPPORTED_VERSION is unreachable here.
		{servicekafka.StepMetadata, domain.StateFail, domain.FailureProtocolUnexpectedResponse},
		{servicekafka.StepMetadata, domain.StateFail, domain.FailureProtocolMalformedResponse},
		{servicekafka.StepMetadata, domain.StateFail, domain.FailureProtocolPeerClosed},
	}

	for _, key := range want {
		if _, owned := protocolClaims[key]; !owned {
			t.Errorf("%s %s/%s is produced and has no owner.\n\n"+
				"ADR 0054: a production-reachable FAIL outcome with no diagnosis owner "+
				"reaches a report as findings=[] and status OK.",
				key.step, key.state, key.failure)
		}
	}
	for key := range protocolClaims {
		if !slices.Contains(want, key) {
			t.Errorf("%s %s/%s is mapped but no producer emits it.\n\n"+
				"A dead mapping authorizes a claim for evidence that cannot occur.",
				key.step, key.state, key.failure)
		}
	}
	if len(protocolClaims) != len(want) {
		t.Errorf("table holds %d outcomes, the producers emit %d", len(protocolClaims), len(want))
	}
}

// TestProtocolCodeCount pins how many codes exist, so a merge or a split is a
// deliberate edit rather than a side effect.
func TestProtocolCodeCount(t *testing.T) {
	codes := map[domain.FindingCode]bool{}
	for _, c := range protocolClaims {
		codes[c.code] = true
	}
	// 11 since Phase 6.2 added KAFKA_PEER_VERIFICATION_FAILED. SCRAM
	// authenticates both parties, so "the broker did not prove it knows the
	// credential" became reachable and is a different claim from "the broker
	// refused what svcdoctor presented".
	if len(codes) != 11 {
		t.Errorf("distinct codes = %d, want 11: %v", len(codes), codes)
	}
}

// --- what the rule must stay silent about ------------------------------------

// TestLocalExecutionOutcomesProduceNoFinding is the claim-discipline boundary.
//
// A budget that expired and a cancelled run learned nothing about the endpoint.
// Turning either into a Kafka claim is the local-timeout-as-remote-failure
// mistake; both reach the operator through Result.Incomplete() and exit 4.
func TestLocalExecutionOutcomesProduceNoFinding(t *testing.T) {
	for _, step := range protocolSteps() {
		for _, class := range []domain.FailureClass{
			domain.FailureExecLocalTimeout, domain.FailureExecCancelled,
		} {
			assertSilent(t, step, domain.StateUnknown, class,
				"svcdoctor's own budget or a cancellation is not a fact about the endpoint")
		}
	}
}

// TestPassProducesNoFinding pins ADR 0052: success is a renderer's outcome line,
// never a finding.
func TestPassProducesNoFinding(t *testing.T) {
	for _, step := range protocolSteps() {
		assertSilent(t, step, domain.StatePass, domain.FailureNone,
			"a passing exchange is reported by the renderer, not claimed by a rule")
	}
}

// TestAFutureFailureClassProducesNoFinding is why the table has no default
// branch.
//
// The class used here is a real declared one that no Kafka producer emits. A
// default folding the unrecognized into a floor would grant it the floor's claim
// — "svcdoctor could not attribute why" — which may be false for a class that is
// perfectly attributable.
func TestAFutureFailureClassProducesNoFinding(t *testing.T) {
	for _, step := range protocolSteps() {
		for _, class := range []domain.FailureClass{
			domain.FailureAuthzDenied,
			domain.FailureResourceNotFound,
			domain.FailureTLSHandshakeFailure,
			domain.FailureExecDepthLimit,
		} {
			assertSilent(t, step, domain.StateFail, class,
				"an unmapped class must not inherit a reviewed claim")
		}
	}
}

// TestAMatchingClassInTheWrongStateProducesNoFinding pins that State is part of
// the key.
//
// A SKIPPED node carrying AUTH_CREDENTIALS_REJECTED is a node disagreeing with
// itself. The rule declines to read it rather than guessing which half is right.
func TestAMatchingClassInTheWrongStateProducesNoFinding(t *testing.T) {
	tests := []struct {
		state domain.State
		class domain.FailureClass
	}{
		{domain.StateSkipped, domain.FailureAuthCredentialsRejected},
		{domain.StateFail, domain.FailureExecRequiredInputMissing},
		{domain.StateFail, domain.FailureExecSkippedByPolicy},
		{domain.StateFail, domain.FailureAuthMechanismUnsupported},
		{domain.StateUnknown, domain.FailureAuthCredentialsRejected},
		{domain.StateSkipped, domain.FailureAuthMechanismUnsupported},
	}
	for _, test := range tests {
		assertSilent(t, servicekafka.StepSASLAuthenticate, test.state, test.class,
			"state and class must agree before a claim is made")
	}
}

// TestAStepAtTheWrongLayerProducesNoFinding pins the layer check.
func TestAStepAtTheWrongLayerProducesNoFinding(t *testing.T) {
	b := newBuilder(t)
	b.node(
		"kafka.metadata/primary.internal:9092/10.0.0.1", "10.0.0.1:9092",
		// Topology is this step's layer; auth is not.
		domain.LayerAuth, servicekafka.StepMetadata,
		domain.StateFail, domain.FailureProtocolPeerClosed, "", nil)

	if found := Protocol(rctx(b.freeze())); len(found) != 0 {
		t.Errorf("findings = %d, want 0: a node disagreeing with itself is not read", len(found))
	}
}

// TestANonKafkaStepProducesNoFinding: the rule owns four steps and nothing else.
func TestANonKafkaStepProducesNoFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 1, "broker-1.internal:9092")
	b.lookup(advertisement, "broker-1.internal", domain.StateFail, domain.FailureDNSNXDomain)

	for _, finding := range Protocol(rctx(b.freeze())) {
		t.Errorf("claimed %s on a step this rule does not own", finding.Code())
	}
}

// --- the five authentication outcomes stay apart -----------------------------

// TestTheFiveAuthenticationOutcomesAreDisjoint is the claim this phase most has
// to protect.
//
// Five different facts, five different next moves, five different codes. The
// risk is not any single mapping but a later change that folds two into an
// umbrella — and the two SKIPPED rows are the pair most at risk, because both
// end with nothing sent.
func TestTheFiveAuthenticationOutcomesAreDisjoint(t *testing.T) {
	tests := []struct {
		name  string
		step  domain.Step
		state domain.State
		class domain.FailureClass
		want  domain.FindingCode
	}{
		{
			name: "peer does not offer the mechanism", step: servicekafka.StepSASLHandshake,
			state: domain.StateFail, class: domain.FailureAuthMechanismNotOffered,
			want: CodeAuthMechanismNotOffered,
		},
		{
			name: "svcdoctor cannot perform the mechanism", step: servicekafka.StepSASLAuthenticate,
			state: domain.StateUnknown, class: domain.FailureAuthMechanismUnsupported,
			want: CodeAuthenticationUnsupportedBySvcdoctor,
		},
		{
			name: "credential withheld by policy", step: servicekafka.StepSASLAuthenticate,
			state: domain.StateSkipped, class: domain.FailureExecSkippedByPolicy,
			want: CodeCredentialWithheld,
		},
		{
			name: "no credential configured", step: servicekafka.StepSASLAuthenticate,
			state: domain.StateSkipped, class: domain.FailureExecRequiredInputMissing,
			want: CodeCredentialNotConfigured,
		},
		{
			name: "credential rejected by the peer", step: servicekafka.StepSASLAuthenticate,
			state: domain.StateFail, class: domain.FailureAuthCredentialsRejected,
			want: CodeCredentialsRejected,
		},
	}

	seen := map[domain.FindingCode]string{}
	for _, test := range tests {
		finding := codeFor(t, test.step, test.state, test.class)
		if got := finding.Code(); got != test.want {
			t.Errorf("%s: code = %s, want %s", test.name, got, test.want)
		}
		if previous, clash := seen[test.want]; clash {
			t.Errorf("%q and %q share code %s; the five outcomes must stay distinct",
				previous, test.name, test.want)
		}
		seen[test.want] = test.name
	}
	if len(seen) != 5 {
		t.Errorf("distinct codes = %d, want 5", len(seen))
	}
}

// TestTheAuthenticationFloorExcludesTheSpecificOutcomes: the floor takes the
// protocol classes and nothing else.
func TestTheAuthenticationFloorExcludesTheSpecificOutcomes(t *testing.T) {
	for key, c := range protocolClaims {
		if c.code != CodeAuthenticationNotCompleted {
			continue
		}
		switch key.failure {
		case domain.FailureProtocolUnsupportedVersion,
			domain.FailureProtocolUnexpectedResponse,
			domain.FailureProtocolMalformedResponse,
			domain.FailureProtocolPeerClosed:
		default:
			t.Errorf("the authentication floor absorbed %s; it names a specific outcome "+
				"that has its own code", key.failure)
		}
		if key.state != domain.StateFail {
			t.Errorf("the authentication floor mapped state %s; a floor describes a "+
				"failed exchange", key.state)
		}
	}
}

// --- prose discipline ---------------------------------------------------------

// TestNoFindingOverclaims scans what svcdoctor asserts and advises.
//
// # Why it reads the summary and the recommendation, and not the detail
//
// A substring scan cannot tell a claim from its denial, and the details here are
// full of deliberate denials: the Metadata floor says it reports nothing about
// topics or partitions, and the ApiVersions floor says it does not state the
// endpoint is not Kafka. Scanning them would flag exactly the sentences that
// make the findings safe.
//
// The summary is the claim and the recommendation is the advice, and neither
// carries a disclaimer. A banned phrase in either is an overclaim with no
// ambiguity. The denials are covered positively by the two tests below.
func TestNoFindingOverclaims(t *testing.T) {
	banned := []string{
		"cluster is healthy", "cluster is unhealthy", "cluster unusable",
		"cluster is broken", "cluster unavailable", "cluster metadata unavailable",
		"wrong password", "incorrect password", "bad password", "wrong credential",
		"is not kafka", "wrong port", "firewall is", "proxy is",
		"broker is too old", "authentication is disabled", "globally",
		"topic", "partition", "consumer lag", "replica", "controller",
		"session established", "root cause",
	}

	for key, c := range protocolClaims {
		asserted := strings.ToLower(c.summary + " " + c.recommendation)
		for _, phrase := range banned {
			if strings.Contains(asserted, phrase) {
				t.Errorf("%s %s/%s: summary or recommendation contains %q, "+
					"which the evidence does not support",
					key.step, key.state, key.failure, phrase)
			}
		}
	}
}

// TestFloorsDenyTheCausesTheyInvite is the positive half of the guard above.
//
// A floor says an exchange did not complete and that svcdoctor could not
// attribute why. The risk is a reader supplying the cause themselves, so each
// floor names the conclusions it is *not* drawing. This asserts those denials
// exist, because deleting one is a silent widening of the claim.
func TestFloorsDenyTheCausesTheyInvite(t *testing.T) {
	tests := []struct {
		name  string
		step  domain.Step
		class domain.FailureClass
		deny  []string
	}{
		{
			name: "ApiVersions floor", step: servicekafka.StepAPIVersions,
			class: domain.FailureProtocolPeerClosed,
			deny:  []string{"could not attribute", "is not", "port is wrong"},
		},
		{
			name: "SASL handshake floor", step: servicekafka.StepSASLHandshake,
			class: domain.FailureProtocolPeerClosed,
			deny:  []string{"could not attribute"},
		},
		{
			name: "authentication floor", step: servicekafka.StepSASLAuthenticate,
			class: domain.FailureProtocolPeerClosed,
			deny:  []string{"could not attribute", "does not state that a credential was"},
		},
		{
			name: "Metadata floor", step: servicekafka.StepMetadata,
			class: domain.FailureProtocolPeerClosed,
			deny:  []string{"says nothing about", "topics", "partitions"},
		},
	}

	for _, test := range tests {
		detail := strings.ToLower(codeFor(t, test.step, domain.StateFail, test.class).Detail())
		for _, phrase := range test.deny {
			if !strings.Contains(detail, phrase) {
				t.Errorf("%s: detail no longer contains %q; the claim widened silently",
					test.name, phrase)
			}
		}
	}
}

// TestMetadataFloorClaimsNothingAboutTopology guards the one overclaim a
// Metadata failure invites.
//
// svcdoctor sends Metadata v1 with an empty topic list. A failure says the
// exchange did not complete and nothing whatsoever about what the cluster
// contains.
func TestMetadataFloorClaimsNothingAboutTopology(t *testing.T) {
	finding := codeFor(t, servicekafka.StepMetadata,
		domain.StateFail, domain.FailureProtocolPeerClosed)

	prose := strings.ToLower(finding.Summary() + " " + finding.Detail())
	if !strings.Contains(prose, "empty topic list") {
		t.Error("the Metadata floor should say what was asked for, so a reader " +
			"cannot read a topology verdict into it")
	}
	for _, phrase := range []string{"topics", "partitions", "controller", "healthy"} {
		// Naming them as things the finding does NOT speak about is fine; the
		// guard is that they never appear as a claim.
		if strings.Contains(prose, phrase+" are") || strings.Contains(prose, phrase+" is broken") {
			t.Errorf("the Metadata floor asserts something about %s", phrase)
		}
	}
}

// TestRecommendationsAreNotExecutable: svcdoctor says where to look, never what
// to run.
func TestRecommendationsAreNotExecutable(t *testing.T) {
	for key, c := range protocolClaims {
		action := c.recommendation
		for _, shell := range []string{"$ ", "kafka-topics.sh", "sudo ", "curl ", "openssl ", "--"} {
			if strings.Contains(action, shell) {
				t.Errorf("%s %s/%s: recommendation %q looks executable",
					key.step, key.state, key.failure, action)
			}
		}
		if action == "" {
			t.Errorf("%s %s/%s has no recommendation", key.step, key.state, key.failure)
		}
	}
}

// TestProtocolRecommendationTextIsValid proves the unreachable branch in
// recommend really is unreachable.
func TestProtocolRecommendationTextIsValid(t *testing.T) {
	for key, c := range protocolClaims {
		if got := recommend(c.recommendation); len(got) != 1 {
			t.Errorf("%s %s/%s: recommendation text was rejected by the model",
				key.step, key.state, key.failure)
		}
	}
}

// TestEveryAuthorizedOutcomeBuildsAValidFinding proves the unreachable branch in
// buildProtocol.
func TestEveryAuthorizedOutcomeBuildsAValidFinding(t *testing.T) {
	for key := range protocolClaims {
		if found := findingsFor(t, key.step, key.state, key.failure); len(found) != 1 {
			t.Errorf("%s %s/%s built no finding; domain.NewFinding rejected the input",
				key.step, key.state, key.failure)
		}
	}
}

// --- references and structure ------------------------------------------------

// TestFindingsReferenceOnlyTheirOwnNode keeps the reference set minimal.
//
// None of these claims is about the logical target and none makes a resolution
// claim, so none cites the anchor or the transport below it.
func TestFindingsReferenceOnlyTheirOwnNode(t *testing.T) {
	for key := range protocolClaims {
		if key.failure == domain.FailureExecSkippedByPolicy {
			continue // has a blocker; covered below.
		}
		b := newBuilder(t)
		id := b.protocolNode(key.step, key.state, key.failure, nil)
		graph := b.freeze()

		found := Protocol(rctx(graph))
		if len(found) != 1 {
			t.Fatalf("%s %s/%s: findings = %d", key.step, key.state, key.failure, len(found))
		}
		refs := found[0].EvidenceRefs()
		if len(refs) != 1 || refs[0] != id {
			t.Errorf("%s %s/%s: refs = %v, want exactly its own node",
				key.step, key.state, key.failure, refs)
		}
	}
}

// TestCredentialWithheldCitesItsBlocker is the one claim that reads an edge.
//
// The claim is *why nothing was attempted*, and the answer is on another node.
// docs/FINDINGS.md section 3.1 item 11 forbids citing a blocked step as a cause;
// here the blocked step is the subject and its blocker is the cause.
func TestCredentialWithheldCitesItsBlocker(t *testing.T) {
	b := newBuilder(t)
	channel := b.node(
		"tls.handshake/primary.internal:9092/10.0.0.1", "10.0.0.1:9092",
		domain.LayerTLS, "tls.handshake", domain.StateFail,
		domain.FailureTLSUnknownAuthority, "", nil)
	skipped := b.protocolNode(servicekafka.StepSASLAuthenticate,
		domain.StateSkipped, domain.FailureExecSkippedByPolicy, nil)
	b.blockedBy(skipped, channel)

	found := Protocol(rctx(b.freeze()))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1", len(found))
	}
	refs := found[0].EvidenceRefs()
	if !slices.Contains(refs, channel) {
		t.Errorf("refs = %v, want the blocker %s: the claim is why nothing was sent",
			refs, channel)
	}
	if !slices.Contains(refs, skipped) {
		t.Errorf("refs = %v, want the node itself %s", refs, skipped)
	}
}

// TestOneNodeProducesAtMostOneFinding: no precedence, no suppression, no second
// rule competing for these steps.
func TestOneNodeProducesAtMostOneFinding(t *testing.T) {
	b := newBuilder(t)
	for key := range protocolClaims {
		b.protocolNode(key.step, key.state, key.failure, nil)
	}
	graph := b.freeze()

	seen := map[domain.EvidenceID]int{}
	for _, finding := range Protocol(rctx(graph)) {
		for _, ref := range finding.EvidenceRefs() {
			node, ok := graph.Node(ref)
			if !ok {
				continue
			}
			if _, owned := protocolLayers[node.Step()]; !owned {
				continue
			}
			seen[ref]++
		}
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("node %s produced %d findings, want at most 1", id, count)
		}
	}
}

// TestTheAdvertisedRulesDoNotCompete: the two existing Kafka rules anchor at
// kafka.broker_advertised and require a passing kafka.metadata, so a failed
// protocol stage cannot make them fire.
func TestTheAdvertisedRulesDoNotCompete(t *testing.T) {
	b := newBuilder(t)
	b.protocolNode(servicekafka.StepMetadata,
		domain.StateFail, domain.FailureProtocolPeerClosed, nil)
	graph := b.freeze()

	if found := AdvertisedEndpointUnreachable(rctx(graph)); len(found) != 0 {
		t.Errorf("the advertised rule claimed %d findings on a failed Metadata exchange",
			len(found))
	}
	if found := UnusableAdvertisement(rctx(graph)); len(found) != 0 {
		t.Errorf("the unusable-advertisement rule claimed %d findings", len(found))
	}
	if found := Protocol(rctx(graph)); len(found) != 1 {
		t.Errorf("the protocol rule produced %d findings, want 1", len(found))
	}
}

// TestProtocolIsDeterministic: the same graph yields the same findings, in the
// same order, every time.
func TestProtocolIsDeterministic(t *testing.T) {
	build := func() []domain.Finding {
		b := newBuilder(t)
		for _, key := range sortedOutcomes() {
			b.protocolNode(key.step, key.state, key.failure, nil)
		}
		return Protocol(rctx(b.freeze()))
	}

	first := build()
	if len(first) != len(protocolClaims) {
		t.Fatalf("findings = %d, want %d", len(first), len(protocolClaims))
	}
	for range 5 {
		next := build()
		if len(next) != len(first) {
			t.Fatalf("finding count drifted: %d then %d", len(first), len(next))
		}
		for i := range first {
			if next[i].Code() != first[i].Code() ||
				next[i].Subject().Ref() != first[i].Subject().Ref() {
				t.Fatalf("finding %d drifted: %s/%s then %s/%s", i,
					first[i].Code(), first[i].Subject().Ref(),
					next[i].Code(), next[i].Subject().Ref())
			}
		}
	}
}

// TestMechanismAppearsInProse: a reader learns which authentication was
// declined, and the attribute is optional so a node without it still builds.
func TestMechanismAppearsInProse(t *testing.T) {
	b := newBuilder(t)
	b.protocolNode(servicekafka.StepSASLAuthenticate,
		domain.StateSkipped, domain.FailureExecRequiredInputMissing,
		map[domain.AttributeKey]domain.AttrValue{
			servicekafka.AttrSASLMechanism: domain.StringAttr("PLAIN"),
		})

	found := Protocol(rctx(b.freeze()))
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1", len(found))
	}
	if !strings.Contains(found[0].Detail(), "PLAIN") {
		t.Error("the detail does not name the mechanism the step concerned")
	}

	// Without the attribute the prose is the base text, not a sentence with a
	// hole in it.
	bare := codeFor(t, servicekafka.StepSASLAuthenticate,
		domain.StateSkipped, domain.FailureExecRequiredInputMissing)
	if strings.Contains(bare.Detail(), "The mechanism this step concerned") {
		t.Error("a node without the attribute produced a dangling sentence")
	}
}

// --- namespace ----------------------------------------------------------------

// TestNoCodeMirrorsAFailureClass keeps the two namespaces apart.
//
// A report carries failureClass on the node and code on the finding. A code
// spelled like a class invites a reader to treat them as one field.
func TestNoCodeMirrorsAFailureClass(t *testing.T) {
	classes := map[string]bool{}
	for _, class := range allFailureClasses() {
		classes[class.String()] = true
	}
	for _, c := range protocolClaims {
		if classes[string(c.code)] {
			t.Errorf("code %s is spelled exactly like a FailureClass", c.code)
		}
		if !strings.HasPrefix(string(c.code), "KAFKA_") {
			t.Errorf("code %s has no service namespace", c.code)
		}
	}
}

// --- helpers ------------------------------------------------------------------

func protocolSteps() []domain.Step {
	steps := make([]domain.Step, 0, len(protocolLayers))
	for step := range protocolLayers {
		steps = append(steps, step)
	}
	slices.Sort(steps)
	return steps
}

func sortedOutcomes() []outcome {
	keys := make([]outcome, 0, len(protocolClaims))
	for key := range protocolClaims {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b outcome) int {
		if a.step != b.step {
			return strings.Compare(string(a.step), string(b.step))
		}
		if a.state != b.state {
			return strings.Compare(a.state.String(), b.state.String())
		}
		return strings.Compare(a.failure.String(), b.failure.String())
	})
	return keys
}

// allFailureClasses returns every class the domain declares, by walking the
// numeric space until the names run out.
func allFailureClasses() []domain.FailureClass {
	var out []domain.FailureClass
	for i := range 200 {
		class := domain.FailureClass(i)
		if !class.Valid() {
			continue
		}
		out = append(out, class)
	}
	return out
}

// --- semantics pinned independently of the table -----------------------------

// TestSeverityAndVantageAreFixedPerCode pins both fields against a literal
// expectation rather than against protocolClaims.
//
// # Why this is not redundant with the table walk above
//
// TestEveryAuthorizedOutcomeProducesItsCode reads its expectation *from* the
// table, so for the fields the table itself supplies — severity and vantage —
// it asserts nothing: editing the table moves both sides together. Mutating
// three severities left that test green. This one holds an independent copy, so
// changing a severity or a vantage flag is a two-place edit and cannot happen by
// accident.
//
// Severity is the impact of the claim about its own subject, never a synonym for
// the evidence state and never a lever for an exit code:
//
//   - ERROR for the six target-side outcomes. Each stops the run from learning
//     what it came for at this endpoint.
//   - WARN for the two run-side refusals. Something real is wrong and nothing
//     about the target was proven wrong; svcdoctor's own state prevented the
//     attempt.
//   - INFO for the capability gap. It is a limit of this binary.
func TestSeverityAndVantageAreFixedPerCode(t *testing.T) {
	want := map[domain.FindingCode]struct {
		severity domain.Severity
		vantage  bool
	}{
		// Target-side: the endpoint said something, or the exchange broke.
		CodeAPIVersionsVersionRejected: {domain.SeverityError, false},
		CodeAPIVersionsNotCompleted:    {domain.SeverityError, true},
		CodeAuthMechanismNotOffered:    {domain.SeverityError, false},
		CodeSASLHandshakeNotCompleted:  {domain.SeverityError, true},
		CodeCredentialsRejected:        {domain.SeverityError, false},
		CodePeerVerificationFailed:     {domain.SeverityError, false},
		CodeAuthenticationNotCompleted: {domain.SeverityError, true},
		CodeMetadataNotCompleted:       {domain.SeverityError, true},

		// Run-side: svcdoctor declined, or had nothing.
		CodeCredentialWithheld:      {domain.SeverityWarn, true},
		CodeCredentialNotConfigured: {domain.SeverityWarn, false},

		// svcdoctor's own capability gap.
		CodeAuthenticationUnsupportedBySvcdoctor: {domain.SeverityInfo, false},
	}

	if len(want) != 11 {
		t.Fatalf("the expectation covers %d codes, want 11", len(want))
	}
	for key, c := range protocolClaims {
		expected, known := want[c.code]
		if !known {
			t.Errorf("%s has no pinned severity or vantage", c.code)
			continue
		}
		if c.severity != expected.severity {
			t.Errorf("%s %s/%s: severity = %s, want %s",
				key.step, key.state, key.failure, c.severity, expected.severity)
		}
		if c.vantageDependent != expected.vantage {
			t.Errorf("%s %s/%s: vantageDependent = %v, want %v",
				key.step, key.state, key.failure, c.vantageDependent, expected.vantage)
		}
	}
}

// TestSummaryStatusFollowsSeverity proves the end-to-end consequence, so the
// severity choices above are anchored to what an operator actually sees.
//
// docs/SCOPE.md maps status to an exit code, and the two run-side refusals and
// the capability gap must not take the exit code with them: each is a real
// limitation, and none is a target-side problem svcdoctor proved.
func TestSummaryStatusFollowsSeverity(t *testing.T) {
	tests := []struct {
		name  string
		step  domain.Step
		state domain.State
		class domain.FailureClass
		want  domain.SummaryStatus
	}{
		{
			name: "rejected credential is a target problem", step: servicekafka.StepSASLAuthenticate,
			state: domain.StateFail, class: domain.FailureAuthCredentialsRejected,
			want: domain.SummaryStatusProblemsFound,
		},
		{
			name: "mechanism not offered is a target problem", step: servicekafka.StepSASLHandshake,
			state: domain.StateFail, class: domain.FailureAuthMechanismNotOffered,
			want: domain.SummaryStatusProblemsFound,
		},
		{
			name: "failed Metadata is a target problem", step: servicekafka.StepMetadata,
			state: domain.StateFail, class: domain.FailureProtocolPeerClosed,
			want: domain.SummaryStatusProblemsFound,
		},
		{
			name: "no credential configured is not", step: servicekafka.StepSASLAuthenticate,
			state: domain.StateSkipped, class: domain.FailureExecRequiredInputMissing,
			want: domain.SummaryStatusOK,
		},
		{
			name: "a withheld credential is not", step: servicekafka.StepSASLAuthenticate,
			state: domain.StateSkipped, class: domain.FailureExecSkippedByPolicy,
			want: domain.SummaryStatusOK,
		},
		{
			name: "a capability gap is not", step: servicekafka.StepSASLAuthenticate,
			state: domain.StateUnknown, class: domain.FailureAuthMechanismUnsupported,
			want: domain.SummaryStatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := newBuilder(t)
			b.protocolNode(test.step, test.state, test.class, nil)
			graph := b.freeze()

			report := assemble(t, graph, Protocol(rctx(graph)))
			if got := report.Summary().Status(); got != test.want {
				t.Errorf("status = %s, want %s", got, test.want)
			}
		})
	}
}
