package kafka

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 13.1B: the classification the production rules actually attach.
//
// See internal/diagnosis/redis/classification_test.go for why a table-only guard
// set is insufficient.
//
// Two of these shipped classified in Phase 10.2 and are asserted here because
// this matrix reaches them: `recommendUnmeasured`, which is the one observation in
// the package svcdoctor can take itself, and `recommendUnsuitable`.
var kafkaClassification = map[string]classificationExpectation{
	recommendVersionRejected:            {diagnosis.SafetyCompare, false},
	recommendAPIVersionsNotCompleted:    {diagnosis.SafetyObserve, false},
	recommendMechanismNotOffered:        {diagnosis.SafetyCompare, false},
	recommendHandshakeNotCompleted:      {diagnosis.SafetyObserve, false},
	recommendCredentialsRejected:        {diagnosis.SafetyVerify, false},
	recommendPeerVerificationFailed:     {diagnosis.SafetyVerify, false},
	recommendUnsupportedExchange:        {diagnosis.SafetyObserve, false},
	recommendAuthenticationNotCompleted: {diagnosis.SafetyObserve, false},
	recommendUnsupportedBySvcdoctor:     {diagnosis.SafetyObserve, false},
	recommendCredentialNotConfigured:    {diagnosis.SafetyObserve, false},
	recommendMetadataNotCompleted:       {diagnosis.SafetyObserve, false},
	recommendUnusable:                   {diagnosis.SafetyObserve, false},
	recommendTCP:                        {diagnosis.SafetyVerify, false},
	recommendTLS:                        {diagnosis.SafetyVerify, false},
	// Shipped classified in Phase 10.2, reached by this matrix, and the one
	// observation in the package svcdoctor can take itself.
	recommendUnmeasured: {diagnosis.SafetyObserve, true},
	recommendUnsuitable: {diagnosis.SafetyCompare, false},
	// Phase 13.1C. `recommendDNS` is the interesting one: it is a member of the
	// *same* list as `recommendTCP` and `recommendTLS`, so
	// `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` used to carry a mixed set of
	// classified and unclassified advice. That shape is now unreachable.
	recommendCredentialWithheld: {diagnosis.SafetyObserve, false},
	recommendDNS:                {diagnosis.SafetyCompare, false},
}

func TestEveryProducedRecommendationCarriesItsFrozenClassification(t *testing.T) {
	assertFrozenClassification(t, everyKafkaFinding(t), kafkaClassification,
		// A complete advertised set needs no next observation from the aggregate:
		// it states what was measured, the per-endpoint findings state the impact,
		// and the boundary states where each stopped. That is the designed answer,
		// not a dropped recommendation.
		map[domain.FindingCode]string{
			CodeAdvertisedTopologyReachability: "no advice when the set is complete",
		})
}

// everyKafkaFinding joins the matrix this package enumerates with the three
// per-layer advertised-endpoint shapes, which it does not.
func everyKafkaFinding(t *testing.T) []domain.Finding {
	t.Helper()
	out := everyFindingThisPackageCanBuild(t)

	// One advertised-endpoint finding per failing transport layer, so the mixed
	// list is exercised at each of its three members.
	for _, layer := range []struct {
		name  string
		build func(b *builder, advertisement domain.EvidenceID)
	}{
		{"dns", func(b *builder, advertisement domain.EvidenceID) {
			b.lookup(advertisement, "broker-2.internal", domain.StateFail, domain.FailureDNSNoAddress)
		}},
		{"tcp", func(b *builder, advertisement domain.EvidenceID) {
			lookup := b.lookup(advertisement, "broker-2.internal",
				domain.StatePass, domain.FailureNone)
			b.connect(lookup, "10.20.0.1", 9093, domain.StateFail,
				domain.FailureTCPConnectionRefused)
		}},
		{"tls", func(b *builder, advertisement domain.EvidenceID) {
			lookup := b.lookup(advertisement, "broker-2.internal",
				domain.StatePass, domain.FailureNone)
			connect := b.connect(lookup, "10.20.0.1", 9093,
				domain.StatePass, domain.FailureNone)
			b.handshake(connect, "10.20.0.1", 9093, domain.StateFail,
				domain.FailureTLSUnknownAuthority)
		}},
	} {
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
		layer.build(b, advertisement)
		out = append(out, AdvertisedEndpointUnreachable(rctx(b.freeze()))...)
	}
	return out
}

// classificationExpectation is what one action must carry.
//
// The maps above use unkeyed literals — `{safety, selfCollectable}` — because a
// keyed one triples the width of a fifty-row table and the two fields are never
// ambiguous about which is which.
type classificationExpectation struct {
	safety          diagnosis.SafetyClass
	selfCollectable bool
}

// assertFrozenClassification is the shared body. It lives in each rule package
// rather than in one place because a rule package may not import another's
// constants, and a generic helper elsewhere would need the whole expectation
// passed in anyway.
//
// `mayCarryNone` names the codes for which an empty recommendation list is the
// designed answer. Everything else with none is the silent-drop shape:
// diagnosis.Recommend returns nil on any error, so a misclassification deletes a
// recommendation rather than failing a build.
func assertFrozenClassification(
	t *testing.T,
	findings []domain.Finding,
	want map[string]classificationExpectation,
	mayCarryNone map[domain.FindingCode]string,
) {
	t.Helper()
	if len(findings) == 0 {
		t.Fatal("the producer matrix yielded no finding; this guard would pass vacuously")
	}

	seen := map[string]bool{}
	for _, f := range findings {
		if len(f.Recommendations()) == 0 {
			if _, allowed := mayCarryNone[f.Code()]; !allowed {
				t.Errorf("%s carries no recommendation at all, and it is not one of the "+
					"codes for which that is the designed answer; diagnosis.Recommend "+
					"drops an invalid classification silently, so an absent "+
					"recommendation is the shape this guard exists to catch", f.Code())
			}
			continue
		}
		for _, r := range f.Recommendations() {
			action := r.Action()
			seen[action] = true

			expect, known := want[action]
			if !known {
				t.Errorf("%s produced the action %q, which is not in the frozen "+
					"classification.\n\n"+
					"ADR 0097 section 2.1: a production rule may not decline to classify "+
					"its own advice, and Phase 13.1C left no exemption list to add it "+
					"to. Classify it, deliberately.", f.Code(), action)
				continue
			}
			if !r.Classified() {
				t.Errorf("%s produced %q unclassified; every production "+
					"recommendation is classified since Phase 13.1C, so a call site "+
					"stopped passing the classification", f.Code(), action)
				continue
			}
			if r.Kind() != domain.RecommendationKindNextEvidence {
				t.Errorf("%s produced %q as %s, want NEXT_EVIDENCE", f.Code(), action, r.Kind())
			}
			if r.Safety() != expect.safety {
				t.Errorf("%s produced %q classified %s, want %s",
					f.Code(), action, r.Safety(), expect.safety)
			}
			if !r.Safety().ChangesNothing() {
				t.Errorf("%s produced %q classified %s, which changes the target",
					f.Code(), action, r.Safety())
			}
			if r.SelfCollectable() != expect.selfCollectable {
				t.Errorf("%s produced %q with selfCollectable=%v, want %v; "+
					"true means svcdoctor can take the observation under its current "+
					"authority, never that it could be programmed to",
					f.Code(), action, r.SelfCollectable(), expect.selfCollectable)
			}
			if r.Rationale() == "" {
				t.Errorf("%s produced %q with no rationale", f.Code(), action)
			}
		}
	}

	for action := range want {
		if !seen[action] {
			t.Errorf("the producer matrix never produced %q, so its row asserts nothing; "+
				"either the matrix lost a shape or the constant is unreachable", action)
		}
	}
}
