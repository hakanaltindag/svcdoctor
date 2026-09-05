package kafka

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.4B, NBE-021: the one hypothesis shape that carries an open question
// with no structured observation beside it.
//
// test/diagnosis/nextevidenceinvariant_test.go holds the cross-service
// inventory, but it can only see what the corpora reach and this shape is not
// among them. So the debt is pinned here, where it is built, and the two tests
// together are the guard: the inventory fails if a *new* code acquires the
// shape, and this fails if the recorded one silently changes.

// TestTheOneExemptHypothesisShapeStillExists keeps the exemption honest.
//
// If this starts failing because the finding gained a NEXT_EVIDENCE
// recommendation, that is the debt being paid: delete this test and the entry in
// hypothesesWithoutStructuredNextEvidence together.
func TestTheOneExemptHypothesisShapeStillExists(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)
	b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	b.connect(lookup, "10.20.0.2", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)

	f := only(t, AdvertisedEndpointUnreachable(rctx(b.freeze())))
	if f.Kind() != domain.FindingKindHypothesis {
		t.Fatalf("kind = %s, want HYPOTHESIS; the fixture no longer builds the shape",
			f.Kind())
	}
	if f.Discriminator() == "" {
		t.Fatal("the hypothesis carries no discriminator; the exemption is about a " +
			"finding that asks an open question")
	}

	var structured int
	for _, r := range f.Recommendations() {
		if r.Kind() == domain.RecommendationKindNextEvidence {
			structured++
		}
	}
	if structured > 0 {
		t.Errorf("%s now carries %d structured next-evidence recommendation(s).\n\n"+
			"That is the NBE-021 debt paid. Delete this test and the "+
			"KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE entry in "+
			"hypothesesWithoutStructuredNextEvidence together.", f.Code(), structured)
	}
	if len(f.Recommendations()) == 0 {
		t.Error("the finding carries no recommendation at all; the exemption describes " +
			"unclassified advice, not absent advice")
	}
	for _, r := range f.Recommendations() {
		if r.Classified() {
			t.Errorf("recommendation %q is classified; the exemption is precisely that "+
				"these three transport sentences predate the advice vocabulary",
				r.Action())
		}
	}
}
