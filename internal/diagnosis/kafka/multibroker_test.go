package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Multi-broker semantics: one finding per unreachable advertisement, and no
// cluster-level aggregate.
//
// An aggregate is rejected because it would state no independent fact, and
// because the obvious wording would be false: the cluster is demonstrably not
// down, since the broker that answered Metadata was reached over a measured path
// in this very run (ADR 0034 section 10).

// unreachable adds an advertisement whose single address refuses the connection.
func unreachable(b *builder, exchange domain.EvidenceID, nodeID int64, endpoint, host, addr string) {
	ad := b.advertised(exchange, nodeID, endpoint)
	l := b.lookup(ad, host, domain.StatePass, domain.FailureNone)
	b.connect(l, addr, 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
}

// reachable adds an advertisement whose single address connects.
func reachable(b *builder, exchange domain.EvidenceID, nodeID int64, endpoint, host, addr string) {
	ad := b.advertised(exchange, nodeID, endpoint)
	l := b.lookup(ad, host, domain.StatePass, domain.FailureNone)
	b.connect(l, addr, 9093, domain.StatePass, domain.FailureNone)
}

func TestOneUnreachableBrokerAmongThreeProducesOneFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	reachable(b, exchange, 1, "broker-1.internal:9093", "broker-1.internal", "10.20.0.1")
	unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
	reachable(b, exchange, 3, "broker-3.internal:9093", "broker-3.internal", "10.20.0.3")

	f := only(t, AdvertisedEndpointUnreachable(rctx(b.freeze())))
	confirmed(t, f)
	if got := f.Subject().Ref(); got != "broker-2.internal:9093" {
		t.Errorf("subject = %q, want the unreachable advertisement's endpoint", got)
	}
	if !strings.Contains(f.Summary(), "broker node 2") {
		t.Errorf("summary does not name the broker: %q", f.Summary())
	}
}

func TestThreeUnreachableBrokersProduceThreeIndependentFindings(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	unreachable(b, exchange, 1, "broker-1.internal:9093", "broker-1.internal", "10.20.0.1")
	unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
	unreachable(b, exchange, 3, "broker-3.internal:9093", "broker-3.internal", "10.20.0.3")

	findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3 (one per advertisement, never an aggregate)", len(findings))
	}

	subjects := map[string]bool{}
	for _, f := range findings {
		confirmed(t, f)
		subjects[f.Subject().Ref()] = true
		// Severity does not move with the number of affected brokers. It is the
		// impact of this finding's claim about its own subject.
		if f.Severity() != domain.SeverityError {
			t.Errorf("severity = %s, want ERROR regardless of how many brokers failed", f.Severity())
		}
	}
	for _, want := range []string{
		"broker-1.internal:9093", "broker-2.internal:9093", "broker-3.internal:9093",
	} {
		if !subjects[want] {
			t.Errorf("no finding for %s", want)
		}
	}
}

// TestConfirmedHypothesisAndReachableCoexist proves the verdicts are computed per
// advertisement and do not leak into each other.
func TestConfirmedHypothesisAndReachableCoexist(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)

	unreachable(b, exchange, 1, "broker-1.internal:9093", "broker-1.internal", "10.20.0.1")

	mixed := b.advertised(exchange, 2, "broker-2.internal:9093")
	mixedLookup := b.lookup(mixed, "broker-2.internal", domain.StatePass, domain.FailureNone)
	b.connect(mixedLookup, "10.20.0.2", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	b.connect(mixedLookup, "10.20.0.5", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)

	reachable(b, exchange, 3, "broker-3.internal:9093", "broker-3.internal", "10.20.0.3")

	findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2: %v", len(findings), summaries(findings))
	}

	bySubject := map[string]domain.Finding{}
	for _, f := range findings {
		bySubject[f.Subject().Ref()] = f
	}
	first, ok := bySubject["broker-1.internal:9093"]
	if !ok {
		t.Fatal("no finding for broker-1")
	}
	confirmed(t, first)

	second, ok := bySubject["broker-2.internal:9093"]
	if !ok {
		t.Fatal("no finding for broker-2")
	}
	hypothesis(t, second)
}

// TestTwoAdvertisementsOfOneEndpointProduceTwoFindings pins ADR 0034 section 12.
// Two node identifiers naming one endpoint are two facts, so Phase 3.4 measures
// them twice and this rule reports them twice, distinguished by their evidence
// rather than by their subject. Nothing deduplicates by endpoint.
func TestTwoAdvertisementsOfOneEndpointProduceTwoFindings(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	unreachable(b, exchange, 1, "broker.internal:9093", "broker.internal", "10.20.0.9")
	unreachable(b, exchange, 2, "broker.internal:9093", "broker.internal", "10.20.0.9")

	findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (two advertisement facts, one endpoint)", len(findings))
	}
	if findings[0].Subject().Ref() != findings[1].Subject().Ref() {
		t.Fatal("the two findings should share a subject")
	}
	if slicesEqual(findings[0].EvidenceRefs(), findings[1].EvidenceRefs()) {
		t.Error("the two findings should be distinguished by their evidence")
	}
}

// TestOneNodeIDAtTwoEndpointsProducesTwoFindings is the mirror case. The node
// identifier is not finding identity.
func TestOneNodeIDAtTwoEndpointsProducesTwoFindings(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	unreachable(b, exchange, 1, "broker-a.internal:9093", "broker-a.internal", "10.20.0.1")
	unreachable(b, exchange, 1, "broker-b.internal:9093", "broker-b.internal", "10.20.0.2")

	findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (one node identifier, two endpoints)", len(findings))
	}
}

// TestControllerIdentityDoesNotChangeSeverity pins ADR 0034 section 15. The
// controller is a point-in-time fact that moves on election, and a client does
// not need it to produce or consume.
//
// The rule cannot read the controller identifier at all — the attribute stayed
// in the adapter — so this test states the property the absence guarantees, on
// two graphs that differ only in which broker the exchange named as controller.
func TestControllerIdentityDoesNotChangeSeverity(t *testing.T) {
	build := func(t *testing.T, controllerID int64) domain.Finding {
		t.Helper()
		b := newBuilder(t)
		exchange := b.node(
			"kafka.metadata/primary.internal:9092/10.0.0.1", "primary.internal:9092",
			domain.LayerTopology, "kafka.metadata", domain.StatePass, domain.FailureNone, "",
			map[domain.AttributeKey]domain.AttrValue{
				"kafka.metadata.controller_id": domain.IntAttr(controllerID),
			})
		unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
		reachable(b, exchange, 7, "broker-7.internal:9093", "broker-7.internal", "10.20.0.7")
		return only(t, AdvertisedEndpointUnreachable(rctx(b.freeze())))
	}

	// Node 2 is the unreachable broker in both graphs; in the first it is also
	// the controller.
	asController := build(t, 2)
	asFollower := build(t, 7)

	if asController.Severity() != asFollower.Severity() {
		t.Errorf("severity changed with controller identity: %s vs %s",
			asController.Severity(), asFollower.Severity())
	}
	if asController.Severity() != domain.SeverityError {
		t.Errorf("severity = %s, want ERROR", asController.Severity())
	}
	if asController.Confidence() != asFollower.Confidence() {
		t.Error("confidence changed with controller identity")
	}
	if asController.Summary() != asFollower.Summary() {
		t.Error("summary changed with controller identity")
	}
}

func slicesEqual(a, b []domain.EvidenceID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
