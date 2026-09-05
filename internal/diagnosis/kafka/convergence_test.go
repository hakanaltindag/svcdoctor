package kafka

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// Phase 10.2A, the Kafka half: the three shapes that proved RuleID-winner prose
// unsafe, and the mutual-exclusivity invariant Phase 10.2 relied on.
//
// # Why these live here and not beside the engine's C-series
//
// The engine tests state the contract with synthetic findings. These drive the
// **real production rules** over graphs a real cluster can produce, which is the
// difference between "the merge implementation behaves like this" and "svcdoctor
// publishes this". Every one of the three was a live defect before Phase 10.2A:
// the rules were right and the engine discarded half of what they said.

// converged runs one rule's output through the production convergence step.
func converged(t *testing.T, id diagnosis.RuleID, findings []domain.Finding) []domain.Finding {
	t.Helper()

	in := make([]diagnosis.AttributedFinding, 0, len(findings))
	for _, f := range findings {
		in = append(in, diagnosis.AttributedFinding{Rule: id, Finding: f})
	}
	out, err := diagnosis.Converge(in)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	return out
}

// twoAdvertisementsAtOneEndpoint builds the graph a cluster produces when two
// brokers publish the same host and port.
//
// ADR 0031 keeps them as two evidence nodes deliberately — the identifier
// carries both the node number and the endpoint precisely so that "two nodes at
// one address" stays visible — and ADR 0034 section 10 decided that they are two
// facts producing two findings.
func twoAdvertisementsAtOneEndpoint(t *testing.T, shapes map[int64]verdictShape) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	ids := make([]int64, 0, len(shapes))
	for id := range shapes {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	for _, nodeID := range ids {
		ad := b.advertised(exchange, nodeID, "shared.internal:9093")
		lookup := b.lookup(ad, "shared.internal", domain.StatePass, domain.FailureNone)
		switch shapes[nodeID] {
		case shapeFailed:
			b.connect(lookup, addrFor(nodeID), 9093,
				domain.StateFail, domain.FailureTCPConnectionRefused)
		case shapeUnmeasured:
			b.connect(lookup, addrFor(nodeID), 9093,
				domain.StateFail, domain.FailureTCPConnectionRefused)
			b.connect(lookup, addrFor(nodeID+100), 9093,
				domain.StateUnknown, domain.FailureExecLocalTimeout)
		case shapeReached, shapeUnusable:
			b.connect(lookup, addrFor(nodeID), 9093, domain.StatePass, domain.FailureNone)
		}
	}
	return b.freeze()
}

func addrFor(nodeID int64) string {
	return "10.20.0." + strconv.FormatInt(nodeID, 10)
}

// TestTwoBrokersAtOneEndpointStayTwoFindings is defect one, and it is the one
// that silently overrode an Accepted decision.
//
// ADR 0034 section 10: *"Two advertisements naming one endpoint are two facts
// and produce two findings; nothing deduplicates by endpoint or by node
// identifier."* Convergence deduplicated by endpoint anyway, because the subject
// is the endpoint and the broker number lives only in the prose. The published
// finding said *"for broker node 2"* while citing node 7's evidence too, and
// node 7's claim was gone.
func TestTwoBrokersAtOneEndpointStayTwoFindings(t *testing.T) {
	g := twoAdvertisementsAtOneEndpoint(t, map[int64]verdictShape{
		2: shapeFailed, 7: shapeFailed,
	})

	raw := AdvertisedEndpointUnreachable(rctx(g))
	if len(raw) != 2 {
		t.Fatalf("the rule produced %d findings, want one per advertisement", len(raw))
	}

	out := converged(t, "kafka/advertised-endpoint", raw)
	if len(out) != 2 {
		t.Fatalf("convergence reduced two brokers to %d finding(s): %v\n\n"+
			"ADR 0034 section 10 decided that two advertisements naming one endpoint "+
			"are two facts. The subject is the endpoint and the broker number is in "+
			"the prose, so merging on identity alone erases one broker's claim while "+
			"keeping its evidence.", len(out), summaries(out))
	}

	// Each surviving claim names its own broker and cites only its own evidence.
	for _, f := range out {
		var node string
		switch {
		case strings.Contains(f.Summary(), "broker node 2"):
			node = "2"
		case strings.Contains(f.Summary(), "broker node 7"):
			node = "7"
		default:
			t.Fatalf("an unexpected claim survived: %q", f.Summary())
		}
		for _, ref := range f.EvidenceRefs() {
			other := "7"
			if node == "7" {
				other = "2"
			}
			if strings.Contains(string(ref), "/"+other+"/") {
				t.Errorf("the claim about broker %s cites broker %s's evidence: %s",
					node, other, ref)
			}
		}
	}
}

// TestTwoUnusableAdvertisementsAtOneSubjectStayTwoFindings is defect two.
func TestTwoUnusableAdvertisementsAtOneSubjectStayTwoFindings(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	b.unusableAdvertised(exchange, 2)
	b.unusableAdvertised(exchange, 7)
	g := b.freeze()

	raw := UnusableAdvertisement(rctx(g))
	if len(raw) != 2 {
		t.Fatalf("the rule produced %d findings, want one per advertisement", len(raw))
	}
	out := converged(t, "kafka/unusable-advertisement", raw)
	if len(out) != 2 {
		t.Fatalf("convergence reduced two unusable advertisements to %d: %v",
			len(out), summaries(out))
	}
}

// TestAConfirmedAndAHypothesisAtOneEndpointStayApart is defect three, and it is
// the worst of them.
//
// One endpoint carried a proven-unreachable broker and a broker whose paths were
// never finished measuring. The unset discriminator folded into the set one,
// CONFIRMED absorbed HYPOTHESIS, the discriminator was cleared, and the report
// stated flatly that the endpoint *could not be reached* — a stronger claim than
// either rule made, built out of one claim's certainty and the other's identity.
//
// Less evidence must never produce a stronger claim.
func TestAConfirmedAndAHypothesisAtOneEndpointStayApart(t *testing.T) {
	g := twoAdvertisementsAtOneEndpoint(t, map[int64]verdictShape{
		2: shapeFailed, 7: shapeUnmeasured,
	})

	raw := AdvertisedEndpointUnreachable(rctx(g))
	if len(raw) != 2 {
		t.Fatalf("the rule produced %d findings, want 2", len(raw))
	}
	out := converged(t, "kafka/advertised-endpoint", raw)
	if len(out) != 2 {
		t.Fatalf("a hypothesis was absorbed into a confirmed claim: %v", summaries(out))
	}

	var sawConfirmed, sawHypothesis bool
	for _, f := range out {
		switch f.Kind() {
		case domain.FindingKindConfirmed:
			sawConfirmed = true
			if f.Confidence() != domain.ConfidenceHigh {
				t.Errorf("the confirmed claim is %s", f.Confidence())
			}
		case domain.FindingKindHypothesis:
			sawHypothesis = true
			if f.Confidence() != domain.ConfidenceLow {
				t.Errorf("the hypothesis was promoted to %s", f.Confidence())
			}
			if f.Discriminator() == "" {
				t.Error("the hypothesis lost the observation that would settle it")
			}
			if !strings.Contains(f.Summary(), "may be unreachable") {
				t.Errorf("the hypothesis states more than it measured: %q", f.Summary())
			}
		}
	}
	if !sawConfirmed || !sawHypothesis {
		t.Errorf("both kinds must survive; got %v", summaries(out))
	}
}

// TestC07TheTopologySentencesAreMutuallyExclusive is section 6 of the phase, and
// it is deliberately split into two claims that are not the same claim.
//
// # Rule applicability safety
//
// *"None of the N"* and *"K of the N … the other M were reached"* come from two
// branches of one `if` in reachabilityProse, evaluated once per advertised
// topology, and topologies returns at most one entry per exchange subject. So
// one exchange yields one sentence, and the two cannot coexist for one subject.
// That is a property of these rules.
//
// # Generic convergence safety
//
// It is **not** the reason the report is safe. Phase 10.2 relied on this
// invariant because the engine would otherwise have picked one of the two
// sentences by a tie-break; Phase 10.2A removed that, so even a future rule that
// broke the invariant would produce two findings rather than one wrong number.
// The invariant is kept because it is true and worth stating, not because
// anything now depends on it.
func TestC07TheTopologySentencesAreMutuallyExclusive(t *testing.T) {
	// Applicability: every shape produces at most one observation per exchange.
	for _, shapes := range topologyShapeMatrix() {
		for _, incomplete := range []bool{false, true} {
			g, _, _ := topologyFixture(t, shapes...)
			out := AdvertisedTopologyReachability(rctxWith(g, incomplete))
			if len(out) > 1 {
				t.Fatalf("%v incomplete=%v produced %d observations: %v",
					shapes, incomplete, len(out), summaries(out))
			}
			if len(out) == 1 {
				s := out[0].Summary()
				none := strings.HasPrefix(s, "None of the ") ||
					strings.HasPrefix(s, "The one broker endpoint")
				partial := strings.Contains(s, "the other")
				if none && partial {
					t.Fatalf("one sentence claims both shapes: %q", s)
				}
			}
		}
	}

	// And the generic net beneath it: had the invariant failed, the two
	// sentences would stay two findings rather than becoming one wrong number.
	subject, err := domain.NewEndpointSubject("primary.internal:9092")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	build := func(summary string, ref domain.EvidenceID) domain.Finding {
		f, err := domain.NewFinding(domain.FindingInput{
			Code: CodeAdvertisedTopologyReachability, Kind: domain.FindingKindConfirmed,
			Severity: domain.SeverityInfo, Confidence: domain.ConfidenceHigh,
			Layer: domain.LayerTopology, Subject: subject, Summary: summary,
			Detail: detailTopologyMeaning, EvidenceRefs: []domain.EvidenceID{ref},
			VantageDependent: true,
		})
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		return f
	}
	out := converged(t, "kafka/advertised-topology", []domain.Finding{
		build("None of the 3 broker endpoints this cluster advertised could be reached "+
			"from this vantage point", "c-none"),
		build("1 of the 3 broker endpoints this cluster advertised could not be reached "+
			"from this vantage point; the other 2 were reached", "c-partial"),
	})
	if len(out) != 2 {
		t.Fatalf("two different counts merged into %d finding(s): %v\n\n"+
			"Rule applicability keeps this shape out of production. It must not be "+
			"the only thing keeping it out of a report.", len(out), summaries(out))
	}
}

// TestTheOneRealKafkaConvergenceStillMerges is C08 at the service layer.
//
// `KAFKA_AUTH_MECHANISM_NOT_OFFERED` reaches one endpoint from two protocol
// steps — the SASL handshake and the SASL authenticate — and both write the same
// summary, the same detail and the same recommendation. That is a genuine
// two-routes-one-claim case, it is the only one Kafka has, and the closure must
// not have broken it.
func TestTheOneRealKafkaConvergenceStillMerges(t *testing.T) {
	b := newBuilder(t)
	for _, step := range []domain.Step{
		servicekafka.StepSASLHandshake, servicekafka.StepSASLAuthenticate,
	} {
		b.node("kafka/"+string(step), "10.0.0.1:9092", domain.LayerAuth, step,
			domain.StateFail, domain.FailureAuthMechanismNotOffered, "",
			map[domain.AttributeKey]domain.AttrValue{
				servicekafka.AttrSASLMechanism: domain.StringAttr("PLAIN"),
			})
	}
	g := b.freeze()

	raw := Protocol(rctx(g))
	if len(raw) != 2 {
		t.Fatalf("the rule produced %d findings, want one per step", len(raw))
	}
	if raw[0].Summary() != raw[1].Summary() || raw[0].Detail() != raw[1].Detail() {
		t.Fatalf("the two routes no longer write one sentence:\n%q\n%q",
			raw[0].Summary(), raw[1].Summary())
	}

	out := converged(t, "kafka/protocol", raw)
	if len(out) != 1 {
		t.Fatalf("two routes to one claim produced %d findings: %v", len(out), summaries(out))
	}
	if len(out[0].EvidenceRefs()) != 2 {
		t.Errorf("the merged claim cites %v, want both steps", out[0].EvidenceRefs())
	}
}
