package kafka

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// Phase 10.2, level L1: the two topology-scoped rules against synthetic graphs.
//
// The scenarios are named for what a reader would call them rather than for the
// branch they hit, and the negative half — the inputs on which these rules must
// say nothing — is as long as the positive half on purpose. The claims withheld
// here are the ones a Kafka diagnostic tool is most tempted to make.

// rctxWith wraps a graph and svcdoctor's own completeness statement.
//
// The rules in this file are the first in the package that read
// RuleContext.Incomplete, so unlike rctx they have to be able to set it. A
// complete set of measurements inside a run svcdoctor cut short is still not a
// complete measurement (ADR 0084 section 4).
func rctxWith(g domain.Graph, incomplete bool) diagnosis.RuleContext {
	return diagnosis.RuleContext{Graph: g, Incomplete: incomplete}
}

// verdictShape is what a fixture wants one advertised endpoint to have become.
type verdictShape int

const (
	shapeReached verdictShape = iota
	shapeFailed
	shapeUnmeasured
	shapeUnusable
)

// topologyFixture builds one Metadata exchange and the advertisements beneath
// it, each in the requested shape.
func topologyFixture(t *testing.T, shapes ...verdictShape) (domain.Graph, domain.EvidenceID, []domain.EvidenceID) {
	t.Helper()

	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	ads := make([]domain.EvidenceID, 0, len(shapes))

	for i, shape := range shapes {
		nodeID := int64(i + 1)
		host := fmt.Sprintf("broker-%d.internal", nodeID)
		endpoint := fmt.Sprintf("%s:9092", host)

		if shape == shapeUnusable {
			ads = append(ads, b.unusableAdvertised(exchange, nodeID))
			continue
		}

		ad := b.advertised(exchange, nodeID, endpoint)
		ads = append(ads, ad)
		lookup := b.lookup(ad, host, domain.StatePass, domain.FailureNone)
		addr := fmt.Sprintf("10.20.0.%d", nodeID)
		switch shape {
		case shapeReached:
			b.connect(lookup, addr, 9092, domain.StatePass, domain.FailureNone)
		case shapeFailed:
			b.connect(lookup, addr, 9092, domain.StateFail, domain.FailureTCPConnectionRefused)
		case shapeUnmeasured:
			b.connect(lookup, addr, 9092, domain.StateUnknown, domain.FailureExecLocalTimeout)
		case shapeUnusable:
		}
	}
	return b.freeze(), exchange, ads
}

// --- the observation --------------------------------------------------------

// TestTheTopologyObservationSaysNothingWhenEveryEndpointWasReached is the
// healthy run, and it is the first thing this rule must get right.
//
// A finding for a run in which nothing failed is noise, and the topology counts
// an operator wants on a healthy run are already on the terminal's topology
// line. ADR 0084 section 3 makes "at least one positively observed failure" a
// precondition rather than a filter.
func TestTheTopologyObservationSaysNothingWhenEveryEndpointWasReached(t *testing.T) {
	g, _, _ := topologyFixture(t, shapeReached, shapeReached, shapeReached)
	none(t, AdvertisedTopologyReachability(rctx(g)))
	none(t, AdvertisedTopologyUnsuitable(rctx(g)))
}

// TestTheTopologyObservationStatesTheContrastOverACompleteSet is the K08 shape:
// PASS PASS FAIL, everything measured.
//
// The sentence is the one ADR 0084 section 3 exists for: it rules against this
// client having no path to the cluster, which three separate per-endpoint
// findings state nowhere.
func TestTheTopologyObservationStatesTheContrastOverACompleteSet(t *testing.T) {
	g, exchange, _ := topologyFixture(t, shapeReached, shapeReached, shapeFailed)

	f := only(t, AdvertisedTopologyReachability(rctx(g)))

	if f.Code() != CodeAdvertisedTopologyReachability {
		t.Errorf("code = %s, want %s", f.Code(), CodeAdvertisedTopologyReachability)
	}
	if f.Kind() != domain.FindingKindConfirmed {
		t.Errorf("kind = %s, want CONFIRMED; every number in it is a count of measured nodes",
			f.Kind())
	}
	if f.Severity() != domain.SeverityInfo {
		t.Errorf("severity = %s, want INFO; severity is never a count-derived cluster "+
			"verdict (ADR 0034 section 13)", f.Severity())
	}
	if f.Layer() != domain.LayerTopology {
		t.Errorf("layer = %s, want L6", f.Layer())
	}
	if !f.VantageDependent() {
		t.Error("vantageDependent = false; reachability is a claim about network position")
	}
	if f.Discriminator() != "" {
		t.Errorf("discriminator = %q; a CONFIRMED finding settles nothing further",
			f.Discriminator())
	}
	if len(f.Recommendations()) != 0 {
		t.Errorf("recommendations = %d, want none on a complete set", len(f.Recommendations()))
	}

	node, ok := g.Node(exchange)
	if !ok {
		t.Fatal("the exchange vanished from the fixture")
	}
	if f.Subject() != node.Subject() {
		t.Errorf("subject = %v, want the exchange's own %v; a set-level count under an "+
			"endpoint-level identity would collide with the per-endpoint findings",
			f.Subject(), node.Subject())
	}

	want := "1 of the 3 broker endpoints this cluster advertised could not be reached " +
		"from this vantage point; the other 2 were reached"
	if f.Summary() != want {
		t.Errorf("summary =\n  %q\nwant\n  %q", f.Summary(), want)
	}
	if !strings.Contains(f.Detail(), "account for the whole advertised set") {
		t.Errorf("the detail does not say the counts are complete:\n%s", f.Detail())
	}
}

// TestTheTopologyObservationStatesTheUniversalNegativeOnlyWhenItIsOne is K09.
func TestTheTopologyObservationStatesTheUniversalNegativeOnlyWhenItIsOne(t *testing.T) {
	g, _, _ := topologyFixture(t, shapeFailed, shapeFailed, shapeFailed)

	f := only(t, AdvertisedTopologyReachability(rctx(g)))

	want := "None of the 3 broker endpoints this cluster advertised could be reached " +
		"from this vantage point"
	if f.Summary() != want {
		t.Errorf("summary =\n  %q\nwant\n  %q", f.Summary(), want)
	}
	if f.Severity() != domain.SeverityInfo {
		t.Errorf("severity = %s; three failures are not a reason to escalate a count",
			f.Severity())
	}
}

// TestAnUnmeasuredEndpointForbidsEveryTotal is K10, and it is the RAB18 lesson
// in this rule's terms: less evidence must never produce a stronger claim.
func TestAnUnmeasuredEndpointForbidsEveryTotal(t *testing.T) {
	g, _, _ := topologyFixture(t, shapeReached, shapeUnmeasured, shapeFailed)

	f := only(t, AdvertisedTopologyReachability(rctx(g)))

	want := "1 of the 3 broker endpoints this cluster advertised could not be reached " +
		"from this vantage point; 1 was reached and 1 was not measured"
	if f.Summary() != want {
		t.Errorf("summary =\n  %q\nwant\n  %q", f.Summary(), want)
	}
	for _, forbidden := range []string{"the other", "account for the whole"} {
		if strings.Contains(f.Summary()+f.Detail(), forbidden) {
			t.Errorf("the incomplete form claims %q, which asserts a total nobody "+
				"established:\n%s\n%s", forbidden, f.Summary(), f.Detail())
		}
	}
	if !strings.Contains(f.Detail(), "not an endpoint that refused") {
		t.Errorf("the detail does not separate not measured from not reached:\n%s", f.Detail())
	}
	if len(f.Recommendations()) != 1 {
		t.Fatalf("recommendations = %d, want the one that asks for the missing measurement",
			len(f.Recommendations()))
	}
	if got := f.Recommendations()[0].Action(); got != recommendUnmeasured {
		t.Errorf("recommendation = %q, want %q", got, recommendUnmeasured)
	}
}

// TestAnIncompleteRunCannotProduceACompleteCount holds the half of completeness
// that lives outside the graph.
//
// Every advertisement here has a positive verdict, so the exchange's own
// children say the set is complete. RuleContext.Incomplete says svcdoctor's
// budget stopped the run anyway, and that is enough on its own: a run cut short
// may have been cut short before an advertisement was ever recorded, and this
// rule cannot see what was never written down.
func TestAnIncompleteRunCannotProduceACompleteCount(t *testing.T) {
	g, _, _ := topologyFixture(t, shapeReached, shapeFailed)

	complete := only(t, AdvertisedTopologyReachability(rctxWith(g, false)))
	cut := only(t, AdvertisedTopologyReachability(rctxWith(g, true)))

	if !strings.Contains(complete.Summary(), "the other 1 was reached") {
		t.Errorf("the complete form did not fire on a complete set: %q", complete.Summary())
	}
	if !strings.Contains(cut.Summary(), "were not measured") {
		t.Errorf("an incomplete run produced a complete count: %q", cut.Summary())
	}
	if cut.Summary() == complete.Summary() {
		t.Error("RuleContext.Incomplete changed nothing; the rule is not reading it")
	}
	none(t, AdvertisedTopologyUnsuitable(rctxWith(g, true)))
}

// TestAnAdvertisementTheClusterStatedUnusablyIsNotAnUnmeasuredOne keeps the
// third category honest in the other direction.
//
// There was no endpoint to sweep and none was promised, so it is a positively
// observed negative — the same reading ADR 0051 and the terminal's topology line
// already take. Calling it unmeasured would let an unusable advertisement
// silently block every complete claim.
func TestAnAdvertisementTheClusterStatedUnusablyIsNotAnUnmeasuredOne(t *testing.T) {
	g, _, _ := topologyFixture(t, shapeReached, shapeUnusable)

	f := only(t, AdvertisedTopologyReachability(rctx(g)))
	if strings.Contains(f.Summary(), "not measured") {
		t.Errorf("an unusable advertisement was counted as unmeasured: %q", f.Summary())
	}
	want := "1 of the 2 broker endpoints this cluster advertised could not be reached " +
		"from this vantage point; the other 1 was reached"
	if f.Summary() != want {
		t.Errorf("summary =\n  %q\nwant\n  %q", f.Summary(), want)
	}
}

// --- the hypothesis ---------------------------------------------------------

// TestTheSuitabilityHypothesisFiresOnlyOnACompleteTotalFailure walks the matrix
// ADR 0084 section 5 fixes.
func TestTheSuitabilityHypothesisFiresOnlyOnACompleteTotalFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shapes []verdictShape
		want   bool
	}{
		{"every advertised endpoint failed, set complete", []verdictShape{shapeFailed, shapeFailed}, true},
		{"one endpoint, and it failed", []verdictShape{shapeFailed}, true},
		{"a reachable peer contradicts it", []verdictShape{shapeReached, shapeFailed}, false},
		{"every endpoint reachable", []verdictShape{shapeReached, shapeReached}, false},
		{"a failure beside an unmeasured endpoint", []verdictShape{shapeFailed, shapeUnmeasured}, false},
		{"nothing measured at all", []verdictShape{shapeUnmeasured, shapeUnmeasured}, false},
		{"only an unusable advertisement", []verdictShape{shapeUnusable}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _, _ := topologyFixture(t, tc.shapes...)
			got := AdvertisedTopologyUnsuitable(rctx(g))
			if tc.want && len(got) != 1 {
				t.Fatalf("findings = %d, want 1: %v", len(got), summaries(got))
			}
			if !tc.want && len(got) != 0 {
				t.Fatalf("findings = %d, want none: %v", len(got), summaries(got))
			}
		})
	}
}

// TestTheSuitabilityHypothesisCanNeverBeHigh is the confidence ceiling, asserted
// on the type rather than on the sentence.
//
// A rendered string could be reworded into overconfidence without failing a
// prose test. This drives the ladder itself: the rule declares AuthorityNone,
// and AuthorityNone admits LOW or MEDIUM and nothing above it, whatever the
// evidence looks like. Raising the ceiling would mean declaring an authority the
// rule does not have, which is a source change a reviewer sees.
func TestTheSuitabilityHypothesisCanNeverBeHigh(t *testing.T) {
	for _, count := range []int{1, 2, 3, 8, 40} {
		shapes := make([]verdictShape, count)
		for i := range shapes {
			shapes[i] = shapeFailed
		}
		g, _, _ := topologyFixture(t, shapes...)
		f := only(t, AdvertisedTopologyUnsuitable(rctx(g)))

		if f.Kind() != domain.FindingKindHypothesis {
			t.Errorf("%d endpoints: kind = %s, want HYPOTHESIS", count, f.Kind())
		}
		if f.Confidence() == domain.ConfidenceHigh {
			t.Errorf("%d endpoints: confidence = HIGH. Routing, listener exposure and a "+
				"broker-side outage are all unexcluded alternatives, and no Kafka field "+
				"states this condition, so neither admission test in ADR 0081 section 2.3 "+
				"applies", count)
		}
		if f.Confidence() != domain.ConfidenceMedium {
			t.Errorf("%d endpoints: confidence = %s, want MEDIUM", count, f.Confidence())
		}
	}

	// And the ladder itself refuses to promote it, whatever a future rule
	// author passes in alongside AuthorityNone.
	g, _, _ := topologyFixture(t, shapeFailed, shapeFailed)
	basis, err := diagnosis.NewBasis().Support(everyID(g)...).Freeze(g)
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	got, err := diagnosis.AdmitConfidence(
		domain.FindingKindHypothesis, diagnosis.AuthorityNone, basis)
	if err != nil {
		t.Fatalf("AdmitConfidence: %v", err)
	}
	if got == domain.ConfidenceHigh {
		t.Error("AuthorityNone admitted HIGH; the ceiling is not structural")
	}
}

// TestTheSuitabilityHypothesisNamesTheObservationThatWouldSettleIt is ADR 0082
// section 2.5 for this claim.
//
// A hypothesis with no discriminator is not actionable and ADR 0083 section 2.2
// rule 2 forbids emitting it. The discriminator and the recommendation are the
// same thought in two forms and must not disagree.
func TestTheSuitabilityHypothesisNamesTheObservationThatWouldSettleIt(t *testing.T) {
	g, _, _ := topologyFixture(t, shapeFailed, shapeFailed)
	f := only(t, AdvertisedTopologyUnsuitable(rctx(g)))

	if f.Discriminator() == "" {
		t.Fatal("the hypothesis carries no discriminator")
	}
	if len(f.Recommendations()) != 1 {
		t.Fatalf("recommendations = %d, want 1", len(f.Recommendations()))
	}
	action := f.Recommendations()[0].Action()
	if !strings.Contains(strings.ToLower(action), "compare") {
		t.Errorf("the recommendation is not the structured form of the discriminator: %q", action)
	}
	if err := diagnosis.ValidateActionText(action); err != nil {
		t.Errorf("the recommendation is not safe advice: %v", err)
	}

	// It asks for a comparison rather than for the same measurement again.
	// Re-running the identical sweep from the identical position produces the
	// identical evidence and separates nothing.
	for _, useless := range []string{"try again", "retry", "re-run"} {
		if strings.Contains(strings.ToLower(action+" "+f.Discriminator()), useless) {
			t.Errorf("the next evidence asks for a repeat rather than a discriminator: %q", action)
		}
	}
}

// TestTheUnsafeSafetyClassesAreUnreachableFromThisPackage is ADR 0082 section
// 2.3 rule 2, exercised through the projection these rules actually use.
func TestTheUnsafeSafetyClassesAreUnreachableFromThisPackage(t *testing.T) {
	for _, class := range []diagnosis.SafetyClass{
		diagnosis.SafetyRestart, diagnosis.SafetyDisruptive, diagnosis.SafetySecurityWeakening,
	} {
		got := diagnosis.Recommend(diagnosis.AdviceInput{
			Kind:      diagnosis.AdviceKindNextEvidence,
			Safety:    class,
			Action:    "Look at something",
			Rationale: "because",
		}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
		if got != nil {
			t.Errorf("%s advice was projected into a recommendation; the class is "+
				"unreachable by construction", class)
		}
	}

	// A remediation below the confidence gate is refused too, and refused
	// entirely rather than downgraded into an unclassified string.
	got := diagnosis.Recommend(diagnosis.AdviceInput{
		Kind:      diagnosis.AdviceKindRemediation,
		Safety:    diagnosis.SafetyConfigChange,
		Action:    "Change the advertised address",
		Rationale: "because",
	}, domain.FindingKindHypothesis, domain.ConfidenceMedium)
	if got != nil {
		t.Error("a REMEDIATION was projected from a MEDIUM hypothesis")
	}
}

// --- what neither rule may do ----------------------------------------------

// TestNoTopologyClaimSurvivesTheBootstrapNotReachingMetadata is K01 through K04
// in one place, and it is the phase's central structural rule.
//
// Without a passing Metadata exchange there is no advertised set, so there is
// nothing for a topology claim to be about. A run that failed at DNS, at TCP, at
// the capability exchange or at authentication has exactly the same standing
// here: none.
func TestNoTopologyClaimSurvivesTheBootstrapNotReachingMetadata(t *testing.T) {
	for _, state := range []domain.State{
		domain.StateFail, domain.StateUnknown, domain.StateSkipped, domain.StateDegraded,
	} {
		t.Run(state.String(), func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(state)
			// An advertisement recorded beneath a non-passing exchange is a
			// shape no producer makes; the rule must still refuse it rather than
			// read it.
			ad := b.advertised(exchange, 1, "broker-1.internal:9092")
			lookup := b.lookup(ad, "broker-1.internal", domain.StatePass, domain.FailureNone)
			b.connect(lookup, "10.20.0.1", 9092, domain.StateFail, domain.FailureTCPConnectionRefused)
			g := b.freeze()

			none(t, AdvertisedTopologyReachability(rctx(g)))
			none(t, AdvertisedTopologyUnsuitable(rctx(g)))
		})
	}

	// And a graph with no Metadata node at all.
	b := newBuilder(t)
	b.node("tcp.connect/bootstrap", "primary.internal:9092", domain.LayerTCP,
		"tcp.connect", domain.StateFail, domain.FailureTCPConnectionRefused, "", nil)
	g := b.freeze()
	none(t, AdvertisedTopologyReachability(rctx(g)))
	none(t, AdvertisedTopologyUnsuitable(rctx(g)))
}

// TestAnExchangeThatAdvertisedNothingProducesNothing covers the metadata-
// succeeded-and-named-no-broker shape.
func TestAnExchangeThatAdvertisedNothingProducesNothing(t *testing.T) {
	b := newBuilder(t)
	b.metadata(domain.StatePass)
	g := b.freeze()

	none(t, AdvertisedTopologyReachability(rctx(g)))
	none(t, AdvertisedTopologyUnsuitable(rctx(g)))
}

// TestTwoExchangesSharingOneSubjectProduceNothing is ADR 0084 section 8.
//
// Two findings sharing (Code, Subject) would be merged, and the merge takes the
// summary from a RuleID tie-break. For these codes that is not merely arbitrary:
// "None of the 2" and "1 of the 2" are different counts, and choosing between
// them alphabetically would publish a number nobody measured. The shape is
// refused rather than reconciled.
func TestTwoExchangesSharingOneSubjectProduceNothing(t *testing.T) {
	b := newBuilder(t)
	first := b.node("kafka.metadata/a", "primary.internal:9092", domain.LayerTopology,
		servicekafka.StepMetadata, domain.StatePass, domain.FailureNone, "", nil)
	second := b.node("kafka.metadata/b", "primary.internal:9092", domain.LayerTopology,
		servicekafka.StepMetadata, domain.StatePass, domain.FailureNone, "", nil)

	for i, exchange := range []domain.EvidenceID{first, second} {
		ad := b.node(fmt.Sprintf("kafka.broker_advertised/%d", i), "broker.internal:9092",
			domain.LayerTopology, servicekafka.StepBrokerAdvertised,
			domain.StatePass, domain.FailureNone, exchange, nil)
		lookup := b.lookup(ad, fmt.Sprintf("broker-%d.internal", i), domain.StatePass, domain.FailureNone)
		b.connect(lookup, fmt.Sprintf("10.20.0.%d", i+1), 9092,
			domain.StateFail, domain.FailureTCPConnectionRefused)
	}
	g := b.freeze()

	none(t, AdvertisedTopologyReachability(rctx(g)))
	none(t, AdvertisedTopologyUnsuitable(rctx(g)))
}

// TestAReachableLoopbackOrPrivateAdvertisementIsNotAnIncident is the address-
// shape trap, and it is a trap because the heuristic is so nearly useful.
//
// A cluster advertising 127.0.0.1 to a client on the same host is correct, and
// so is one advertising an RFC 1918 address to a client inside that network.
// The failure is the evidence; the shape of the address is not.
func TestAReachableLoopbackOrPrivateAdvertisementIsNotAnIncident(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "10.4.5.6", "192.168.10.20"} {
		t.Run(addr, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			ad := b.advertised(exchange, 1, addr+":9092")
			// An advertisement that named an address resolves nothing, so the
			// connection hangs straight off it (ADR 0059).
			b.node("tcp.connect/literal/"+addr, addr+":9092", domain.LayerTCP, "tcp.connect",
				domain.StatePass, domain.FailureNone, ad, nil)
			g := b.freeze()

			none(t, AdvertisedTopologyReachability(rctx(g)))
			none(t, AdvertisedTopologyUnsuitable(rctx(g)))
		})
	}
}

// TestTheTopologyRulesToleratesTheZeroRuleContext is the obligation every rule
// carries: a run that measured nothing must not panic one.
func TestTheTopologyRulesToleratesTheZeroRuleContext(t *testing.T) {
	none(t, AdvertisedTopologyReachability(diagnosis.RuleContext{}))
	none(t, AdvertisedTopologyUnsuitable(diagnosis.RuleContext{}))
}

// --- evidence, determinism and validity ------------------------------------

// TestEveryTopologyReferenceIsInTheGraphAndLoadBearing is ADR 0078 section 2.3
// rule 1: a citation that changes nothing was decoration.
//
// Load-bearingness is established by rebuilding the fixture without each cited
// node and requiring the output to change. A frozen graph cannot be edited, so
// the fixture is rebuilt — which is the honest form of the test anyway, because
// it is the producer that would stop writing a node.
func TestEveryTopologyReferenceIsInTheGraphAndLoadBearing(t *testing.T) {
	shapes := []verdictShape{shapeReached, shapeFailed}
	g, _, _ := topologyFixture(t, shapes...)
	f := only(t, AdvertisedTopologyReachability(rctx(g)))

	if len(f.EvidenceRefs()) == 0 {
		t.Fatal("the finding cites nothing")
	}
	for _, ref := range f.EvidenceRefs() {
		if _, ok := g.Node(ref); !ok {
			t.Errorf("cited evidence %q is not in the graph", ref)
		}
	}
	if !slices.IsSorted(f.EvidenceRefs()) {
		t.Errorf("evidence refs are not sorted: %v", f.EvidenceRefs())
	}

	for _, ref := range f.EvidenceRefs() {
		t.Run(string(ref), func(t *testing.T) {
			reduced := graphWithout(t, shapes, ref)
			got := AdvertisedTopologyReachability(rctx(reduced))
			if len(got) == 1 && got[0].Summary() == f.Summary() &&
				slices.Equal(got[0].EvidenceRefs(), f.EvidenceRefs()) {
				t.Errorf("removing %q changed nothing, so it was decoration", ref)
			}
		})
	}
}

// graphWithout rebuilds the fixture with one node and its descendants absent.
func graphWithout(t *testing.T, shapes []verdictShape, drop domain.EvidenceID) domain.Graph {
	t.Helper()

	full, _, _ := topologyFixture(t, shapes...)
	excluded := map[domain.EvidenceID]bool{drop: true}
	// A node's children cannot survive it: the graph refuses a parent edge to a
	// node it does not hold.
	for changed := true; changed; {
		changed = false
		for _, node := range full.Nodes() {
			if excluded[node.ID()] {
				continue
			}
			for _, parent := range full.Parents(node.ID()) {
				if excluded[parent] {
					excluded[node.ID()] = true
					changed = true
				}
			}
		}
	}

	b := domain.NewGraphBuilder()
	for _, node := range full.Nodes() {
		if excluded[node.ID()] {
			continue
		}
		if err := b.AddEvidence(node); err != nil {
			t.Fatalf("AddEvidence(%q): %v", node.ID(), err)
		}
	}
	for _, node := range full.Nodes() {
		if excluded[node.ID()] {
			continue
		}
		for _, parent := range full.Parents(node.ID()) {
			if err := b.AddParent(node.ID(), parent); err != nil {
				t.Fatalf("AddParent(%q): %v", node.ID(), err)
			}
		}
	}
	g, err := b.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return g
}

// TestEveryTopologyShapeBuildsAValidFinding drives the whole matrix through
// domain.NewFinding, so the "unreachable" error branches in the builders are
// proven unreachable rather than assumed.
func TestEveryTopologyShapeBuildsAValidFinding(t *testing.T) {
	built := 0
	for _, shapes := range topologyShapeMatrix() {
		for _, incomplete := range []bool{false, true} {
			g, _, _ := topologyFixture(t, shapes...)
			ctx := rctxWith(g, incomplete)
			for _, f := range slices.Concat(
				AdvertisedTopologyReachability(ctx), AdvertisedTopologyUnsuitable(ctx),
			) {
				if f.IsZero() {
					t.Fatalf("%v incomplete=%v produced a zero finding", shapes, incomplete)
				}
				built++
			}
		}
	}
	if built == 0 {
		t.Fatal("the matrix built no finding at all; this test would pass vacuously")
	}
	t.Logf("%d findings built across the shape matrix", built)
}

// topologyShapeMatrix enumerates the advertised-set shapes worth driving.
func topologyShapeMatrix() [][]verdictShape {
	all := []verdictShape{shapeReached, shapeFailed, shapeUnmeasured, shapeUnusable}

	var out [][]verdictShape
	for _, a := range all {
		out = append(out, []verdictShape{a})
		for _, b := range all {
			out = append(out, []verdictShape{a, b})
			for _, c := range all {
				out = append(out, []verdictShape{a, b, c})
			}
		}
	}
	return out
}

// TestTopologyOutputDoesNotDependOnAdvertisementOrder is K-P13.
//
// The cluster chooses the order brokers appear in a Metadata response, and it is
// free to change between calls. A report whose sentence depended on it would be
// non-deterministic for reasons outside svcdoctor entirely.
func TestTopologyOutputDoesNotDependOnAdvertisementOrder(t *testing.T) {
	forward, _, _ := topologyFixture(t, shapeReached, shapeFailed, shapeUnmeasured)
	reverse, _, _ := topologyFixture(t, shapeUnmeasured, shapeFailed, shapeReached)

	a := only(t, AdvertisedTopologyReachability(rctx(forward)))
	b := only(t, AdvertisedTopologyReachability(rctx(reverse)))

	if a.Summary() != b.Summary() {
		t.Errorf("advertisement order changed the sentence:\n  %q\n  %q", a.Summary(), b.Summary())
	}
	if len(a.EvidenceRefs()) != len(b.EvidenceRefs()) {
		t.Errorf("advertisement order changed the reference count: %d vs %d",
			len(a.EvidenceRefs()), len(b.EvidenceRefs()))
	}
}

// TestTheTopologyRulesAreDeterministic runs each rule repeatedly over one graph.
func TestTheTopologyRulesAreDeterministic(t *testing.T) {
	g, _, _ := topologyFixture(t, shapeFailed, shapeFailed, shapeUnusable)
	ctx := rctx(g)

	first := slices.Concat(
		AdvertisedTopologyReachability(ctx), AdvertisedTopologyUnsuitable(ctx))
	for i := 0; i < 32; i++ {
		again := slices.Concat(
			AdvertisedTopologyReachability(ctx), AdvertisedTopologyUnsuitable(ctx))
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d findings, want %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j].Summary() != first[j].Summary() ||
				!slices.Equal(again[j].EvidenceRefs(), first[j].EvidenceRefs()) {
				t.Fatalf("run %d differs at finding %d", i, j)
			}
		}
	}
}

// everyID returns every evidence identifier in a graph, for the basis tests.
func everyID(g domain.Graph) []domain.EvidenceID {
	var out []domain.EvidenceID
	for _, node := range g.Nodes() {
		if len(g.BlockedBy(node.ID())) > 0 {
			// A blocked node is evidence for nothing and BasisBuilder.Freeze
			// refuses it in either direction (ADR 0081 section 2.4).
			continue
		}
		out = append(out, node.ID())
	}
	return out
}

// --- guards the Phase 10.2 mutation suite exposed ---------------------------

// TestASweepShapeTheChainDoesNotProduceIsNotMeasured pins the direction an
// unrecognized graph errs in.
//
// The mutation that motivated it turned an unrecognized shape into a positively
// observed negative, and every other guard passed: the counts still summed, the
// findings were still valid, the fuzz properties still held. The claim that
// changed was the one nobody was asserting — an endpoint svcdoctor could not
// read was reported as one that refused.
func TestASweepShapeTheChainDoesNotProduceIsNotMeasured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(b *builder, ad domain.EvidenceID)
	}{
		{"two lookups under one advertisement", func(b *builder, ad domain.EvidenceID) {
			b.lookup(ad, "broker-1.internal", domain.StatePass, domain.FailureNone)
			b.node("dns.lookup/second", "broker-1.internal", domain.LayerDNS, "dns.lookup",
				domain.StatePass, domain.FailureNone, ad, nil)
		}},
		{"a resolution and a resolution-free connection", func(b *builder, ad domain.EvidenceID) {
			b.lookup(ad, "broker-1.internal", domain.StatePass, domain.FailureNone)
			b.node("tcp.connect/literal", "10.20.0.9:9092", domain.LayerTCP, "tcp.connect",
				domain.StateFail, domain.FailureTCPConnectionRefused, ad, nil)
		}},
		{"a protocol node where transport belongs", func(b *builder, ad domain.EvidenceID) {
			b.node("kafka.api_versions/under-ad", "broker-1.internal:9092", domain.LayerProtocol,
				servicekafka.StepAPIVersions, domain.StatePass, domain.FailureNone, ad, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			// One endpoint that really did fail, so the rule fires and there is a
			// sentence to inspect.
			failed := b.advertised(exchange, 1, "broker-9.internal:9092")
			l := b.lookup(failed, "broker-9.internal", domain.StatePass, domain.FailureNone)
			b.connect(l, "10.20.9.1", 9092, domain.StateFail, domain.FailureTCPConnectionRefused)

			ad := b.advertised(exchange, 2, "broker-1.internal:9092")
			tc.build(b, ad)
			g := b.freeze()

			if got := classifyAdvertised(g, mustNode(t, g, ad)); got != reachNotMeasured {
				t.Errorf("an unrecognized sweep classified as %d, want reachNotMeasured. "+
					"The failure this classification prevents is a count asserting an "+
					"endpoint was unreachable when nobody looked, so an unreadable "+
					"shape must err towards saying so.", got)
			}

			f := only(t, AdvertisedTopologyReachability(rctx(g)))
			if !strings.Contains(f.Summary(), "1 was not measured") {
				t.Errorf("summary = %q, want the unmeasured endpoint counted separately",
					f.Summary())
			}
			none(t, AdvertisedTopologyUnsuitable(rctx(g)))
		})
	}
}

// TestNoTopologyClaimSpeaksAboutACredential is the vocabulary boundary between
// these rules and the authentication ones.
//
// A topology claim is about endpoints a cluster named and whether they answered.
// It has no standing to say anything about a credential, and the two claims lead
// to opposite next moves: one sends an operator to look at the network, the
// other to look at a secret. The mutation that motivated this guard put
// `KAFKA_CREDENTIALS_REJECTED`'s own sentence on the suitability hypothesis,
// where it read as an accusation against a credential nobody presented to any
// broker in that sweep.
func TestNoTopologyClaimSpeaksAboutACredential(t *testing.T) {
	// The list is authentication vocabulary and not a general word list. Two
	// entries were removed after they matched correct prose: "account" is a
	// substring of "the counts above account for the whole advertised set", and
	// a guard that forbids ordinary English is a guard that gets deleted.
	authWords := []string{
		"credential", "password", "secret", "principal", "username", "user name",
		"authenticat", "sasl", "scram", "bearer token", "rejected", "logged in",
	}

	checked := 0
	for _, shapes := range topologyShapeMatrix() {
		for _, incomplete := range []bool{false, true} {
			g, _, _ := topologyFixture(t, shapes...)
			ctx := rctxWith(g, incomplete)
			for _, f := range slices.Concat(
				AdvertisedTopologyReachability(ctx), AdvertisedTopologyUnsuitable(ctx),
			) {
				checked++
				prose := strings.ToLower(f.Summary() + " " + f.Detail() + " " + f.Discriminator())
				for _, rec := range f.Recommendations() {
					prose += " " + strings.ToLower(rec.Action())
				}
				for _, word := range authWords {
					if strings.Contains(prose, word) {
						t.Errorf("%s says %q. A topology claim is about endpoints and "+
							"whether they answered; a credential claim is a different "+
							"finding with a different next move.\n%s", f.Code(), word, prose)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no claim was examined; this guard is vacuous")
	}
}

// TestTheTopologyReferencesCiteBothSidesOfTheContrast pins the reference set
// exactly, rather than counting it.
//
// docs/FINDINGS.md section 3.1 rule 10: both halves of a contrast are part of
// the proof. "Two were reached" rests on the nodes that reached them, and a
// version of this rule that cited only the failures would be asserting the
// positive half from the absence of evidence against it.
func TestTheTopologyReferencesCiteBothSidesOfTheContrast(t *testing.T) {
	g, exchange, ads := topologyFixture(t, shapeReached, shapeFailed, shapeUnmeasured)
	f := only(t, AdvertisedTopologyReachability(rctx(g)))

	refs := f.EvidenceRefs()
	for _, want := range append([]domain.EvidenceID{exchange}, ads...) {
		if !slices.Contains(refs, want) {
			t.Errorf("the finding does not cite %q; the exchange and every advertisement "+
				"are the set it counts", want)
		}
	}

	var sawPass, sawFail bool
	for _, ref := range refs {
		node := mustNode(t, g, ref)
		if node.Layer() == domain.LayerTopology {
			continue
		}
		switch node.State() {
		case domain.StatePass:
			sawPass = true
		case domain.StateFail:
			sawFail = true
		case domain.StateUnknown, domain.StateSkipped, domain.StateDegraded:
			t.Errorf("the finding cites %q, whose state %s proves nothing about "+
				"reachability", ref, node.State())
		}
	}
	if !sawPass {
		t.Error("no reaching node is cited, so \"1 was reached\" rests on nothing")
	}
	if !sawFail {
		t.Error("no failing node is cited, so the failure count rests on nothing")
	}
}

// TestTwoExchangesSharingASubjectNeverConverge is the merge-safety property
// ADR 0084 section 8 makes structural.
//
// If the shape were emitted rather than refused, the engine would merge the two
// findings and take Summary from a RuleID tie-break — publishing one of two
// different counts, chosen alphabetically. This asserts the refusal at the point
// the refusal lives, so a rule author who removes it fails here rather than in a
// report nobody re-reads.
func TestTwoExchangesSharingASubjectNeverConverge(t *testing.T) {
	b := newBuilder(t)
	var exchanges []domain.EvidenceID
	for i, shapes := range [][]verdictShape{
		{shapeFailed, shapeFailed},
		{shapeReached, shapeFailed},
	} {
		exchange := b.node(fmt.Sprintf("kafka.metadata/%d", i), "primary.internal:9092",
			domain.LayerTopology, servicekafka.StepMetadata,
			domain.StatePass, domain.FailureNone, "", nil)
		exchanges = append(exchanges, exchange)
		for j, shape := range shapes {
			host := fmt.Sprintf("b%d-%d.internal", i, j)
			ad := b.node(fmt.Sprintf("kafka.broker_advertised/%d-%d", i, j), host+":9092",
				domain.LayerTopology, servicekafka.StepBrokerAdvertised,
				domain.StatePass, domain.FailureNone, exchange, nil)
			l := b.lookup(ad, host, domain.StatePass, domain.FailureNone)
			state, class := domain.StatePass, domain.FailureNone
			if shape == shapeFailed {
				state, class = domain.StateFail, domain.FailureTCPConnectionRefused
			}
			b.connect(l, fmt.Sprintf("10.20.%d.%d", i, j+1), 9092, state, class)
		}
	}
	g := b.freeze()

	if len(exchanges) != 2 {
		t.Fatalf("the fixture built %d exchanges", len(exchanges))
	}
	none(t, AdvertisedTopologyReachability(rctx(g)))
	none(t, AdvertisedTopologyUnsuitable(rctx(g)))
}

// mustNode reads a node back out of a graph.
func mustNode(t *testing.T, g domain.Graph, id domain.EvidenceID) domain.Evidence {
	t.Helper()
	node, ok := g.Node(id)
	if !ok {
		t.Fatalf("evidence %q is not in the graph", id)
	}
	return node
}
