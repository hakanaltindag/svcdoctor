package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The HYPOTHESIS matrix: some paths failed, others never completed, and nothing
// reached the terminal layer.
//
// The claim is a different one, not a hedged version of the confirmed claim:
// "at least one path failed; the rest were unmeasured". The severity follows the
// claim rather than the belief, which is why WARN here is not severity tracking
// confidence (ADR 0034 section 8).

// TestFailureBesideAnUnknownPathIsAHypothesis is the canonical mixed sweep.
func TestFailureBesideAnUnknownPathIsAHypothesis(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)
	refused := b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	unmeasured := b.connect(
		lookup, "10.20.0.2", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(rctx(graph)))
	hypothesis(t, f)

	// Both halves of the claim are evidenced: the failure, and the path that was
	// never finished. The unmeasured node is cited as evidence of the
	// incompleteness the finding asserts, not as a cause (ADR 0034 section 11.4).
	wantRefs(t, f, exchange, advertisement, refused, unmeasured)
	assertRefsAreClean(t, graph, f, exchange, advertisement)

	if !strings.Contains(f.Summary(), "not measured") {
		t.Errorf("summary does not express incompleteness: %q", f.Summary())
	}
	if !strings.Contains(f.Detail(), "not proven") {
		t.Errorf("detail does not express incompleteness: %q", f.Detail())
	}
}

// TestFailureBesideABudgetSkippedPathIsAHypothesis covers the other unmeasured
// shape: an address the budget never attempted, recorded by recordUnattempted as
// a SKIPPED TCP node with an EXEC_ class.
//
// It is the case ADR 0034 section 9 warns must not be handled by a blanket
// "SKIPPED is never referenced" rule: a prerequisite skip is never a cause, but
// a budget skip is exactly the evidence this hypothesis rests on.
func TestFailureBesideABudgetSkippedPathIsAHypothesis(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)

	refused := b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	prerequisiteSkip := b.skippedHandshake(refused, "10.20.0.1", 9093)

	unattempted := b.connect(lookup, "10.20.0.2", 9093, domain.StateSkipped, domain.FailureExecCancelled)
	budgetSkipHandshake := b.skippedHandshake(unattempted, "10.20.0.2", 9093)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(rctx(graph)))
	hypothesis(t, f)

	// The budget-skipped TCP node is cited; both prerequisite skips beneath the
	// TCP nodes are not.
	wantRefs(t, f, exchange, advertisement, refused, unattempted)
	assertRefsAreClean(t, graph, f, exchange, advertisement)

	for _, skip := range []domain.EvidenceID{prerequisiteSkip, budgetSkipHandshake} {
		for _, ref := range f.EvidenceRefs() {
			if ref == skip {
				t.Errorf("prerequisite skip %s is referenced", skip)
			}
		}
	}
}

// TestSeveralFailuresAndSeveralUnmeasuredPathsCiteEveryOwner proves the causal
// set is per path rather than one representative of each category.
func TestSeveralFailuresAndSeveralUnmeasuredPathsCiteEveryOwner(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)

	refused := b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	reset := b.connect(lookup, "10.20.0.2", 9093, domain.StateFail, domain.FailureTCPConnectionReset)
	timedOut := b.connect(lookup, "10.20.0.3", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
	cancelled := b.connect(lookup, "10.20.0.4", 9093, domain.StateSkipped, domain.FailureExecCancelled)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(rctx(graph)))
	hypothesis(t, f)
	wantRefs(t, f, exchange, advertisement, refused, reset, timedOut, cancelled)
}

// TestAHandshakeThatNeverFinishedIsIncompleteness covers the mixed sweep at L3:
// one handshake was rejected and another never completed.
func TestAHandshakeThatNeverFinishedIsIncompleteness(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)

	firstTCP := b.connect(lookup, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
	rejected := b.handshake(
		firstTCP, "10.20.0.1", 9093, domain.StateFail, domain.FailureTLSUnknownAuthority)
	secondTCP := b.connect(lookup, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone)
	unfinished := b.handshake(
		secondTCP, "10.20.0.2", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(rctx(graph)))
	hypothesis(t, f)
	wantRefs(t, f, exchange, advertisement, rejected, unfinished)
	assertRefsAreClean(t, graph, f, exchange, advertisement)
}

// TestTheHypothesisDoesNotTriggerProblemsFound restates the operational half of
// ADR 0034 section 20: an incomplete measurement must never fail a pipeline on
// svcdoctor's own timeout.
func TestTheHypothesisDoesNotTriggerProblemsFound(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)
	b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	b.connect(lookup, "10.20.0.2", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)

	f := only(t, AdvertisedEndpointUnreachable(rctx(b.freeze())))
	if f.Severity() == domain.SeverityError || f.Severity() == domain.SeverityCritical {
		t.Errorf("severity = %s; a hypothesis must not make the run exit non-zero", f.Severity())
	}
}
