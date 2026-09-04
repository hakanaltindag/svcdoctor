package transport

import (
	"slices"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// What these findings are allowed to say, checked as text.
//
// The structural guards cannot catch a rule that draws the right conclusion and
// then explains it wrongly. A summary that says "the service is down" is a
// different claim from the one the code authorizes, and a reader acts on the
// sentence rather than on the constant.

// everyFinding produces one of each authorized finding, so a prose scan cannot
// silently cover fewer than three.
func everyFinding(t *testing.T) []domain.Finding {
	t.Helper()

	var out []domain.Finding
	out = append(out, DNS(rctx(requestedDNS(t, domain.StateFail, domain.FailureDNSNoAddress)))...)
	out = append(out, DNS(rctx(requestedDNS(t, domain.StateFail, domain.FailureDNSTimeout)))...)
	out = append(out, TCP(rctx(requestedTCP(t,
		fail("10.0.0.1", domain.FailureTCPConnectionRefused))))...)

	if len(out) != 3 {
		t.Fatalf("got %d findings, want one of each authorized code", len(out))
	}
	return out
}

// TestNoFindingClaimsACauseItDidNotObserve is the claim-discipline guard.
//
// Each banned phrase is one an operator would act on immediately and which the
// evidence does not support. "Firewall" is the one most likely to be added in
// good faith: a timeout really is what a dropped packet looks like, and it is
// also what an overloaded host, a black-holed route and a misconfigured security
// group look like. svcdoctor observed none of them.
func TestNoFindingClaimsACauseItDidNotObserve(t *testing.T) {
	banned := map[string]string{
		"firewall":       "a timeout does not distinguish a firewall from a route or a load problem",
		"security group": "svcdoctor observed no cloud configuration",
		"network policy": "svcdoctor observed no cluster policy",
		"is down":        "an unreachable endpoint is not an observed outage",
		"not running":    "svcdoctor observed no process",
		"does not exist": "the DNS probe refuses to assert non-existence, and so must this",
		"nxdomain":       "no producer emits NXDOMAIN; claiming it would invent the distinction",
		"unreachable":    "a refused connection proves a host answered",
		"misconfigured":  "svcdoctor observed values, never how they were produced",
		"blocked":        "nothing observed establishes that anything blocked anything",
		"no listener":    "svcdoctor observed no listener either way",
	}

	for _, finding := range everyFinding(t) {
		text := strings.ToLower(finding.Summary() + " " + finding.Detail())
		for _, r := range finding.Recommendations() {
			text += " " + strings.ToLower(r.Action())
		}

		for phrase, why := range banned {
			if strings.Contains(text, phrase) {
				t.Errorf("%s says %q: %s", finding.Code(), phrase, why)
			}
		}
	}
}

// TestTheScanWouldCatchABannedPhrase is the control.
//
// A phrase list checked against text that never contained any of them proves
// nothing about the scan.
func TestTheScanWouldCatchABannedPhrase(t *testing.T) {
	sample := strings.ToLower(
		"The service is down, a firewall blocked it, the host is unreachable, " +
			"the name does not exist, and the process is not running")
	for _, phrase := range []string{
		"is down", "firewall", "blocked", "unreachable", "does not exist", "not running",
	} {
		if !strings.Contains(sample, phrase) {
			t.Errorf("the scan cannot see %q; the guard above is vacuous", phrase)
		}
	}
}

// TestEveryFindingNamesItsVantage pins the qualification that makes the claims
// honest.
//
// Each summary is a statement about one network position. Dropping the
// qualification would turn "I could not reach it" into "it cannot be reached",
// which is the overclaim the vantage flag exists to prevent and which no reader
// would catch from the flag alone.
func TestEveryFindingNamesItsVantage(t *testing.T) {
	for _, finding := range everyFinding(t) {
		if !strings.Contains(finding.Summary(), "from this vantage point") {
			t.Errorf("%s summary does not qualify its position: %q",
				finding.Code(), finding.Summary())
		}
		if !finding.VantageDependent() {
			t.Errorf("%s is not marked vantage-dependent", finding.Code())
		}
	}
}

// TestNoFindingCarriesADiscriminator pins that a CONFIRMED claim leaves nothing
// open.
//
// docs/FINDINGS.md reserves the discriminator for a HYPOTHESIS, where it names
// the observation that would settle the question. All three findings here restate
// a measurement, so there is nothing to settle.
func TestNoFindingCarriesADiscriminator(t *testing.T) {
	for _, finding := range everyFinding(t) {
		if finding.Discriminator() != "" {
			t.Errorf("%s carries a discriminator %q on a CONFIRMED finding",
				finding.Code(), finding.Discriminator())
		}
	}
}

// TestFindingsSurvivePseudonymization is docs/FINDINGS.md's own readability test.
//
// Read the finding with every hostname replaced and ask whether it still says
// what failed. It does only if the prose carries no identity — which is also what
// keeps a shareable report from leaking through a sentence redaction cannot see.
func TestFindingsSurvivePseudonymization(t *testing.T) {
	for _, finding := range everyFinding(t) {
		text := finding.Summary() + " " + finding.Detail()
		for _, r := range finding.Recommendations() {
			text += " " + r.Action()
		}

		for _, identity := range []string{"db.example.com", "10.0.0.1", "5432"} {
			if strings.Contains(text, identity) {
				t.Errorf("%s puts %q in prose; identity belongs on the subject and the "+
					"evidence, where redaction transforms it", finding.Code(), identity)
			}
		}
	}
}

// TestRecommendationTextIsValid pins the constants the unreachable branch in
// recommendations() assumes.
func TestRecommendationTextIsValid(t *testing.T) {
	for _, action := range []string{
		recommendNameNotResolved, recommendResolutionFailed, recommendConnectionNotEstablished,
	} {
		if _, err := domain.NewRecommendation(action); err != nil {
			t.Errorf("NewRecommendation(%q): %v", action, err)
		}
	}

	for _, finding := range everyFinding(t) {
		if got := len(finding.Recommendations()); got != 1 {
			t.Errorf("%s carries %d recommendations, want exactly 1", finding.Code(), got)
		}
	}
}

// TestEveryAuthorizedShapeBuildsAValidFinding drives the whole producer matrix
// through build, so the unreachable error branch there is asserted rather than
// assumed.
func TestEveryAuthorizedShapeBuildsAValidFinding(t *testing.T) {
	dnsClasses := []domain.FailureClass{
		domain.FailureDNSNoAddress,
		domain.FailureDNSTimeout,
		domain.FailureDNSResolverFailure,
	}
	for _, class := range dnsClasses {
		if got := len(DNS(rctx(requestedDNS(t, domain.StateFail, class)))); got != 1 {
			t.Errorf("%s produced %d findings, want 1", class, got)
		}
	}

	tcpClasses := []domain.FailureClass{
		domain.FailureTCPConnectionRefused,
		domain.FailureTCPConnectionReset,
		domain.FailureTCPConnectionTimeout,
		domain.FailureTCPNetworkUnreachable,
		domain.FailureTCPHostUnreachable,
		domain.FailureTCPConnectionFailed,
	}
	for _, class := range tcpClasses {
		graph := requestedTCP(t, fail("10.0.0.1", class))
		if got := len(TCP(rctx(graph))); got != 1 {
			t.Errorf("%s produced %d findings, want 1", class, got)
		}
	}
}

// --- determinism ---------------------------------------------------------------

// TestOutputIsIndependentOfInsertionOrder pins determinism before the engine
// sorts anything.
//
// Addresses are discovered in whatever order a resolver and the network produce,
// and a report has to be byte-stable for the same facts. The graph canonicalizes
// its own order, and these rules must not reintroduce a dependency on how the
// graph was built.
func TestOutputIsIndependentOfInsertionOrder(t *testing.T) {
	outcomes := []connectOutcome{
		fail("10.0.0.1", domain.FailureTCPConnectionRefused),
		fail("10.0.0.2", domain.FailureTCPConnectionTimeout),
		fail("10.0.0.3", domain.FailureTCPHostUnreachable),
		fail("10.0.0.4", domain.FailureTCPConnectionReset),
	}

	baseline := TCP(rctx(requestedTCP(t, outcomes...)))
	if len(baseline) != 1 {
		t.Fatalf("got %d findings, want 1", len(baseline))
	}
	wantRefs := baseline[0].EvidenceRefs()

	for _, permutation := range permutations(outcomes) {
		findings := TCP(rctx(requestedTCP(t, permutation...)))
		if len(findings) != 1 {
			t.Fatalf("permutation %v produced %d findings", permutation, len(findings))
		}
		if !slices.Equal(findings[0].EvidenceRefs(), wantRefs) {
			t.Errorf("permutation produced refs %v, want %v",
				findings[0].EvidenceRefs(), wantRefs)
		}
		if findings[0].Summary() != baseline[0].Summary() {
			t.Error("permutation changed the summary")
		}
	}
}

// TestTwoAnchorsProduceDeterministicOrder pins the multi-target case before one
// exists.
//
// ADR 0043 fixes the aggregation unit as the anchor and says a rule must iterate
// anchors rather than expect one, so that multi-target support is a composition
// change and not a rule rewrite. This asserts the iteration is already ordered.
func TestTwoAnchorsProduceDeterministicOrder(t *testing.T) {
	build := func() domain.Graph {
		b := newBuilder(t)
		for _, target := range []struct{ endpoint, host string }{
			{"b.example.com:5432", "b.example.com"},
			{"a.example.com:5432", "a.example.com"},
		} {
			anchor := b.anchor(target.endpoint)
			b.lookup(anchor, target.host, domain.StateFail, domain.FailureDNSNoAddress)
		}
		return b.freeze()
	}

	first := DNS(rctx(build()))
	if len(first) != 2 {
		t.Fatalf("got %d findings, want one per anchor", len(first))
	}
	if first[0].Subject().Ref() != "a.example.com:5432" {
		t.Errorf("first subject = %q, want canonical order to put a.example.com first",
			first[0].Subject().Ref())
	}

	second := DNS(rctx(build()))
	for i := range first {
		if first[i].Subject().Ref() != second[i].Subject().Ref() {
			t.Error("two evaluations of one graph disagreed on order")
		}
	}
}

// permutations returns every ordering of a small slice.
func permutations(in []connectOutcome) [][]connectOutcome {
	if len(in) <= 1 {
		return [][]connectOutcome{slices.Clone(in)}
	}

	var out [][]connectOutcome
	for i := range in {
		rest := make([]connectOutcome, 0, len(in)-1)
		rest = append(rest, in[:i]...)
		rest = append(rest, in[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]connectOutcome{in[i]}, tail...))
		}
	}
	return out
}
