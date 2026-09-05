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

// Phase 10.2, level L4: the topology rules against arbitrary advertised sets.
//
// The unit tests drive the shapes a Kafka run produces. This drives the shapes
// it does not: duplicate broker identifiers, an advertisement with no sweep, a
// sweep with two lookups, hostile hostnames, hundreds of endpoints, and every
// state at every level. The properties asserted are the ones that must hold on
// any input at all, because a graph is built from a server's answer and a server
// is not obliged to be reasonable.

// FuzzAdvertisedTopology drives both Phase 10.2 rules over a generated graph.
//
// The seed corpus covers the shapes the unit tests name, so a regression in one
// of them is caught by `go test` and not only by a fuzzing run.
func FuzzAdvertisedTopology(f *testing.F) {
	f.Add([]byte{}, "b.example", false)
	f.Add([]byte{0}, "b.example", false)
	f.Add([]byte{1, 1, 1}, "b.example", false)
	f.Add([]byte{0, 1, 2}, "b.example", true)
	f.Add([]byte{2, 2, 2, 2, 2}, "broker.example", false)
	f.Add([]byte{3, 4, 5, 6, 7, 8}, "x", true)
	f.Add([]byte{9, 9, 9}, "\n\r\t", false)
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, strings.Repeat("a", 200), true)
	// "Brok" is here because the first version of this target checked the prose
	// for the hostname as a substring, and a four-letter host that is a prefix of
	// "broker" failed it on prose that had copied nothing. The check below is the
	// property that was meant, and this seed keeps the case covered.
	f.Add([]byte{1, 1}, "Brok", false)
	// The empty host, for the shape-versus-name distinction described on
	// fuzzGraph. It is a legal ":9092" endpoint and an illegal bare hostname.
	f.Add([]byte{1, 1}, "", false)

	f.Fuzz(func(t *testing.T, shape []byte, host string, incomplete bool) {
		g, built := fuzzGraph(t, shape, host)
		if !built {
			return
		}
		ctx := diagnosis.RuleContext{Graph: g, Incomplete: incomplete}

		observation := AdvertisedTopologyReachability(ctx)
		hypothesis := AdvertisedTopologyUnsuitable(ctx)

		assertAtMostOnePerIdentity(t, slices.Concat(observation, hypothesis))
		for _, finding := range slices.Concat(observation, hypothesis) {
			assertTopologyFindingIsWellFormed(t, g, finding)
			assertProseIsInert(t, finding)
		}
		assertCountsAreConsistent(t, observation)
		assertHypothesisImpliesNoReachedEndpoint(t, observation, hypothesis, incomplete)
		assertProseIgnoresTheAdvertisedName(t, shape, host, incomplete,
			proseOf(slices.Concat(observation, hypothesis)))
	})
}

// fuzzGraph turns a byte string into a Metadata exchange and an advertised set.
//
// Each byte is one advertisement, and its low nibble selects a shape from a
// table that deliberately includes graphs no producer makes. It returns false
// when the generated graph could not be frozen, which is not a finding about the
// rules.
func fuzzGraph(t *testing.T, shape []byte, host string) (domain.Graph, bool) {
	t.Helper()

	// A hostile host must still be a usable subject reference in **both** the
	// positions a sweep puts it — bare on the DNS node, and with a port on the
	// advertisement — because a name that is valid in one and not the other
	// produces a differently *shaped* graph rather than a differently named one,
	// and assertProseIgnoresTheAdvertisedName would then be comparing two
	// different scenarios. The fuzzer found exactly that with the empty string,
	// which is a legal ":9092" endpoint and an illegal bare host.
	_, withPort := domain.NewEndpointSubject(host + ":9092")
	_, bare := domain.NewEndpointSubject(host)
	if withPort != nil || bare != nil {
		host = "b.example"
	}
	// Bound the work so a fuzzer cannot turn this into a memory test.
	if len(shape) > 64 {
		shape = shape[:64]
	}

	b := domain.NewGraphBuilder()
	exchange, ok := fuzzNode(t, b, "kafka.metadata/x", "bootstrap.example:9092",
		domain.LayerTopology, servicekafka.StepMetadata, domain.StatePass,
		domain.FailureNone, "")
	if !ok {
		return domain.Graph{}, false
	}

	for i, code := range shape {
		endpoint := fmt.Sprintf("%s:%d", host, 9092+i%3)
		state, class := domain.StatePass, domain.FailureNone
		if code&0x10 != 0 {
			// An advertisement the cluster stated unusably.
			state, class = domain.StateFail, domain.FailureProtocolUnexpectedResponse
		}
		ad, ok := fuzzNode(t, b, fmt.Sprintf("kafka.broker_advertised/%d", i), endpoint,
			domain.LayerTopology, servicekafka.StepBrokerAdvertised, state, class, exchange)
		if !ok {
			continue
		}
		fuzzSweep(t, b, ad, i, host, code%10)
	}

	g, err := b.Freeze()
	if err != nil {
		return domain.Graph{}, false
	}
	return g, true
}

// fuzzSweep hangs one of ten sweep shapes beneath an advertisement.
//
// Shapes 0 through 5 are ones the transport chain produces. Shapes 6 through 9
// are ones it does not: no sweep at all, two lookups under one advertisement,
// two handshakes under one connection, and a protocol node where transport
// belongs. Every one of them must leave the rules silent or counting the
// endpoint as unmeasured, never as a proven failure.
func fuzzSweep(
	t *testing.T, b *domain.GraphBuilder, ad domain.EvidenceID, i int, host string, shape byte,
) {
	t.Helper()

	addr := fmt.Sprintf("10.30.%d.%d:9092", i/250, i%250)
	lookupID := fmt.Sprintf("dns.lookup/%d", i)
	tcpID := fmt.Sprintf("tcp.connect/%d", i)
	tlsID := fmt.Sprintf("tls.handshake/%d", i)

	lookup := func(state domain.State, class domain.FailureClass) (domain.EvidenceID, bool) {
		return fuzzNode(t, b, lookupID, host, domain.LayerDNS, "dns.lookup", state, class, ad)
	}
	connect := func(parent domain.EvidenceID, state domain.State, class domain.FailureClass) (domain.EvidenceID, bool) {
		return fuzzNode(t, b, tcpID, addr, domain.LayerTCP, "tcp.connect", state, class, parent)
	}

	switch shape {
	case 0: // resolved, connected
		if l, ok := lookup(domain.StatePass, domain.FailureNone); ok {
			connect(l, domain.StatePass, domain.FailureNone)
		}
	case 1: // resolved, refused
		if l, ok := lookup(domain.StatePass, domain.FailureNone); ok {
			connect(l, domain.StateFail, domain.FailureTCPConnectionRefused)
		}
	case 2: // resolved, connected, handshake failed
		if l, ok := lookup(domain.StatePass, domain.FailureNone); ok {
			if c, ok := connect(l, domain.StatePass, domain.FailureNone); ok {
				fuzzNode(t, b, tlsID, addr, domain.LayerTLS, "tls.handshake",
					domain.StateFail, domain.FailureTLSHostnameMismatch, c)
			}
		}
	case 3: // did not resolve
		lookup(domain.StateFail, domain.FailureDNSNXDomain)
	case 4: // resolution never finished
		lookup(domain.StateUnknown, domain.FailureExecLocalTimeout)
	case 5: // an address literal: no lookup at all
		connect(ad, domain.StateUnknown, domain.FailureExecCancelled)
	case 6: // nothing beneath the advertisement
	case 7: // two lookups under one advertisement, which no producer makes
		if _, ok := lookup(domain.StatePass, domain.FailureNone); ok {
			fuzzNode(t, b, lookupID+"-b", host, domain.LayerDNS, "dns.lookup",
				domain.StatePass, domain.FailureNone, ad)
		}
	case 8: // two handshakes under one connection, which no producer makes
		if l, ok := lookup(domain.StatePass, domain.FailureNone); ok {
			if c, ok := connect(l, domain.StatePass, domain.FailureNone); ok {
				fuzzNode(t, b, tlsID, addr, domain.LayerTLS, "tls.handshake",
					domain.StatePass, domain.FailureNone, c)
				fuzzNode(t, b, tlsID+"-b", addr, domain.LayerTLS, "tls.handshake",
					domain.StateFail, domain.FailureTLSUnknownAuthority, c)
			}
		}
	case 9: // a protocol node where transport belongs
		fuzzNode(t, b, fmt.Sprintf("kafka.api_versions/%d", i), addr, domain.LayerProtocol,
			servicekafka.StepAPIVersions, domain.StatePass, domain.FailureNone, ad)
	}
}

// fuzzNode adds one node, reporting whether it landed.
//
// A rejected node is not a defect: the builder refuses duplicates and malformed
// values, and a fuzzer will generate both. What matters is that the rules cope
// with whatever did land.
func fuzzNode(
	t *testing.T, b *domain.GraphBuilder, id, subjectRef string, layer domain.Layer,
	step domain.Step, state domain.State, class domain.FailureClass, parent domain.EvidenceID,
) (domain.EvidenceID, bool) {
	t.Helper()

	subject, err := domain.NewEndpointSubject(subjectRef)
	if err != nil {
		return "", false
	}
	elapsed := domain.Measured(0)
	if state == domain.StateUnknown || state == domain.StateSkipped {
		elapsed = domain.Unmeasured()
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: domain.EvidenceID(id), Subject: subject, Layer: layer, Step: step,
		State: state, FailureClass: class, StartedAt: origin, Elapsed: elapsed,
	})
	if err != nil {
		return "", false
	}
	if err := b.AddEvidence(evidence); err != nil {
		return "", false
	}
	if parent != "" {
		if err := b.AddParent(evidence.ID(), parent); err != nil {
			return "", false
		}
	}
	return evidence.ID(), true
}

// assertAtMostOnePerIdentity is the convergence-safety property, checked before
// the engine ever runs.
//
// These rules must not produce two findings sharing (Code, Subject), because the
// merge would then choose one of two different sentences by a rule-name
// tie-break. ADR 0084 section 8 makes it structural; this is the check that the
// structure holds on inputs nobody designed.
func assertAtMostOnePerIdentity(t *testing.T, findings []domain.Finding) {
	t.Helper()

	seen := map[string]int{}
	for _, f := range findings {
		key := string(f.Code()) + "\x00" + f.Subject().Ref()
		seen[key]++
		if seen[key] > 1 {
			t.Fatalf("%s appears %d times for subject %q; the merge would choose one "+
				"summary of several by RuleID", f.Code(), seen[key], f.Subject().Ref())
		}
	}
}

// assertTopologyFindingIsWellFormed checks the structural obligations every
// finding these rules emit must meet.
func assertTopologyFindingIsWellFormed(t *testing.T, g domain.Graph, f domain.Finding) {
	t.Helper()

	if f.IsZero() {
		t.Fatal("a zero finding reached the output")
	}
	if f.Subject().IsZero() {
		t.Fatalf("%s carries no subject", f.Code())
	}
	if f.Layer() != domain.LayerTopology {
		t.Fatalf("%s is filed at %s, want L6", f.Code(), f.Layer())
	}
	if !f.VantageDependent() {
		t.Fatalf("%s is not vantage-dependent; every claim here is about reachability "+
			"from one network position", f.Code())
	}
	if f.EvidenceRefCount() == 0 {
		t.Fatalf("%s cites nothing", f.Code())
	}
	for _, ref := range f.EvidenceRefs() {
		node, ok := g.Node(ref)
		if !ok {
			t.Fatalf("%s cites %q, which is not in the graph", f.Code(), ref)
		}
		if len(g.BlockedBy(node.ID())) > 0 {
			t.Fatalf("%s cites %q, which did not run because an upstream step failed; "+
				"a blocked step is evidence for nothing", f.Code(), ref)
		}
	}
	if !slices.IsSorted(f.EvidenceRefs()) {
		t.Fatalf("%s cites %v, which is not sorted", f.Code(), f.EvidenceRefs())
	}

	switch f.Code() {
	case CodeAdvertisedTopologyReachability:
		if f.Kind() != domain.FindingKindConfirmed || f.Severity() != domain.SeverityInfo {
			t.Fatalf("the observation is %s at %s, want CONFIRMED at INFO",
				f.Kind(), f.Severity())
		}
		if f.Discriminator() != "" {
			t.Fatalf("the observation carries the discriminator %q", f.Discriminator())
		}
	case CodeAdvertisedTopologyUnsuitable:
		if f.Kind() != domain.FindingKindHypothesis {
			t.Fatalf("the suitability claim is %s, want HYPOTHESIS", f.Kind())
		}
		if f.Confidence() == domain.ConfidenceHigh {
			t.Fatal("the suitability hypothesis reached HIGH; no evidence available to " +
				"these rules discriminates it from a routing or broker-side alternative")
		}
		if f.Discriminator() == "" {
			t.Fatal("a hypothesis with no discriminator is not actionable and must not " +
				"be emitted (ADR 0083 section 2.2 rule 2)")
		}
		if len(f.Recommendations()) == 0 {
			t.Fatal("a hypothesis carrying a discriminator must carry the structured " +
				"form of it too (ADR 0082 section 2.5)")
		}
	default:
		t.Fatalf("an unexpected code %s reached the output", f.Code())
	}

	for _, rec := range f.Recommendations() {
		if err := diagnosis.ValidateActionText(rec.Action()); err != nil {
			t.Fatalf("%s carries unsafe advice: %v", f.Code(), err)
		}
	}
}

// assertProseIsInert checks that a claim cannot act on the surfaces it is
// rendered into: the terminal, Markdown and JSON each read some of these
// differently.
func assertProseIsInert(t *testing.T, f domain.Finding) {
	t.Helper()

	prose := proseOf([]domain.Finding{f})
	for _, bad := range []string{"\r", "\t", "\x1b", "\x00", "```", "](", "{\""} {
		if strings.Contains(prose, bad) {
			t.Fatalf("%s prose contains %q, which a renderer would act on", f.Code(), bad)
		}
	}
}

// assertProseIgnoresTheAdvertisedName is ADR 0081 section 2.7 under adversarial
// input, and it is stated as an equality rather than as a substring search.
//
// # Why the substring form was wrong
//
// The first version of this check asked whether the prose contained the
// advertised hostname, and the fuzzer refuted it in under a second: the host
// "Brok" is a case-insensitive substring of the word "broker", which every one
// of these sentences contains and none of them copied. A substring search over
// English is a search for coincidences.
//
// The property that was actually meant is that the advertised name does not
// *influence* the prose at all. Rebuilding the identical graph shape under a
// fixed benign name and requiring byte equality says exactly that, and it holds
// against any encoding, any homoglyph and any escaping a substring check would
// miss.
func assertProseIgnoresTheAdvertisedName(
	t *testing.T, shape []byte, host string, incomplete bool, got string,
) {
	t.Helper()

	const benign = "reference.example"
	if host == benign {
		return
	}
	g, built := fuzzGraph(t, shape, benign)
	if !built {
		return
	}
	ctx := diagnosis.RuleContext{Graph: g, Incomplete: incomplete}
	want := proseOf(slices.Concat(
		AdvertisedTopologyReachability(ctx), AdvertisedTopologyUnsuitable(ctx)))

	if got != want {
		t.Fatalf("advertising %q changed the trusted prose.\n got %q\nwant %q\n\n"+
			"A hostname is server-controlled and reaches the report as a subject and "+
			"as evidence, where it is typed and redactable. It may not reach a "+
			"summary, a detail, a discriminator or a recommendation.", host, got, want)
	}
}

// proseOf concatenates every free-text field a set of findings carries.
func proseOf(findings []domain.Finding) string {
	var out strings.Builder
	for _, f := range findings {
		out.WriteString(f.Summary())
		out.WriteString("\n")
		out.WriteString(f.Detail())
		out.WriteString("\n")
		out.WriteString(f.Discriminator())
		for _, rec := range f.Recommendations() {
			out.WriteString("\n")
			out.WriteString(rec.Action())
		}
		out.WriteString("\n")
	}
	return out.String()
}

// assertCountsAreConsistent checks the arithmetic inside the observation's own
// sentence.
//
// It is the cheapest possible guard against the whole class of counting defect:
// whatever the shapes were, the three categories must sum to the total the
// sentence names, and none of them may be negative.
func assertCountsAreConsistent(t *testing.T, observation []domain.Finding) {
	t.Helper()

	for _, f := range observation {
		summary := f.Summary()
		switch {
		case strings.HasPrefix(summary, "The one broker endpoint"):
		case strings.HasPrefix(summary, "None of the "):
			var total int
			if _, err := fmt.Sscanf(summary, "None of the %d broker endpoints", &total); err != nil {
				t.Fatalf("parsing %q: %v", summary, err)
			}
			if total < 2 {
				t.Fatalf("%q names a total of %d; the universal form needs at least two",
					summary, total)
			}
		default:
			var notReached, total int
			if _, err := fmt.Sscanf(summary, "%d of the %d broker endpoints",
				&notReached, &total); err != nil {
				t.Fatalf("parsing %q: %v", summary, err)
			}
			if notReached < 1 {
				t.Fatalf("%q fired with nothing positively failing", summary)
			}
			if notReached > total {
				t.Fatalf("%q counts more failures than endpoints", summary)
			}
		}
	}
}

// assertHypothesisImpliesNoReachedEndpoint is the contradiction rule, stated as
// an implication over the pair of findings.
//
// The suitability hypothesis rests on nothing having been reached. If the
// observation beside it names a reached endpoint, or admits an unmeasured one,
// the hypothesis had no business being emitted.
func assertHypothesisImpliesNoReachedEndpoint(
	t *testing.T, observation, hypothesis []domain.Finding, incomplete bool,
) {
	t.Helper()

	if len(hypothesis) == 0 {
		return
	}
	if incomplete {
		t.Fatal("a suitability hypothesis survived a run svcdoctor cut short; a claim " +
			"about a whole set needs the whole set")
	}
	if len(observation) != len(hypothesis) {
		t.Fatalf("%d hypotheses beside %d observations; the hypothesis fires only where "+
			"something positively failed, which the observation also reports",
			len(hypothesis), len(observation))
	}
	for _, f := range observation {
		if !strings.HasPrefix(f.Summary(), "None of the ") &&
			!strings.HasPrefix(f.Summary(), "The one broker endpoint") {
			t.Fatalf("a suitability hypothesis was emitted beside %q, which names a "+
				"reached or unmeasured endpoint", f.Summary())
		}
	}
}
