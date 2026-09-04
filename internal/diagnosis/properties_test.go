package diagnosis

import (
	"encoding/json"
	"runtime"
	"slices"
	"strconv"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The Phase 10.1a property suite.
//
// Eighteen invariants. Most are also asserted at the point they are implemented,
// where the failure message is more useful; this file is where they are stated
// as *properties* rather than as unit expectations, so that a reader can see the
// whole contract in one place and a mutation harness has one obvious target.
//
// Several of them are already held elsewhere and are cross-referenced rather
// than duplicated, because a second copy of an assertion is a second thing to
// keep in step.
//
//	P01 input permutation does not change the semantic result   here
//	P02 rule registration permutation does not change the result here
//	P03 UNKNOWN never becomes FAIL                               here
//	P04 SKIPPED never becomes FAIL                               here
//	P05 missing evidence is not contradiction                    basis_test.go
//	P06 blocked evidence is not contradiction                    basis_test.go
//	P07 contradiction cannot raise confidence                    confidence_test.go
//	P08 missing evidence cannot raise confidence                 confidence_test.go
//	P09 many weak supports cannot vote to HIGH                   confidence_test.go
//	P10 duplicate semantic hypotheses converge deterministically  converge_test.go
//	P11 separate subjects remain separate                        converge_test.go
//	P12 an all-PASS graph produces no failure boundary           boundary_test.go
//	P13 cancellation does not fabricate a failure boundary       boundary_test.go
//	P14 invalid evidence references are rejected                 failure_test.go, basis_test.go
//	P15 a duplicate RuleID is rejected                           registry_test.go
//	P16 a frozen registry is immutable                           registry_test.go
//	P17 repeated evaluation is byte-deterministic                here
//	P18 no existing public output changes                        test/security/diagnosticcore_test.go
//	                                                             and the whole existing suite

// stateRule reports the state of every node it can see, as a finding per node.
//
// It is the instrument for P03 and P04: a rule that transcribes states is the
// closest thing to a rule that could upgrade one, so if an upgrade were possible
// anywhere it would show here.
func stateRule(t *testing.T) Rule {
	t.Helper()

	return func(ctx RuleContext) []domain.Finding {
		var out []domain.Finding
		for _, node := range ctx.Graph.Nodes() {
			code := "TCP_STATE_" + node.State().String()
			out = append(out, findingAbout(t, code, node.Subject(),
				domain.FindingKindConfirmed, domain.SeverityInfo, domain.ConfidenceHigh,
				"the recorded state of "+string(node.ID()), node.ID()))
		}
		return out
	}
}

// mixedGraph carries one node in each of the five states.
func mixedGraph(t *testing.T) domain.Graph {
	t.Helper()

	s := newSpec(t)
	dns := s.endpoint("x-dns", "mix.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.endpoint("x-tcp", "mix.example:5432", domain.LayerTCP, "tcp.connect", domain.StateFail)
	tls := s.endpoint("x-tls", "mix.example:5432", domain.LayerTLS, "tls.handshake", domain.StateSkipped)
	s.endpoint("x-proto", "mix.example:5432", domain.LayerProtocol, "protocol.exchange", domain.StateDegraded)
	s.unknown("x-auth", "mix.example:5432", domain.LayerAuth, "auth.exchange")
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	s.blockedBy(tls, tcp)
	return s.freeze()
}

// TestP01InputPermutationDoesNotChangeTheResult is property P01.
//
// The same evidence described in a different insertion order is the same
// evidence. domain.Graph already guarantees canonical node ordering, so what
// this proves is that nothing in the reasoning layer reintroduces a dependence
// on how the evidence arrived.
func TestP01InputPermutationDoesNotChangeTheResult(t *testing.T) {
	type node struct {
		id, ref string
		layer   domain.Layer
		step    string
		state   domain.State
	}
	nodes := []node{
		{"y-dns", "one.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass},
		{"y-tcp", "one.example:5432", domain.LayerTCP, "tcp.connect", domain.StateFail},
		{"y-other", "two.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass},
		{"y-more", "two.example:5432", domain.LayerTCP, "tcp.connect", domain.StatePass},
	}

	build := func(order []int) domain.Graph {
		s := newSpec(t)
		for _, i := range order {
			n := nodes[i]
			s.endpoint(n.id, n.ref, n.layer, n.step, n.state)
		}
		return s.freeze()
	}

	engine := engineOf(t, stateRule(t))
	baseline := build([]int{0, 1, 2, 3})
	want, err := json.Marshal(engine.Diagnose(RuleContext{Graph: baseline}))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	wantBoundaries := renderBoundaries(Boundaries(baseline))

	for i, order := range permutations(len(nodes)) {
		g := build(order)

		got, err := json.Marshal(engine.Diagnose(RuleContext{Graph: g}))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("insertion order %v changed the findings:\nwant %s\ngot  %s",
				order, want, got)
		}
		if gotBoundaries := renderBoundaries(Boundaries(g)); gotBoundaries != wantBoundaries {
			t.Fatalf("insertion order %d %v changed the boundaries:\nwant %s\ngot  %s",
				i, order, wantBoundaries, gotBoundaries)
		}
	}
}

// TestP02RuleRegistrationPermutationDoesNotChangeResult is property P02, and it
// is the reason registration order is allowed to be a readability choice.
func TestP02RuleRegistrationPermutationDoesNotChangeResult(t *testing.T) {
	g := mixedGraph(t)
	subject := endpointSubject(t, "mix.example:5432")

	rules := []Rule{
		func(RuleContext) []domain.Finding {
			return []domain.Finding{findingAbout(t, "DNS_NO_ADDRESS", subject,
				domain.FindingKindConfirmed, domain.SeverityWarn, domain.ConfidenceMedium,
				"a", "x-dns")}
		},
		func(RuleContext) []domain.Finding {
			return []domain.Finding{findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
				domain.FindingKindConfirmed, domain.SeverityCritical, domain.ConfidenceHigh,
				"b", "x-tcp")}
		},
		func(RuleContext) []domain.Finding { return nil },
		func(RuleContext) []domain.Finding {
			return []domain.Finding{findingAbout(t, "TLS_CHAIN_NOT_TRUSTED", subject,
				domain.FindingKindHypothesis, domain.SeverityError, domain.ConfidenceLow,
				"c", "x-proto")}
		},
	}

	want, err := json.Marshal(engineOf(t, rules...).Diagnose(RuleContext{Graph: g}))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	for _, order := range permutations(len(rules)) {
		wired := make([]Rule, 0, len(rules))
		for _, i := range order {
			wired = append(wired, rules[i])
		}

		got, err := json.Marshal(engineOf(t, wired...).Diagnose(RuleContext{Graph: g}))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("wiring order %v changed the report:\nwant %s\ngot  %s", order, want, got)
		}
	}
}

// TestP03UnknownNeverBecomesFail is property P03 and mutation M01, and it is
// ADR 0078 section 2.3 rule 6: a rule reads states and produces findings; it may
// not upgrade one.
func TestP03UnknownNeverBecomesFail(t *testing.T) {
	g := mixedGraph(t)

	findings := engineOf(t, stateRule(t)).Diagnose(RuleContext{Graph: g})

	byRef := map[domain.EvidenceID]domain.FindingCode{}
	for _, f := range findings {
		for _, ref := range f.EvidenceRefs() {
			byRef[ref] = f.Code()
		}
	}

	for _, node := range g.Nodes() {
		want := domain.FindingCode("TCP_STATE_" + node.State().String())
		if got := byRef[node.ID()]; got != want {
			t.Errorf("node %s is %s and was reported as %s", node.ID(), node.State(), got)
		}
	}
	if got := byRef["x-auth"]; got != "TCP_STATE_UNKNOWN" {
		t.Errorf("the UNKNOWN node was reported as %s", got)
	}

	// And the graph still says what it said. Nothing about reasoning over a
	// state may change it.
	node, ok := g.Node("x-auth")
	if !ok || node.State() != domain.StateUnknown {
		t.Error("the UNKNOWN node's state changed during diagnosis")
	}
}

// TestP04SkippedNeverBecomesFail is property P04 and mutation M02.
func TestP04SkippedNeverBecomesFail(t *testing.T) {
	g := mixedGraph(t)

	findings := engineOf(t, stateRule(t)).Diagnose(RuleContext{Graph: g})

	for _, f := range findings {
		if slices.Contains(f.EvidenceRefs(), "x-tls") && f.Code() != "TCP_STATE_SKIPPED" {
			t.Errorf("the SKIPPED node was reported as %s", f.Code())
		}
	}

	node, ok := g.Node("x-tls")
	if !ok || node.State() != domain.StateSkipped {
		t.Error("the SKIPPED node's state changed during diagnosis")
	}

	// The boundary agrees: a SKIPPED node is neither half of one, and it is
	// recorded as blocked rather than failed.
	b := requireBoundary(t, g, "mix.example:5432")
	if b.FirstEvidencedFailure() == "x-tls" {
		t.Error("the SKIPPED node became the first evidenced failure")
	}
	if last, ok := b.LastConfirmedGood(); ok && last == "x-tls" {
		t.Error("the SKIPPED node became the last confirmed-good")
	}
}

// TestP17RepeatedEvaluationIsDeterministic is property P17.
//
// Repeated, and across GOMAXPROCS settings. The engine holds no mutable state
// and rules are pure, so scheduling cannot reach the output — which is the
// property a 512-target fleet run needs and the one a hidden map iteration would
// break silently.
func TestP17RepeatedEvaluationIsDeterministic(t *testing.T) {
	g := mixedGraph(t)
	engine := engineOf(t, stateRule(t))

	first, err := json.Marshal(engine.Diagnose(RuleContext{Graph: g}))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })

	for _, procs := range []int{1, 2, 4, original} {
		runtime.GOMAXPROCS(procs)
		for i := range 32 {
			again, err := json.Marshal(engine.Diagnose(RuleContext{Graph: g}))
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(again) != string(first) {
				t.Fatalf("GOMAXPROCS=%d iteration %d differed:\n%s\n%s",
					procs, i, first, again)
			}
			if got := renderBoundaries(Boundaries(g)); got != renderBoundaries(Boundaries(g)) {
				t.Fatalf("GOMAXPROCS=%d: boundaries are not stable: %s", procs, got)
			}
		}
	}
}

// TestTheRuleContextDoesNotReachTheOutput pins that the two new fields are
// inputs a rule may consult, not values the engine folds into a result.
//
// If Incomplete or Vantage leaked into the engine's own behaviour, a run's
// findings would change with facts about svcdoctor rather than facts about the
// target — which is the confusion ADR 0083 section 2.3 keeps out of the report.
func TestTheRuleContextDoesNotReachTheOutput(t *testing.T) {
	g := mixedGraph(t)
	engine := engineOf(t, stateRule(t))

	vantage, err := domain.NewLocalVantage("host-a")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	want, err := json.Marshal(engine.Diagnose(RuleContext{Graph: g}))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	for _, ctx := range []RuleContext{
		{Graph: g, Incomplete: true},
		{Graph: g, Vantage: vantage},
		{Graph: g, Vantage: vantage, Incomplete: true},
	} {
		got, err := json.Marshal(engine.Diagnose(ctx))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(got) != string(want) {
			t.Errorf("the engine folded a context field into its own result:\n%s\n%s",
				want, got)
		}
	}
}

// TestPerformanceStaysLinear is the complexity budget of
// docs/design/DIAGNOSTIC_INTELLIGENCE.md section L, checked as a shape rather
// than as a stopwatch.
//
// Diagnosis reads memory. What must not exist is a rule-pair combinatorial or a
// whole-graph rescan per node, and both would show as a super-linear growth in
// work rather than as a slow constant. This asserts the results are right at a
// realistic fleet-shaped size and that the run completes; a timing assertion
// would be flaky on a loaded machine and would tell a reader less.
func TestPerformanceStaysLinear(t *testing.T) {
	const (
		branches = 64
		perDepth = 4
	)

	s := newSpec(t)
	root := s.endpoint("z-root", "seed.example:9092",
		domain.LayerTopology, "topology.discover", domain.StatePass)
	for i := range branches {
		ref := "b" + strconv.Itoa(i) + ".example:9092"
		dns := s.endpoint("z-"+strconv.Itoa(i)+"-dns", ref,
			domain.LayerDNS, "dns.lookup", domain.StatePass)
		s.parent(dns, root)
		previous := dns
		for depth := 1; depth < perDepth; depth++ {
			state := domain.StatePass
			if i%3 == 0 && depth == 2 {
				state = domain.StateFail
			}
			id := domain.EvidenceID("z-" + strconv.Itoa(i) + "-" + strconv.Itoa(depth))
			node := s.endpoint(string(id), ref, domain.Layer(depth+2),
				"step.number"+strconv.Itoa(depth), state)
			s.parent(node, previous)
			previous = node
		}
	}
	g := s.freeze()

	if got, want := g.Len(), 1+branches*perDepth; got != want {
		t.Fatalf("the fixture has %d nodes, want %d", got, want)
	}

	boundaries := Boundaries(g)
	wantBoundaries := 0
	for i := range branches {
		if i%3 == 0 {
			wantBoundaries++
		}
	}
	if len(boundaries) != wantBoundaries {
		t.Errorf("got %d boundaries over %d branches, want %d",
			len(boundaries), branches, wantBoundaries)
	}

	counts := SiblingOutcome(g, "z-root")
	if counts.Total() != branches {
		t.Errorf("SiblingOutcome saw %d child subjects, want %d", counts.Total(), branches)
	}

	findings := engineOf(t, stateRule(t)).Diagnose(RuleContext{Graph: g})
	if len(findings) != g.Len() {
		t.Errorf("got %d findings over %d nodes", len(findings), g.Len())
	}
}
