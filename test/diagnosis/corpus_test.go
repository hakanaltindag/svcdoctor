package diagnosis_test

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The golden incident corpus, started in Phase 10.1B.
//
// ADR 0083 section 2.5 specifies the shape and section 2.4 makes it level L6 of
// the validation pyramid. It is started here rather than waiting for Phase 10.6
// so that the *format* is fixed while the corpus is small enough to change: the
// service phases will each add rows, and a format argued about later is a format
// every existing row has to be rewritten for.
//
// Each fixture carries four parts, and the fourth is the one that matters:
//
//	intent      what the run was configured to do
//	evidence    the frozen graph, built here rather than captured
//	expected    the claims that must appear
//	forbidden   the claims that must not
//
// **`forbidden` is a first-class expectation, not a comment.** It is the
// mechanism that stops diagnostic language from drifting into overconfidence one
// helpful sentence at a time, and a corpus whose forbidden lists are empty
// proves nothing — which TestTheCorpusForbidsSomethingEverywhere enforces.
//
// # Why the fixtures are built and not captured
//
// ADR 0083 section 5: a graph captured from a real environment would put a real
// hostname in the repository, which docs/SECURITY.md and the redaction contract
// exist to prevent. Every subject here is a documentation-reserved name.

// incident is one corpus fixture.
type incident struct {
	// name is the scenario, in the operator's terms.
	name string

	// intent is what the run was asked to do. It is prose today because no
	// declared-expectation model exists: ADR 0083 section 2.6 keeps `expect:`
	// out of configuration, so intent is context for a reader rather than an
	// input to a rule.
	intent string

	// build produces the frozen evidence.
	build func(t *testing.T) domain.Graph

	// incomplete is whether svcdoctor's own budget cut the run short.
	incomplete bool

	// expectBoundaries maps a subject reference to the layer its boundary must
	// be filed at. A subject absent from this map must have no boundary.
	expectBoundaries map[string]domain.Layer

	// expectNoBoundaryFor names subjects that must be left alone, so that "no
	// boundary" is asserted rather than merely unlisted.
	expectNoBoundaryFor []string

	// forbidden is what this scenario must never say, in any output surface.
	forbidden []forbiddenClaim
}

// corpus is the whole set. It is deliberately short.
func corpus() []incident {
	return []incident{
		{
			name:   "a name that does not resolve",
			intent: "reach a PostgreSQL endpoint by hostname over verified TLS",
			build: func(t *testing.T) domain.Graph {
				s := newGraph(t)
				dns := s.nodeWithClass("c1-dns", "db.example:5432", domain.LayerDNS,
					string(vocabulary.StepDNSLookup), domain.StateFail, domain.FailureDNSNoAddress)
				tcp := s.node("c1-tcp", "db.example:5432", domain.LayerTCP,
					string(vocabulary.StepTCPConnect), domain.StateSkipped)
				s.parent(tcp, dns)
				s.blocked(tcp, dns)
				return s.freeze()
			},
			expectBoundaries: map[string]domain.Layer{"db.example:5432": domain.LayerDNS},
			forbidden: []forbiddenClaim{
				{"does not exist", "a negative answer and a name with no address record look the same"},
				{"nxdomain", "the resolver did not distinguish it"},
				{"typo", "nothing observed how the name was produced"},
				{"dns is down", "one negative answer is not a resolver outage"},
				{"the connection failed", "the connection was never attempted"},
				{"could not connect", "the same"},
			},
		},
		{
			name:   "one discovered endpoint of three is unreachable",
			intent: "reach a cluster and verify every endpoint it advertises",
			build: func(t *testing.T) domain.Graph {
				s := newGraph(t)
				seed := s.node("c2-seed", "seed.example:9092", domain.LayerTopology,
					"topology.discover", domain.StatePass)
				for _, addr := range []string{"b1.example:9092", "b2.example:9092"} {
					ok := s.node("c2-"+addr, addr, domain.LayerTCP,
						string(vocabulary.StepTCPConnect), domain.StatePass)
					s.parent(ok, seed)
				}
				bad := s.nodeWithClass("c2-b3.example:9092", "b3.example:9092", domain.LayerTCP,
					string(vocabulary.StepTCPConnect), domain.StateFail,
					domain.FailureTCPConnectionRefused)
				s.parent(bad, seed)
				return s.freeze()
			},
			expectBoundaries:    map[string]domain.Layer{"b3.example:9092": domain.LayerTCP},
			expectNoBoundaryFor: []string{"b1.example:9092", "b2.example:9092", "seed.example:9092"},
			forbidden: []forbiddenClaim{
				{"the cluster is", "cluster health was not measured and is not a thing svcdoctor observes"},
				{"degraded", "a cluster-health verdict from one endpoint's transport result"},
				{"the broker is down", "a refusal distinguishes neither a host nor a process"},
				{"quorum", "nothing about cluster membership was observed"},
				{"failover", "no remediation follows from one unreachable endpoint"},
			},
		},
		{
			name:   "the budget expired mid-run",
			intent: "reach every resolved address of a multi-homed endpoint",
			build: func(t *testing.T) domain.Graph {
				s := newGraph(t)
				anchor := s.node("c3-target", "db.example:5432", domain.LayerInput,
					string(vocabulary.StepTargetRequested), domain.StatePass)
				dns := s.node("c3-dns", "db.example:5432", domain.LayerDNS,
					string(vocabulary.StepDNSLookup), domain.StatePass)
				s.parent(dns, anchor)

				measured := s.nodeWithClass("c3-one", "10.0.0.1:5432", domain.LayerTCP,
					string(vocabulary.StepTCPConnect), domain.StateFail,
					domain.FailureTCPConnectionRefused)
				s.parent(measured, dns)

				never := s.node("c3-two", "10.0.0.2:5432", domain.LayerTCP,
					string(vocabulary.StepTCPConnect), domain.StateUnknown)
				s.parent(never, dns)
				return s.freeze()
			},
			incomplete:          true,
			expectBoundaries:    map[string]domain.Layer{"10.0.0.1:5432": domain.LayerTCP},
			expectNoBoundaryFor: []string{"10.0.0.2:5432", "db.example:5432"},
			forbidden: []forbiddenClaim{
				{"all addresses", "one of the two was never attempted"},
				{"every address", "the same"},
				{"addresses are unreachable", "an unmeasured address is not an unreachable one"},
				{"only 10.0.0.1", "a claim about the one nobody measured"},
				{"was not reached", "\"not measured\" and \"not reached\" are two claims (ADR 0052)"},
			},
		},
	}
}

// TestTheGoldenIncidentCorpus runs every fixture through the production pipeline.
func TestTheGoldenIncidentCorpus(t *testing.T) {
	for _, fixture := range corpus() {
		t.Run(fixture.name, func(t *testing.T) {
			t.Logf("intent: %s", fixture.intent)

			r := diagnose(t, fixture.build(t), fixture.incomplete, transportAndBoundary()...)
			got := r.boundaries(t)

			for subject, wantLayer := range fixture.expectBoundaries {
				b, present := got[subject]
				if !present {
					t.Errorf("no boundary for %s, want one at %s", subject, wantLayer)
					continue
				}
				if b.Layer() != wantLayer {
					t.Errorf("the %s boundary is at %s, want %s", subject, b.Layer(), wantLayer)
				}
				if b.Kind() != domain.FindingKindConfirmed {
					t.Errorf("the %s boundary is %s, want CONFIRMED", subject, b.Kind())
				}
				if b.Severity() != domain.SeverityInfo {
					t.Errorf("the %s boundary is %s, want INFO", subject, b.Severity())
				}
				if b.Discriminator() != "" {
					t.Errorf("the %s boundary carries a discriminator %q; it settles nothing",
						subject, b.Discriminator())
				}
				if len(b.Recommendations()) != 0 {
					t.Errorf("the %s boundary carries a recommendation; a boundary states "+
						"where observation stopped and advises nothing", subject)
				}
				for _, ref := range b.EvidenceRefs() {
					if _, ok := r.graph.Node(ref); !ok {
						t.Errorf("the %s boundary cites %q, which is not in the graph",
							subject, ref)
					}
				}
			}

			for _, subject := range fixture.expectNoBoundaryFor {
				if _, present := got[subject]; present {
					t.Errorf("%s got a boundary and must not have one", subject)
				}
			}

			assertRefuses(t, r, fixture.forbidden)
		})
	}
}

// TestTheCorpusForbidsSomethingEverywhere is ADR 0083 section 7's guard.
//
// A fixture with an empty forbidden list is a fixture that asserts only what
// svcdoctor *did* say, and the thing that decays is what it must never say.
func TestTheCorpusForbidsSomethingEverywhere(t *testing.T) {
	all := corpus()
	if len(all) == 0 {
		t.Fatal("the corpus is empty")
	}
	for _, fixture := range all {
		if len(fixture.forbidden) == 0 {
			t.Errorf("the %q fixture forbids nothing, so it proves nothing about "+
				"overclaiming (ADR 0083 section 2.5)", fixture.name)
		}
		if fixture.intent == "" {
			t.Errorf("the %q fixture declares no intent", fixture.name)
		}
		for _, claim := range fixture.forbidden {
			if claim.why == "" {
				t.Errorf("the %q fixture forbids %q without saying why",
					fixture.name, claim.phrase)
			}
		}
	}
}

// TestTheCorpusFixturesCarryNoRealIdentity is ADR 0083 section 5.
//
// A captured graph would put a real hostname in the repository. Every subject
// here must be a documentation-reserved name or a private-range address.
func TestTheCorpusFixturesCarryNoRealIdentity(t *testing.T) {
	for _, fixture := range corpus() {
		t.Run(fixture.name, func(t *testing.T) {
			g := fixture.build(t)
			if g.Len() == 0 {
				t.Fatal("the fixture built no evidence")
			}
			for _, node := range g.Nodes() {
				ref := node.Subject().Ref()
				host, _, found := strings.Cut(ref, ":")
				if !found {
					host = ref
				}
				switch {
				case strings.HasSuffix(host, ".example"), host == "example":
					// A documentation-reserved name.
				case strings.HasPrefix(host, "10."), strings.HasPrefix(host, "192.168."),
					strings.HasPrefix(host, "127."):
					// A private or loopback address.
				default:
					t.Errorf("subject %q is neither documentation-reserved nor private; a "+
						"corpus fixture must be synthetic (ADR 0083 section 5)", ref)
				}
			}
		})
	}
}

// TestTheCorpusUsesTheProductionRuleSet keeps the fixtures honest about what
// they exercise.
//
// A corpus that quietly ran a convenient subset of the rules would be measuring
// the fixtures rather than the product.
func TestTheCorpusUsesTheProductionRuleSet(t *testing.T) {
	wired := map[string]bool{"diag/failure-boundary": true}
	for _, r := range transportAndBoundary() {
		wired[r.id] = true
	}

	for _, want := range []string{
		"diag/failure-boundary", "transport/dns", "transport/tcp", "transport/tls",
	} {
		if !wired[want] {
			t.Errorf("the corpus does not wire %q, which every composition root does", want)
		}
	}

	// And the boundary rule really is the one internal/app wires, not a copy.
	var _ diagnosis.Rule = diagnosis.FailureBoundary
}
