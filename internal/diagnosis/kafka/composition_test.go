package kafka

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Composition: both Kafka rules wired into one engine, which is how a real run
// will use them.
//
// The property under test is that they partition the advertisements rather than
// overlapping. It is structural rather than coordinated — neither rule knows the
// other exists, and neither suppresses anything. Phase 3.3 records an
// advertisement PASS exactly when it names a usable endpoint and FAIL exactly
// when it does not; AdvertisedEndpointUnreachable requires PASS and
// UnusableAdvertisement requires FAIL, so the two predicates are complementary
// on a single field.
//
// That is worth a test rather than a comment: if either rule ever relaxed its
// state check, one advertisement would produce two findings that contradict each
// other — "no path reached it" and "there was nothing to reach".

func bothRules() diagnosis.Engine {
	return testEngine(AdvertisedEndpointUnreachable, UnusableAdvertisement)
}

// codesOf returns the code and subject of each finding, for comparison.
type produced struct {
	code    domain.FindingCode
	subject string
}

func run(t *testing.T, b *builder) []produced {
	t.Helper()
	out := []produced{}
	for _, f := range bothRules().Diagnose(rctx(b.freeze())) {
		out = append(out, produced{f.Code(), f.Subject().Ref()})
	}
	return out
}

func TestTheTwoRulesNeverBothFireForOneAdvertisement(t *testing.T) {
	tests := []struct {
		name  string
		build func(*builder, domain.EvidenceID)
		want  []produced
	}{
		{
			name: "usable but unreachable: only the reachability finding",
			build: func(b *builder, exchange domain.EvidenceID) {
				unreachable(b, exchange, 2, "broker-2.internal:9092", "broker-2.internal", "10.20.0.2")
			},
			want: []produced{
				{CodeAdvertisedEndpointUnreachable, "broker-2.internal:9092"},
			},
		},
		{
			name: "unusable: only the usability finding",
			build: func(b *builder, exchange domain.EvidenceID) {
				b.unusable(exchange, 2, ":9093", "", 9093)
			},
			want: []produced{
				{CodeAdvertisedEndpointUnusable, ":9093"},
			},
		},
		{
			name: "usable and reachable: neither",
			build: func(b *builder, exchange domain.EvidenceID) {
				reachable(b, exchange, 2, "broker-2.internal:9092", "broker-2.internal", "10.20.0.2")
			},
			want: []produced{},
		},
		{
			name: "one of each, on different brokers",
			build: func(b *builder, exchange domain.EvidenceID) {
				b.unusable(exchange, 2, ":9093", "", 9093)
				unreachable(b, exchange, 3, "broker-3.internal:9092", "broker-3.internal", "10.20.0.3")
			},
			want: []produced{
				{CodeAdvertisedEndpointUnreachable, "broker-3.internal:9092"},
				{CodeAdvertisedEndpointUnusable, ":9093"},
			},
		},
		{
			name: "several unusable advertisements",
			build: func(b *builder, exchange domain.EvidenceID) {
				b.unusable(exchange, 1, ":9093", "", 9093)
				b.unusable(exchange, 2, "broker-2.internal:0", "broker-2.internal", 0)
				b.unusable(exchange, 3, "broker-3.internal:70000", "broker-3.internal", 70000)
			},
			want: []produced{
				{CodeAdvertisedEndpointUnusable, ":9093"},
				{CodeAdvertisedEndpointUnusable, "broker-2.internal:0"},
				{CodeAdvertisedEndpointUnusable, "broker-3.internal:70000"},
			},
		},
		{
			name: "a full cluster: reachable, unreachable, incomplete and unusable",
			build: func(b *builder, exchange domain.EvidenceID) {
				reachable(b, exchange, 1, "broker-1.internal:9092", "broker-1.internal", "10.20.0.1")
				unreachable(b, exchange, 2, "broker-2.internal:9092", "broker-2.internal", "10.20.0.2")
				mixed := b.advertised(exchange, 3, "broker-3.internal:9092")
				lookup := b.lookup(mixed, "broker-3.internal", domain.StatePass, domain.FailureNone)
				b.connect(lookup, "10.20.0.31", 9092, domain.StateFail, domain.FailureTCPConnectionRefused)
				b.connect(lookup, "10.20.0.32", 9092, domain.StateUnknown, domain.FailureExecLocalTimeout)
				b.unusable(exchange, 4, "broker-4.internal:0", "broker-4.internal", 0)
			},
			want: []produced{
				{CodeAdvertisedEndpointUnreachable, "broker-2.internal:9092"},
				{CodeAdvertisedEndpointUnreachable, "broker-3.internal:9092"},
				{CodeAdvertisedEndpointUnusable, "broker-4.internal:0"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			tc.build(b, exchange)

			got := run(t, b)
			if len(got) != len(tc.want) {
				t.Fatalf("findings = %v, want %v", got, tc.want)
			}
			seen := map[produced]int{}
			for _, p := range got {
				seen[p]++
			}
			for _, p := range tc.want {
				if seen[p] == 0 {
					t.Errorf("missing finding %v; got %v", p, got)
				}
				seen[p]--
			}
			for p, n := range seen {
				if n > 0 {
					t.Errorf("unexpected finding %v (%d extra)", p, n)
				}
			}
		})
	}
}

// TestNoSubjectCarriesTwoKafkaFindings is the invariant stated directly: across
// the whole matrix, no advertisement subject ever attracts both codes.
func TestNoSubjectCarriesTwoKafkaFindings(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	reachable(b, exchange, 1, "broker-1.internal:9092", "broker-1.internal", "10.20.0.1")
	unreachable(b, exchange, 2, "broker-2.internal:9092", "broker-2.internal", "10.20.0.2")
	b.unusable(exchange, 3, ":9093", "", 9093)
	b.unusable(exchange, 4, "broker-4.internal:-1", "broker-4.internal", -1)

	bySubject := map[string]map[domain.FindingCode]bool{}
	for _, f := range bothRules().Diagnose(rctx(b.freeze())) {
		if bySubject[f.Subject().Ref()] == nil {
			bySubject[f.Subject().Ref()] = map[domain.FindingCode]bool{}
		}
		bySubject[f.Subject().Ref()][f.Code()] = true
	}
	for subject, codes := range bySubject {
		if len(codes) > 1 {
			t.Errorf("subject %q carries %d Kafka findings; the two claims are "+
				"mutually exclusive", subject, len(codes))
		}
	}
	if len(bySubject) != 3 {
		t.Errorf("subjects with findings = %d, want 3", len(bySubject))
	}
}

// TestTheEngineNeedsNoSuppression states the ownership property: the rules
// partition their input structurally, so no engine-level deduplication exists
// and none is needed.
func TestTheEngineNeedsNoSuppression(t *testing.T) {
	engine := bothRules()
	if engine.RuleCount() != 2 {
		t.Fatalf("rule count = %d, want 2", engine.RuleCount())
	}

	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	b.unusable(exchange, 2, ":9093", "", 9093)
	graph := b.freeze()

	// Each rule alone produces exactly what the pair produces together: nothing
	// is added, removed or altered by composition.
	unreachableAlone := AdvertisedEndpointUnreachable(rctx(graph))
	unusableAlone := UnusableAdvertisement(rctx(graph))
	together := engine.Diagnose(rctx(graph))

	if len(unreachableAlone) != 0 {
		t.Errorf("the reachability rule fired on an unusable advertisement: %d", len(unreachableAlone))
	}
	if len(unusableAlone) != 1 {
		t.Fatalf("the usability rule produced %d findings, want 1", len(unusableAlone))
	}
	if len(together) != len(unreachableAlone)+len(unusableAlone) {
		t.Errorf("composition changed the result: %d together, %d + %d apart",
			len(together), len(unreachableAlone), len(unusableAlone))
	}
}

// TestAnUnusableAdvertisementWithATransportSweepStillYieldsOneFinding is the
// case that actually pins the exclusivity, and it exists because a mutation run
// showed the other composition tests do not.
//
// In every graph a real run produces, an unusable advertisement has no sweep
// beneath it — Phase 3.4 skips it (ADR 0033) — so the reachability rule stays
// silent for two independent reasons at once: the advertisement is not PASS, and
// there are no measured paths to own a failure. That coincidence hides which
// mechanism is doing the work, and a mutation that removed the state check
// changed no test result.
//
// This graph separates them. It is contract drift rather than something a
// producer creates: an advertisement svcdoctor could not turn into a target,
// with transport evidence beneath it anyway. Only the state check keeps the two
// claims apart here, and without it one advertisement would carry both "there
// was nothing to reach" and "no path reached it" — findings that contradict each
// other in the same report.
func TestAnUnusableAdvertisementWithATransportSweepStillYieldsOneFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.unusable(exchange, 2, ":9093", "", 9093)
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)
	b.connect(lookup, "10.20.0.2", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	graph := b.freeze()

	findings := bothRules().Diagnose(rctx(graph))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1: %v", len(findings), summaries(findings))
	}
	if got := findings[0].Code(); got != CodeAdvertisedEndpointUnusable {
		t.Errorf("code = %s, want %s", got, CodeAdvertisedEndpointUnusable)
	}
	if got := len(AdvertisedEndpointUnreachable(rctx(graph))); got != 0 {
		t.Errorf("the reachability rule produced %d findings for an advertisement that "+
			"never named a usable endpoint", got)
	}
}
