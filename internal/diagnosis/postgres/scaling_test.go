package postgres

import (
	"fmt"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 10.3, section 45: reasoning stays negligible beside the network.
//
// The admission-scope rule is the first PostgreSQL rule that looks at a *set*,
// so it is the first that could plausibly be quadratic. It is not, and the shape
// of the code is why: it makes one pass over `Graph.Nodes()` to classify, and one
// pass over the classified slices to build. **No rule here compares an address
// with another address**, which is the thing that would make it all-pairs.
//
// The counts below are absurd for a real PostgreSQL target — a name resolving to
// 500 addresses is not a deployment anyone has — and that is deliberate: the
// point is to see the curve, not to model a workload.

// TestTheAdmissionScopeScalesLinearly is the assertion, and it is deliberately
// loose.
//
// A benchmark that failed on a shared runner's scheduling noise would be deleted
// within a month. This asserts the property that actually matters — that the
// per-address cost does not grow with the number of addresses — with a factor
// wide enough that only a genuine complexity change trips it.
func TestTheAdmissionScopeScalesLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement")
	}

	perAddress := map[int]time.Duration{}
	for _, n := range []int{1, 3, 10, 50, 100, 500} {
		g := scalingGraph(t, n)
		ctx := diagnosis.RuleContext{Graph: g}

		// Warm, then measure enough iterations that a single scheduling hiccup
		// does not dominate.
		for range 5 {
			runAllRules(ctx)
		}
		const iterations = 20
		start := time.Now()
		for range iterations {
			runAllRules(ctx)
		}
		perAddress[n] = time.Since(start) / (iterations * time.Duration(n))
		t.Logf("%3d addresses: %8s total, %8s per address",
			n, time.Since(start)/iterations, perAddress[n])
	}

	// The property: the per-address cost at 500 is within a wide constant factor
	// of the cost at 10. A quadratic rule would be fifty times worse here, so the
	// factor separates the two without being sensitive to noise.
	const tolerance = 8
	if perAddress[500] > perAddress[10]*tolerance {
		t.Errorf("the per-address cost grew %.1fx between 10 and 500 addresses "+
			"(%s -> %s), which is the shape of an all-pairs comparison",
			float64(perAddress[500])/float64(perAddress[10]),
			perAddress[10], perAddress[500])
	}
}

// BenchmarkPostgresRules records the numbers the validation document quotes.
func BenchmarkPostgresRules(b *testing.B) {
	for _, n := range []int{1, 3, 10, 50, 100, 500} {
		b.Run(fmt.Sprintf("addresses=%d", n), func(b *testing.B) {
			g := scalingGraph(benchT{b}, n)
			ctx := diagnosis.RuleContext{Graph: g}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				runAllRules(ctx)
			}
		})
	}
}

// runAllRules evaluates the production rule set once.
func runAllRules(ctx diagnosis.RuleContext) int {
	n := 0
	for _, rule := range []diagnosis.Rule{
		SSLRequest, TLS, Startup, Authentication, Session, AdmissionScope,
	} {
		n += len(rule(ctx))
	}
	return n
}

// scalingGraph builds one run with n addresses, half of them refused.
//
// Half refused rather than all, so the admission scope takes its contrast branch
// and the per-address rule fires on every second address: a graph that produced
// no findings would measure the classification pass and not the construction.
func scalingGraph(t fataler, n int) domain.Graph {
	b := domain.NewGraphBuilder()
	at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	anchorSubject, err := domain.NewTargetSubject("db.internal:5432")
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}
	anchor, err := domain.NewEvidence(domain.EvidenceInput{
		ID: "scale-target", Subject: anchorSubject, Layer: domain.LayerInput,
		Step: vocabulary.StepTargetRequested, State: domain.StatePass,
		FailureClass: domain.FailureNone, StartedAt: at, Elapsed: domain.Unmeasured(),
	})
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if err := b.AddEvidence(anchor); err != nil {
		t.Fatalf("adding anchor: %v", err)
	}

	for i := range n {
		address := fmt.Sprintf("10.%d.%d.%d:5432", i/65536, (i/256)%256, i%256)
		subject, err := domain.NewEndpointSubject(address)
		if err != nil {
			t.Fatalf("subject %s: %v", address, err)
		}

		state, class := domain.StatePass, domain.FailureNone
		attrs := map[domain.AttributeKey]domain.AttrValue{
			servicepostgres.AttrAuthMethod: domain.StringAttr("sasl"),
		}
		if i%2 == 0 {
			state, class = domain.StateFail, domain.FailureAuthzNotPermitted
			attrs = map[domain.AttributeKey]domain.AttrValue{
				servicepostgres.AttrSQLState:      domain.StringAttr("28000"),
				servicepostgres.AttrErrorIsNative: domain.BoolAttr(true),
			}
		}

		tcp, err := domain.NewEvidence(domain.EvidenceInput{
			ID: domain.EvidenceID(fmt.Sprintf("scale-tcp-%d", i)), Subject: subject,
			Layer: domain.LayerTCP, Step: vocabulary.StepTCPConnect,
			State: domain.StatePass, FailureClass: domain.FailureNone,
			StartedAt: at, Elapsed: domain.Measured(time.Millisecond),
		})
		if err != nil {
			t.Fatalf("tcp %d: %v", i, err)
		}
		startup, err := domain.NewEvidence(domain.EvidenceInput{
			ID: domain.EvidenceID(fmt.Sprintf("scale-startup-%d", i)), Subject: subject,
			Layer: domain.LayerProtocol, Step: servicepostgres.StepStartup,
			State: state, FailureClass: class, Attributes: attrs,
			StartedAt: at, Elapsed: domain.Measured(time.Millisecond),
		})
		if err != nil {
			t.Fatalf("startup %d: %v", i, err)
		}
		for _, pair := range []struct {
			node   domain.Evidence
			parent domain.EvidenceID
		}{{tcp, anchor.ID()}, {startup, tcp.ID()}} {
			if err := b.AddEvidence(pair.node); err != nil {
				t.Fatalf("adding %s: %v", pair.node.ID(), err)
			}
			if err := b.AddParent(pair.node.ID(), pair.parent); err != nil {
				t.Fatalf("parent of %s: %v", pair.node.ID(), err)
			}
		}
	}

	g, err := b.Freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	return g
}

// fataler is the one method scalingGraph needs from *testing.T and *testing.B.
type fataler interface {
	Fatalf(format string, args ...any)
}

// benchT adapts a benchmark to fataler.
type benchT struct{ b *testing.B }

func (t benchT) Fatalf(format string, args ...any) { t.b.Fatalf(format, args...) }
