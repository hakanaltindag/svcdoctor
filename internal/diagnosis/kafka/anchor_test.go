package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Anchoring tests: the rule starts at an advertisement and walks down, and never
// starts at a transport node and asks what that node is about.
//
// That direction is the mechanism by which the rule avoids provenance. A rule
// that met a failed lookup and asked "is this endpoint one the user named, or one
// the cluster advertised?" would be reading Origin off graph shape, which
// docs/REPORT_SCHEMA.md forbids and ADR 0034 section 2 re-affirms.

// TestBootstrapTransportFailureIsNotClaimed is the canonical proof.
//
// The run's own bootstrap sweep is in the graph, it failed, and it hangs off
// nothing. The rule must not notice it: it owns advertised-endpoint reachability
// and nothing else, and whether generic transport findings exist at all is a
// question ADR 0034 section 16 leaves to application orchestration, which does
// not exist.
func TestBootstrapTransportFailureIsNotClaimed(t *testing.T) {
	b := newBuilder(t)

	// A bootstrap sweep with no parent, failing at every address.
	bootstrapLookup := b.node(
		"dns.lookup/primary.internal", "primary.internal",
		domain.LayerDNS, "dns.lookup", domain.StatePass, domain.FailureNone, "", nil)
	b.node(
		"tcp.connect/primary.internal/10.0.0.1", "10.0.0.1:9092",
		domain.LayerTCP, "tcp.connect", domain.StateFail, domain.FailureTCPConnectionRefused,
		bootstrapLookup, nil)

	exchange := b.metadata(domain.StatePass)
	reachable(b, exchange, 1, "broker-1.internal:9093", "broker-1.internal", "10.20.0.1")

	none(t, AdvertisedEndpointUnreachable(rctx(b.freeze())))
}

// TestTheSameEndpointAsBootstrapAndAdvertisement is Phase 3.4's important case,
// and the standing proof that provenance cannot be read off the graph.
//
// One endpoint is measured twice in one run under two scopes: once as the run's
// bootstrap target and once as an endpoint the cluster advertised back. Both
// sweeps fail. Exactly one finding is produced, it is anchored at the
// advertisement, and its evidence is the advertisement's own sweep — never the
// unscoped bootstrap nodes, which the rule has no edge to and no business
// claiming.
func TestTheSameEndpointAsBootstrapAndAdvertisement(t *testing.T) {
	b := newBuilder(t)

	// The bootstrap measurement of primary.internal:9092.
	bootstrapLookup := b.node(
		"dns.lookup/primary.internal", "primary.internal",
		domain.LayerDNS, "dns.lookup", domain.StatePass, domain.FailureNone, "", nil)
	bootstrapConnect := b.node(
		"tcp.connect/primary.internal/10.0.0.1", "10.0.0.1:9092",
		domain.LayerTCP, "tcp.connect", domain.StateFail, domain.FailureTCPConnectionRefused,
		bootstrapLookup, nil)

	// The cluster answered Metadata and advertised the very same endpoint.
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 1, "primary.internal:9092")
	scopedLookup := b.lookup(advertisement, "primary.internal", domain.StatePass, domain.FailureNone)
	scopedConnect := b.connect(
		scopedLookup, "10.0.0.1", 9092, domain.StateFail, domain.FailureTCPConnectionRefused)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(rctx(graph)))
	confirmed(t, f)
	wantRefs(t, f, exchange, advertisement, scopedConnect)

	for _, unscoped := range []domain.EvidenceID{bootstrapLookup, bootstrapConnect} {
		for _, ref := range f.EvidenceRefs() {
			if ref == unscoped {
				t.Errorf("the finding cites the unscoped bootstrap node %s", unscoped)
			}
		}
	}
}

// TestFindingsAreIndependentOfGraphAssemblyOrder pins determinism.
//
// The same set of facts, recorded in a different order, must produce the same
// findings with the same references. The rule walks edges and sorts what it
// reports; it never depends on insertion order, child order or map iteration.
func TestFindingsAreIndependentOfGraphAssemblyOrder(t *testing.T) {
	forward := func(b *builder, exchange domain.EvidenceID) {
		unreachable(b, exchange, 1, "broker-1.internal:9093", "broker-1.internal", "10.20.0.1")
		unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
	}
	reverse := func(b *builder, exchange domain.EvidenceID) {
		unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
		unreachable(b, exchange, 1, "broker-1.internal:9093", "broker-1.internal", "10.20.0.1")
	}

	render := func(t *testing.T, add func(*builder, domain.EvidenceID)) []string {
		t.Helper()
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		add(b, exchange)

		findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
		domain.SortFindings(findings)

		out := make([]string, 0, len(findings))
		for _, f := range findings {
			refs := make([]string, 0, len(f.EvidenceRefs()))
			for _, r := range f.EvidenceRefs() {
				refs = append(refs, string(r))
			}
			out = append(out, f.Summary()+" | "+strings.Join(refs, ","))
		}
		return out
	}

	first := render(t, forward)
	second := render(t, reverse)

	if len(first) != 2 {
		t.Fatalf("findings = %d, want 2", len(first))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("finding %d differs with assembly order:\n %s\n %s", i, first[i], second[i])
		}
	}
}

// TestMultipleRunsOfOneGraphAreIdentical is the cheap half of determinism: map
// iteration inside the rule would show up here.
func TestMultipleRunsOfOneGraphAreIdentical(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	ad := b.advertised(exchange, 2, "broker-2.internal:9093")
	l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
	for _, addr := range []string{"10.20.0.1", "10.20.0.2", "10.20.0.3", "2001:db8::10"} {
		b.connect(l, addr, 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	}
	graph := b.freeze()

	want := only(t, AdvertisedEndpointUnreachable(rctx(graph)))
	for i := 0; i < 50; i++ {
		got := only(t, AdvertisedEndpointUnreachable(rctx(graph)))
		if got.Summary() != want.Summary() {
			t.Fatalf("summary drifted on run %d: %q vs %q", i, got.Summary(), want.Summary())
		}
		if !slicesEqual(got.EvidenceRefs(), want.EvidenceRefs()) {
			t.Fatalf("references drifted on run %d", i)
		}
	}
}
