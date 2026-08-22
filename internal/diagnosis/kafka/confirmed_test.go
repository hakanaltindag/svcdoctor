package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The CONFIRMED matrix: every sweep shape in which ADR 0034 section 5 authorizes
// the claim that no advertised path reaches the endpoint.
//
// Each case pins the finding's fields and its exact evidence references, because
// the references are the part of the policy a plausible refactor breaks first.

// TestDNSNoAddressIsConfirmed covers a lookup that answered with nothing usable.
// The terminal layer is irrelevant: nothing was reachable at L1 and the verdict
// is the same whichever layer would have been terminal.
func TestDNSNoAddressIsConfirmed(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StateFail, domain.FailureDNSNoAddress)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(graph))
	confirmed(t, f)
	wantRefs(t, f, exchange, advertisement, lookup)
	assertRefsAreClean(t, graph, f, exchange, advertisement)

	if !strings.Contains(f.Summary(), "L1 DNS_NO_ADDRESS") {
		t.Errorf("summary does not name the earliest evidenced failure: %q", f.Summary())
	}
}

// TestDNSResolverFailureIsConfirmed is the other lookup failure shape. It is a
// separate case because the class differs and the class reaches the summary.
func TestDNSResolverFailureIsConfirmed(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(
		advertisement, "broker-2.internal", domain.StateFail, domain.FailureDNSResolverFailure)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(graph))
	confirmed(t, f)
	wantRefs(t, f, exchange, advertisement, lookup)

	if !strings.Contains(f.Summary(), "L1 DNS_RESOLVER_FAILURE") {
		t.Errorf("summary = %q", f.Summary())
	}
}

// TestPlaintextSingleRefusedConnectionIsConfirmed is the smallest transport
// case: one address, refused, and TCP is the terminal layer because no TLS node
// exists anywhere in the sweep.
func TestPlaintextSingleRefusedConnectionIsConfirmed(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)
	refused := b.connect(lookup, "10.20.0.2", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(graph))
	confirmed(t, f)
	wantRefs(t, f, exchange, advertisement, refused)
	assertRefsAreClean(t, graph, f, exchange, advertisement)

	if !strings.Contains(f.Detail(), "L2") {
		t.Errorf("detail does not name the terminal layer: %q", f.Detail())
	}
}

// TestPlaintextEveryConnectionFailsIsOneFinding proves the per-address facts do
// not become per-address findings.
func TestPlaintextEveryConnectionFailsIsOneFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)
	first := b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	second := b.connect(lookup, "10.20.0.2", 9093, domain.StateFail, domain.FailureTCPConnectionTimeout)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(graph))
	confirmed(t, f)
	wantRefs(t, f, exchange, advertisement, first, second)

	// Both classes are named, sorted, so the text is complete and independent of
	// traversal order.
	if !strings.Contains(f.Summary(), "L2 TCP_CONNECTION_REFUSED, TCP_CONNECTION_TIMEOUT") {
		t.Errorf("summary = %q", f.Summary())
	}
}

// TestTLSPlanWithEveryConnectionFailedCitesTheBlockerNotTheSkip is the case
// ADR 0034 section 9 exists for. The sweep required TLS, so every TCP node has a
// SKIPPED handshake beneath it; the blocker owns the failure and the skip is
// never referenced.
func TestTLSPlanWithEveryConnectionFailedCitesTheBlockerNotTheSkip(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)

	first := b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	firstSkip := b.skippedHandshake(first, "10.20.0.1", 9093)
	second := b.connect(lookup, "10.20.0.2", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	secondSkip := b.skippedHandshake(second, "10.20.0.2", 9093)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(graph))
	confirmed(t, f)

	// Identical to the plaintext row: the references do not depend on the plan.
	wantRefs(t, f, exchange, advertisement, first, second)
	assertRefsAreClean(t, graph, f, exchange, advertisement)

	for _, skip := range []domain.EvidenceID{firstSkip, secondSkip} {
		for _, ref := range f.EvidenceRefs() {
			if ref == skip {
				t.Errorf("prerequisite skip %s is referenced as a cause", skip)
			}
		}
	}
	// The terminal layer is still TLS: the plan is observable from the SKIPPED
	// nodes even though they are not cited.
	if !strings.Contains(f.Detail(), "L3") {
		t.Errorf("detail should name TLS as the terminal layer: %q", f.Detail())
	}
}

// TestTLSPlanWithEveryHandshakeFailedIsConfirmed covers the case where the
// connection succeeded everywhere and the required layer was never reached.
func TestTLSPlanWithEveryHandshakeFailedIsConfirmed(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)

	firstTCP := b.connect(lookup, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
	firstTLS := b.handshake(
		firstTCP, "10.20.0.1", 9093, domain.StateFail, domain.FailureTLSHostnameMismatch)
	secondTCP := b.connect(lookup, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone)
	secondTLS := b.handshake(
		secondTCP, "10.20.0.2", 9093, domain.StateFail, domain.FailureTLSHostnameMismatch)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(graph))
	confirmed(t, f)

	// No TCP PASS node: a failed handshake exists only if the connection was
	// established, so the TCP node proves nothing the TLS node does not.
	wantRefs(t, f, exchange, advertisement, firstTLS, secondTLS)
	assertRefsAreClean(t, graph, f, exchange, advertisement)

	if !strings.Contains(f.Summary(), "L3 TLS_HOSTNAME_MISMATCH") {
		t.Errorf("summary should name the certificate failure, not just unreachability: %q", f.Summary())
	}
}

// TestMixedCausalLayersCitesEachPathsOwnOwner is the shape that killed the
// earlier "nodes that fail at the terminal layer" wording: one path failed at
// L2 and never reached L3 at all, while the other failed at L3.
func TestMixedCausalLayersCitesEachPathsOwnOwner(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)

	refused := b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	b.skippedHandshake(refused, "10.20.0.1", 9093)

	connected := b.connect(lookup, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone)
	rejected := b.handshake(
		connected, "10.20.0.2", 9093, domain.StateFail, domain.FailureTLSUnknownAuthority)
	graph := b.freeze()

	f := only(t, AdvertisedEndpointUnreachable(graph))
	confirmed(t, f)
	wantRefs(t, f, exchange, advertisement, refused, rejected)
	assertRefsAreClean(t, graph, f, exchange, advertisement)

	// The earliest evidenced failing layer across the sweep is L2, and only the
	// classes at that layer are named.
	if !strings.Contains(f.Summary(), "L2 TCP_CONNECTION_REFUSED") {
		t.Errorf("summary = %q", f.Summary())
	}
	if strings.Contains(f.Summary(), "TLS_UNKNOWN_AUTHORITY") {
		t.Errorf("summary names a later layer's class: %q", f.Summary())
	}
}

// TestRecommendationsFollowTheEvidencedLayers pins ADR 0034 section 18: advice is
// tied to the evidenced failure layer and to nothing else.
func TestRecommendationsFollowTheEvidencedLayers(t *testing.T) {
	tests := []struct {
		name  string
		build func(*builder, domain.EvidenceID) // given the advertisement
		want  []string
	}{
		{
			name: "dns",
			build: func(b *builder, ad domain.EvidenceID) {
				b.lookup(ad, "broker-2.internal", domain.StateFail, domain.FailureDNSNXDomain)
			},
			want: []string{recommendDNS},
		},
		{
			name: "tcp",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
			},
			want: []string{recommendTCP},
		},
		{
			name: "tls",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				c := b.connect(l, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
				b.handshake(c, "10.20.0.1", 9093, domain.StateFail, domain.FailureTLSCertificateExpired)
			},
			want: []string{recommendTLS},
		},
		{
			name: "tcp and tls, in layer order",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				r := b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
				b.skippedHandshake(r, "10.20.0.1", 9093)
				c := b.connect(l, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone)
				b.handshake(c, "10.20.0.2", 9093, domain.StateFail, domain.FailureTLSHostnameMismatch)
			},
			want: []string{recommendTCP, recommendTLS},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
			tc.build(b, advertisement)

			f := only(t, AdvertisedEndpointUnreachable(b.freeze()))
			got := make([]string, 0, len(f.Recommendations()))
			for _, r := range f.Recommendations() {
				got = append(got, r.Action())
			}
			if len(got) != len(tc.want) {
				t.Fatalf("recommendations = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("recommendation %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
