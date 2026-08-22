package kafka

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The withholding matrix.
//
// Withholding a finding is not withholding information: every node below stays
// in the graph and in the report. What is withheld is a conclusion svcdoctor
// cannot justify.

// TestOneWorkingAddressWithholdsTheFinding is the hard half of ADR 0034
// section 6. A client that selects the working address succeeds, so the claim
// would be false — and no partial-reachability finding is emitted either,
// because its actionability depends on which address a real client picks, which
// svcdoctor does not observe.
func TestOneWorkingAddressWithholdsTheFinding(t *testing.T) {
	tests := []struct {
		name  string
		build func(*builder, domain.EvidenceID)
	}{
		{
			name: "plaintext: one refused, one connected",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
				b.connect(l, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone)
			},
		},
		{
			name: "tls: one handshake rejected, one accepted",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				a := b.connect(l, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
				b.handshake(a, "10.20.0.1", 9093, domain.StateFail, domain.FailureTLSHostnameMismatch)
				c := b.connect(l, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone)
				b.handshake(c, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone)
			},
		},
		{
			name: "dual stack: IPv4 unrouted, IPv6 reaches the terminal layer",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				v4 := b.connect(
					l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPNetworkUnreachable)
				b.skippedHandshake(v4, "10.20.0.1", 9093)
				v6 := b.connect(l, "2001:db8::10", 9093, domain.StatePass, domain.FailureNone)
				b.handshake(v6, "2001:db8::10", 9093, domain.StatePass, domain.FailureNone)
			},
		},
		{
			name: "dual stack: IPv6 unrouted, IPv4 reaches the terminal layer",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.connect(l, "2001:db8::10", 9093, domain.StateFail, domain.FailureTCPNetworkUnreachable)
				b.connect(l, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
			},
		},
		{
			name: "everything passes",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				c := b.connect(l, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
				b.handshake(c, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
			},
		},
		{
			name: "a working address alongside a failure and an unmeasured path",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
				b.connect(l, "10.20.0.2", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
				b.connect(l, "10.20.0.3", 9093, domain.StatePass, domain.FailureNone)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
			tc.build(b, advertisement)
			none(t, AdvertisedEndpointUnreachable(b.freeze()))
		})
	}
}

// TestNothingPositivelyEvidencedWithholdsTheFinding covers ADR 0034 section 7.
// "I could not measure it" and "it is broken" are different claims, and an
// unfinished measurement is a gap in svcdoctor rather than a fault of the
// cluster. The summary already reports unknown and skipped counts.
func TestNothingPositivelyEvidencedWithholdsTheFinding(t *testing.T) {
	tests := []struct {
		name  string
		build func(*builder, domain.EvidenceID)
	}{
		{
			name: "every connection unknown after a local timeout",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.connect(l, "10.20.0.1", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
				b.connect(l, "10.20.0.2", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
			},
		},
		{
			name: "every address skipped for budget",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				first := b.connect(
					l, "10.20.0.1", 9093, domain.StateSkipped, domain.FailureExecCancelled)
				b.skippedHandshake(first, "10.20.0.1", 9093)
				second := b.connect(
					l, "10.20.0.2", 9093, domain.StateSkipped, domain.FailureExecCancelled)
				b.skippedHandshake(second, "10.20.0.2", 9093)
			},
		},
		{
			name: "the lookup itself timed out",
			build: func(b *builder, ad domain.EvidenceID) {
				b.lookup(ad, "broker-2.internal", domain.StateUnknown, domain.FailureExecLocalTimeout)
			},
		},
		{
			name:  "the advertisement was never measured",
			build: func(*builder, domain.EvidenceID) {},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
			tc.build(b, advertisement)
			none(t, AdvertisedEndpointUnreachable(b.freeze()))
		})
	}
}

// TestAnUnusableAdvertisementProducesNoReachabilityFinding covers ADR 0034
// section 14. "The cluster advertises an endpoint no client can act on" is a
// configuration finding and a genuinely useful one; it is not this finding, and
// it is not authorized yet.
func TestAnUnusableAdvertisementProducesNoReachabilityFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	b.unusableAdvertised(exchange, 3)
	none(t, AdvertisedEndpointUnreachable(b.freeze()))
}

// TestAFailedMetadataExchangeWithholdsTheFinding covers the contrast half of the
// claim. Without a successful exchange the finding would be about the network in
// general rather than about the cluster's configuration.
func TestAFailedMetadataExchangeWithholdsTheFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StateFail)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	b.lookup(advertisement, "broker-2.internal", domain.StateFail, domain.FailureDNSNXDomain)
	none(t, AdvertisedEndpointUnreachable(b.freeze()))
}

// TestAnOrphanAdvertisementWithholdsTheFinding covers the same requirement from
// the other side: an advertisement with no exchange above it has no successful
// half to reference, so the finding has nothing to contrast against.
func TestAnOrphanAdvertisementWithholdsTheFinding(t *testing.T) {
	b := newBuilder(t)
	advertisement := b.node(
		"kafka.broker_advertised/orphan", "broker-2.internal:9093",
		domain.LayerTopology, "kafka.broker_advertised", domain.StatePass, domain.FailureNone, "",
		map[domain.AttributeKey]domain.AttrValue{"kafka.broker.node_id": domain.IntAttr(2)})
	b.lookup(advertisement, "broker-2.internal", domain.StateFail, domain.FailureDNSNXDomain)
	none(t, AdvertisedEndpointUnreachable(b.freeze()))
}
