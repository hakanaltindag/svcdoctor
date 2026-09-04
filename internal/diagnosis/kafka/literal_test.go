package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 6.7 — an advertised endpoint that named an address.
//
// A Kafka cluster routinely advertises addresses: a broker behind a load
// balancer, a Kubernetes Service, a listener configured with an address rather
// than a name. Its sweep resolves nothing, so it has no L1 node and its
// connection hangs straight off the advertisement (ADR 0059).
//
// The rule must treat it as a first-class advertised endpoint — same
// reachability verdict, same causal owner, same evidence references — and not as
// an unrecognized shape, which would silently drop every literal broker out of
// the topology.

// literalAdvertisement builds an advertisement whose sweep resolved nothing.
func (b *builder) literalConnect(
	advertisement domain.EvidenceID, addr string, port int,
	state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	b.t.Helper()
	return b.node(
		"tcp.connect/"+shortOf(advertisement)+"/"+addr,
		addrPort(addr, port), domain.LayerTCP, "tcp.connect", state, class, advertisement, nil)
}

// addrPort renders an endpoint the way the producers do, bracketing IPv6.
func addrPort(addr string, port int) string {
	host := addr
	if strings.Contains(addr, ":") {
		host = "[" + addr + "]"
	}
	return host + ":" + itoa(port)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

// The core of ADR 0054 for this shape: a reachable FAIL must have an owner.
func TestALiteralAdvertisementIsOwned(t *testing.T) {
	for _, addr := range []string{"10.20.30.41", "2001:db8::42"} {
		t.Run(addr, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			advertisement := b.advertised(exchange, 2, addrPort(addr, 9093))
			b.literalConnect(advertisement, addr, 9093,
				domain.StateFail, domain.FailureTCPConnectionRefused)

			findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
			if len(findings) != 1 {
				t.Fatalf("findings = %d, want 1: a literal advertisement must be owned", len(findings))
			}
			if findings[0].Code() != CodeAdvertisedEndpointUnreachable {
				t.Fatalf("code = %s, want %s", findings[0].Code(), CodeAdvertisedEndpointUnreachable)
			}
			// The finding is a topology claim, so its layer is L6 exactly as a
			// named advertisement's is. The transport layer that failed lives on
			// the cited evidence, which is where a reader looks for it.
			if findings[0].Layer() != domain.LayerTopology {
				t.Fatalf("layer = %s, want L6", findings[0].Layer())
			}
			refs := findings[0].EvidenceRefs()
			if len(refs) == 0 {
				t.Fatal("the finding cites nothing")
			}
		})
	}
}

// The prose must not describe resolution that did not happen. This is the
// advertised counterpart of the requested-target defect.
func TestALiteralAdvertisementClaimsNoResolution(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "10.20.30.41:9093")
	b.literalConnect(advertisement, "10.20.30.41", 9093,
		domain.StateFail, domain.FailureTCPConnectionRefused)

	f := AdvertisedEndpointUnreachable(rctx(b.freeze()))[0]
	text := f.Summary() + "\n" + f.Detail()
	for _, forbidden := range []string{
		"hostname did not resolve",
		"yielded no address",
		"the advertised hostname",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the finding says %q about a sweep that resolved nothing:\n%s", forbidden, text)
		}
	}
}

// A literal advertisement that was reached suppresses the claim, exactly as a
// resolved name does. Counting it as unreachable would be the more damaging
// direction of the same mistake.
func TestAReachedLiteralAdvertisementProducesNoFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "10.20.30.41:9093")
	b.literalConnect(advertisement, "10.20.30.41", 9093, domain.StatePass, domain.FailureNone)

	if findings := AdvertisedEndpointUnreachable(rctx(b.freeze())); len(findings) != 0 {
		t.Fatalf("findings = %v, want none: the endpoint was reached", findings)
	}
}

// TLS over a literal advertisement is still the terminal layer when the plan
// required one, and the handshake is still the causal owner.
func TestALiteralAdvertisementCarriesItsTLSOwner(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "10.20.30.41:9093")
	connection := b.literalConnect(advertisement, "10.20.30.41", 9093,
		domain.StatePass, domain.FailureNone)
	handshake := b.handshake(connection, "10.20.30.41", 9093,
		domain.StateFail, domain.FailureTLSUnknownAuthority)

	findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	refs := findings[0].EvidenceRefs()
	found := false
	for _, ref := range refs {
		if ref == handshake {
			found = true
		}
	}
	if !found {
		t.Fatalf("refs = %v, want the handshake %s as the causal owner", refs, handshake)
	}
	if findings[0].Layer() != domain.LayerTopology {
		t.Fatalf("layer = %s, want L6", findings[0].Layer())
	}
}

// A local budget expiry on a literal advertisement stays "not measured": it is
// svcdoctor's own limit, never a claim that the broker is unreachable.
func TestALiteralAdvertisementCutShortIsNotCalledUnreachable(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "10.20.30.41:9093")
	b.literalConnect(advertisement, "10.20.30.41", 9093,
		domain.StateUnknown, domain.FailureExecLocalTimeout)

	findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
	for _, f := range findings {
		if f.Kind() == domain.FindingKindConfirmed {
			t.Fatalf("a locally-timed-out literal advertisement produced a confirmed claim: %v", f)
		}
	}
}

// A named advertisement is unaffected: the second shape did not replace the
// first.
func TestANamedAdvertisementStillResolves(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	b.lookup(advertisement, "broker-2.internal", domain.StateFail, domain.FailureDNSNoAddress)

	findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Detail()+findings[0].Summary(), "no address") &&
		!strings.Contains(findings[0].Summary(), "could not be reached") {
		t.Fatalf("the named claim changed shape: %v", findings[0])
	}
}

// A mixed topology — one name, one IPv4, one IPv6 — produces one coherent set of
// claims, with no shape assumption that all advertisements are of one kind.
func TestAMixedAdvertisedTopologyIsDiagnosedCoherently(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)

	named := b.advertised(exchange, 1, "broker-1.internal:9093")
	lookup := b.lookup(named, "broker-1.internal", domain.StatePass, domain.FailureNone)
	b.connect(lookup, "10.20.30.40", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)

	four := b.advertised(exchange, 2, "10.20.30.42:9093")
	b.literalConnect(four, "10.20.30.42", 9093, domain.StateFail, domain.FailureTCPConnectionTimeout)

	six := b.advertised(exchange, 3, "[2001:db8::42]:9093")
	b.literalConnect(six, "2001:db8::42", 9093, domain.StateFail, domain.FailureTCPHostUnreachable)

	findings := AdvertisedEndpointUnreachable(rctx(b.freeze()))
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want one per advertisement: %v", len(findings), findings)
	}
	subjects := map[string]bool{}
	for _, f := range findings {
		subjects[f.Subject().Ref()] = true
	}
	for _, want := range []string{
		"broker-1.internal:9093", "10.20.30.42:9093", "[2001:db8::42]:9093",
	} {
		if !subjects[want] {
			t.Errorf("no finding for %s: %v", want, subjects)
		}
	}
}
