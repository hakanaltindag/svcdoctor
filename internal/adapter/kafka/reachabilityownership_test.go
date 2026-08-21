package kafka

import (
	"net"
	"reflect"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// This phase is measurement-only: there is no protocol consumer behind the
// transport it establishes, so every connection it opens must be closed before
// it returns. These tests count real sockets on both ends rather than trusting
// the code that owns them.

// --- nothing survives the call ----------------------------------------------

// TestEveryAdvertisedConnectionIsClosedExactlyOnce.
//
// Closed at all is measured on the peer: its read loop only ends when svcdoctor
// closes, so awaitIdle returning is the proof that nothing is still open. Closed
// *once* is measured on svcdoctor's own sockets, because an idempotent Close
// that ran twice would look identical from the far end.
func TestEveryAdvertisedConnectionIsClosedExactlyOnce(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
		advertisedBroker(3, "broker-3.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2").
		resolving(t, "broker-3.internal", "10.20.0.3")
	dialer := newAdvertisedDialer(peer)

	measure(t, target, tcpPlan(resolver, dialer))

	established := dialer.established()
	if len(established) != 3 {
		t.Fatalf("established = %d, want 3", len(established))
	}
	for i, conn := range established {
		if got := conn.closeCount(); got != 1 {
			t.Errorf("connection %d was closed %d times, want exactly 1", i, got)
		}
	}

	peer.awaitAccepted(t, 3)
	peer.awaitIdle()
}

// TestDualStackLeavesNoLiveSocket: several addresses for one advertisement, and
// every one of them released.
func TestDualStackLeavesNoLiveSocket(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1", "10.20.0.2", "2001:db8::1")
	dialer := newAdvertisedDialer(peer)

	measure(t, target, tcpPlan(resolver, dialer))

	established := dialer.established()
	if len(established) != 3 {
		t.Fatalf("established = %d, want one per resolved address", len(established))
	}
	for i, conn := range established {
		if got := conn.closeCount(); got != 1 {
			t.Errorf("connection %d was closed %d times, want exactly 1", i, got)
		}
	}

	peer.awaitAccepted(t, 3)
	peer.awaitIdle()
}

// TestTLSPathsAreReleasedToo: a completed handshake is a connection somebody has
// to close, and this phase is that somebody.
func TestTLSPathsAreReleasedToo(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedTLSPeer(t, "broker-1.internal")
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1", "10.20.0.2")
	dialer := newAdvertisedDialer(peer)

	measure(t, target, tlsPlan(resolver, dialer, peer))

	established := dialer.established()
	if len(established) != 2 {
		t.Fatalf("established = %d, want 2", len(established))
	}
	for i, conn := range established {
		if got := conn.closeCount(); got != 1 {
			t.Errorf("connection %d was closed %d times, want exactly 1", i, got)
		}
	}

	peer.awaitAccepted(t, 2)
	peer.awaitIdle()
}

// TestAFailedPathLeaksNothing: refusals and unresolvable names leave no socket
// behind, and the paths that did connect are still released.
func TestAFailedPathLeaksNothing(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "missing.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
		advertisedBroker(3, "broker-3.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		failing("missing.internal", &net.DNSError{Err: "no such host", IsNotFound: true}).
		resolving(t, "broker-2.internal", "10.20.0.2").
		resolving(t, "broker-3.internal", "10.20.0.3")
	dialer := newAdvertisedDialer(peer, "10.20.0.2")

	measure(t, target, tcpPlan(resolver, dialer))

	established := dialer.established()
	if len(established) != 1 {
		t.Fatalf("established = %d, want 1: only one address accepted a connection",
			len(established))
	}
	if got := established[0].closeCount(); got != 1 {
		t.Errorf("the one connection was closed %d times, want exactly 1", got)
	}

	peer.awaitAccepted(t, 1)
	peer.awaitIdle()
	if got := peer.acceptedCount(); got != 1 {
		t.Errorf("the peer accepted %d connections, want 1", got)
	}
}

// TestTheCallerReceivesNoConnection is the structural half of the ownership
// claim: there is no accessor a caller could take a socket through, so a
// discovered-broker connection cannot escape even by mistake.
//
// A pool of live connections to discovered brokers would be a resource with no
// reader — nothing in this phase or any phase below it speaks to a discovered
// endpoint — and it would have to be closed by a layer that never opened it.
func TestTheCallerReceivesNoConnection(t *testing.T) {
	resultType := reflect.TypeOf(&MeasurementResult{})

	connType := reflect.TypeOf((*net.Conn)(nil)).Elem()
	continuationType := reflect.TypeOf(&transport.Continuation{})

	for i := range resultType.NumMethod() {
		method := resultType.Method(i)
		for out := range method.Type.NumOut() {
			switch returned := method.Type.Out(out); {
			case returned == connType, returned == continuationType:
				t.Errorf("MeasurementResult.%s hands back %s: no live discovered-broker "+
					"connection may leave this phase", method.Name, returned)
			case returned.Kind() == reflect.Slice && returned.Elem() == continuationType:
				t.Errorf("MeasurementResult.%s hands back transport continuations", method.Name)
			}
		}
	}

	// And there is nothing to close, because there is nothing left open.
	var value any = &MeasurementResult{}
	if _, ok := value.(interface{ Close() error }); ok {
		t.Error("MeasurementResult has a Close: it owns a resource it should have released")
	}
	if _, ok := value.(interface{ TakeConn() (net.Conn, bool) }); ok {
		t.Error("MeasurementResult hands out a connection")
	}
}

// --- the one-hop boundary ---------------------------------------------------

// TestNoKafkaProtocolReachesADiscoveredEndpoint is the scope statement of the
// phase, measured rather than asserted.
//
// The peer is not a Kafka broker and would answer nothing if asked; what it does
// is count every byte that arrives above TLS. svcdoctor establishes transport
// and closes, so the count must be zero: no ApiVersions, no SaslHandshake, no
// SaslAuthenticate, no Metadata.
func TestNoKafkaProtocolReachesADiscoveredEndpoint(t *testing.T) {
	for _, testCase := range []struct {
		name string
		tls  bool
	}{
		{"plaintext", false},
		{"tls", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target := discoveredTopology(t,
				advertisedBroker(1, "broker-1.internal", 9093),
				advertisedBroker(2, "broker-2.internal", 9093),
			)
			resolver := newHostResolver().
				resolving(t, "broker-1.internal", "10.20.0.1").
				resolving(t, "broker-2.internal", "10.20.0.2")

			var peer *advertisedPeer
			var plan TransportPlan
			if testCase.tls {
				peer = newAdvertisedTLSPeer(t, "broker-1.internal")
				plan = tlsPlan(resolver, newAdvertisedDialer(peer), peer)
			} else {
				peer = newAdvertisedPeer(t)
				plan = tcpPlan(resolver, newAdvertisedDialer(peer))
			}

			result := measure(t, target, plan)
			if result.Measured() != 2 {
				t.Fatalf("measured = %d, want 2: the fixture path did not run", result.Measured())
			}

			peer.awaitAccepted(t, 2)
			peer.awaitIdle()

			if got := peer.appBytesRead(); got != 0 {
				t.Errorf("the advertised endpoint received %d application bytes, want 0: "+
					"this phase stops at transport", got)
			}
		})
	}
}

// TestTheBootstrapBrokerIsAskedNothingFurther: the one-hop boundary also means
// no second Metadata, so the connection the topology came over is untouched.
func TestTheBootstrapBrokerIsAskedNothingFurther(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	)
	before := target.broker.metadataRequestCount()

	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2")
	measure(t, target, tcpPlan(resolver, newAdvertisedDialer(peer)))

	if got := target.broker.metadataRequestCount(); got != before {
		t.Errorf("the bootstrap broker saw %d metadata requests, want the %d it had: "+
			"reachability re-enters nothing", got, before)
	}
	if got := len(target.registry.all()); got != 1 {
		t.Errorf("%d bootstrap connections exist, want 1: nothing redialled the bootstrap", got)
	}
}
