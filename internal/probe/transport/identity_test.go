package transport

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	probetls "github.com/hakanaltindag/svcdoctor/internal/probe/tls"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The identity authority of a chain run, held at the layer that decides it.
//
// # Why these are here and not in internal/probe/tls
//
// The TLS probe verifies whatever `ServerName` it is handed and is already
// tested on that. **The chain is what decides which name that is**, and it is
// the only place the decision exists: `tlsParams` reads
// `TLS.ServerName || Host`, and every Kafka handshake and every advertised-broker
// handshake goes through it.
//
// Phase 6.6's mutation matrix found the layer unguarded. Replacing the whole
// rule with `serverName := p.Host` — ignoring `--tls-server-name` outright —
// passed the entire repository suite. The PostgreSQL adapter's copy of the same
// rule *was* covered, so the two halves of one policy were guarded unequally.
//
// ADR 0058 §3 and §4 are what these pin.

// TestTheServerNameOverrideReachesTheHandshake is the mutation's direct answer.
//
// The peer's certificate names only the override, so a chain that ignored it and
// verified against `Host` would fail to verify — and the recorded server name
// would name the host rather than the override. Both are asserted, because
// either alone can be satisfied by an implementation that is wrong in the other
// direction.
func TestTheServerNameOverrideReachesTheHandshake(t *testing.T) {
	const override = "override.internal"

	peer := newTLSPeer(t, []string{override})
	result, graph := run(t, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1"),
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool, ServerName: override},
	})

	handshake := onlyHandshake(t, graph)
	if got := handshake.State(); got != domain.StatePass {
		t.Fatalf("handshake state = %s, want PASS; the override did not reach verification",
			got)
	}
	assertServerName(t, handshake, override)

	// And it really did verify, rather than passing because verification was off.
	continuations := result.Continuations()
	if len(continuations) != 1 {
		t.Fatalf("continuations = %d, want 1", len(continuations))
	}
	if got := continuations[0].Channel(); got != security.ChannelTLSVerified {
		t.Errorf("channel = %s, want tls-verified", got)
	}
}

// TestWithoutAnOverrideTheRequestedHostIsTheIdentity is the other half.
//
// A test that only pinned the override would be satisfied by a chain that used
// the override *always* — including as a default. This fixes the fallback.
func TestWithoutAnOverrideTheRequestedHostIsTheIdentity(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	_, graph := run(t, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1"),
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool},
	})

	handshake := onlyHandshake(t, graph)
	if got := handshake.State(); got != domain.StatePass {
		t.Fatalf("handshake state = %s, want PASS", got)
	}
	assertServerName(t, handshake, testHost)
}

// TestResolutionNeverBecomesTheIdentity is ADR 0058 §3.
//
// The certificate names the requested host and **not** the address it resolved
// to. A chain that used the resolved address as the identity — the shape
// `serverName = addr.Addr().String()` produces — verifies nothing a client would
// verify, and lets anything that can influence DNS choose the name svcdoctor
// will accept.
//
// It is the identity analogue of ADR 0028's credential rule, and it is asserted
// on the recorded attribute as well as on the outcome so that a run which
// happened to pass for another reason cannot satisfy it.
func TestResolutionNeverBecomesTheIdentity(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	_, graph := run(t, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1"),
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool},
	})

	handshake := onlyHandshake(t, graph)
	if got := handshake.State(); got != domain.StatePass {
		t.Fatalf("handshake state = %s, want PASS", got)
	}
	for _, resolved := range []string{"10.0.0.1", "10.0.0.1:5432"} {
		assertServerNameIsNot(t, handshake, resolved)
	}
}

// TestTheIdentityIsOneNamePerRunNotOnePerAddress pins that several addresses of
// one name all verify that name.
//
// A real client behaves this way, and it is what makes per-address divergence a
// fact about the target rather than about svcdoctor. The peer's certificate
// carries the host and neither address.
func TestTheIdentityIsOneNamePerRunNotOnePerAddress(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	_, graph := run(t, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1", "10.0.0.2"),
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool},
	})

	handshakes := handshakeNodes(graph)
	if len(handshakes) != 2 {
		t.Fatalf("handshakes = %d, want 2", len(handshakes))
	}
	for _, node := range handshakes {
		if got := node.State(); got != domain.StatePass {
			t.Errorf("%s state = %s, want PASS", node.Subject().Ref(), got)
		}
		assertServerName(t, node, testHost)
	}
}

// --- helpers ------------------------------------------------------------------

func handshakeNodes(graph domain.Graph) []domain.Evidence {
	var out []domain.Evidence
	for _, node := range graph.Nodes() {
		if node.Step() == probetls.StepHandshake {
			out = append(out, node)
		}
	}
	return out
}

func onlyHandshake(t *testing.T, graph domain.Graph) domain.Evidence {
	t.Helper()
	nodes := handshakeNodes(graph)
	if len(nodes) != 1 {
		t.Fatalf("handshake nodes = %d, want 1", len(nodes))
	}
	return nodes[0]
}

func serverNameOf(t *testing.T, node domain.Evidence) string {
	t.Helper()
	value, ok := node.Attribute(probetls.AttrServerName)
	if !ok {
		t.Fatalf("%s records no %s attribute", node.ID(), probetls.AttrServerName)
	}
	// A host-kind attribute, so that redaction pseudonymizes it rather than
	// carrying an operator's internal name into a shareable report.
	name, ok := value.Host()
	if !ok {
		t.Fatalf("%s is not a host attribute", probetls.AttrServerName)
	}
	return name
}

func assertServerName(t *testing.T, node domain.Evidence, want string) {
	t.Helper()
	if got := serverNameOf(t, node); got != want {
		t.Errorf("%s = %q, want %q", probetls.AttrServerName, got, want)
	}
}

func assertServerNameIsNot(t *testing.T, node domain.Evidence, unwanted string) {
	t.Helper()
	if got := serverNameOf(t, node); got == unwanted {
		t.Errorf("%s = %q; a resolved address became the TLS identity",
			probetls.AttrServerName, got)
	}
}
