package tls

import (
	"net"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// IP-literal identity, pinned before Phase 6.7 depends on it.
//
// # Why these exist now, in a phase that implements no IP-literal support
//
// ADR 0058 §6 asserts that an IP-literal target verifies against a certificate's
// IP SANs with no flag, and that Go sends no SNI for one. Phase 6.7's graph work
// is built on both claims. They were measured against the standard library
// during the Phase 6.6 review; **a measurement taken once, outside the
// repository, is not a contract.** These re-take it on every build.
//
// The behaviour is Go's rather than svcdoctor's, which is exactly why it needs
// a test here: this package passes `ServerName` through verbatim, so if Go ever
// stopped matching IP SANs, or started matching CN, svcdoctor's IP-literal
// support would change without a line of svcdoctor changing. ADR 0058 §16 lists
// that as a reopen condition, and this is how it would be noticed.

// TestAnIPLiteralVerifiesAgainstAnIPSAN is the claim Phase 6.7 rests on.
func TestAnIPLiteralVerifiesAgainstAnIPSAN(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	evidence := handshake(t, f.conn, f.params(ca, "127.0.0.1")).Evidence()

	if got := evidence.State(); got != domain.StatePass {
		t.Fatalf("state = %s, want PASS: an IP literal must verify against an IP SAN "+
			"with no --tls-server-name (ADR 0058 section 6)", got)
	}
	if !boolAttr(t, evidence, AttrVerified) {
		t.Error("tls.verified is false on a handshake that matched an IP SAN")
	}
}

// TestAnIPLiteralDoesNotMatchADNSSAN keeps the previous test from being read as
// "IP targets verify against anything".
//
// The certificate names the address as a DNS name rather than as an IP SAN, and
// that is not a match. It is the shape a certificate takes when somebody typed
// an address into a `subjectAltName = DNS:` field, and accepting it would mean
// svcdoctor verifying peers no real client accepts.
func TestAnIPLiteralDoesNotMatchADNSSAN(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"127.0.0.1"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	evidence := handshake(t, f.conn, f.params(ca, "127.0.0.1")).Evidence()

	if got := evidence.State(); got != domain.StateFail {
		t.Fatalf("state = %s, want FAIL: a DNS SAN spelled like an address is not "+
			"an IP SAN", got)
	}
	if got := evidence.FailureClass(); got != domain.FailureTLSHostnameMismatch {
		t.Errorf("failure class = %s, want %s", got, domain.FailureTLSHostnameMismatch)
	}
}

// TestAnIPSANDoesNotSatisfyADifferentAddress pins that the match is on the
// address and not merely on the SAN's presence.
func TestAnIPSANDoesNotSatisfyADifferentAddress(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{ips: []net.IP{net.ParseIP("10.0.0.1")}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	evidence := handshake(t, f.conn, f.params(ca, "127.0.0.1")).Evidence()

	if got := evidence.State(); got != domain.StateFail {
		t.Fatalf("state = %s, want FAIL", got)
	}
	if got := evidence.FailureClass(); got != domain.FailureTLSHostnameMismatch {
		t.Errorf("failure class = %s, want %s", got, domain.FailureTLSHostnameMismatch)
	}
}

// TestAnAddressTargetWithADNSOverrideVerifiesTheOverride is ADR 0058 §6's
// second shape: connect by address, verify the name.
//
// It is the correct configuration for a host reachable only by address whose
// certificate names it by DNS, and it is what makes the override worth having
// once Phase 6.7 accepts literals.
func TestAnAddressTargetWithADNSOverrideVerifiesTheOverride(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"kafka.internal"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	// The address is where the connection went; the override is what is verified.
	evidence := handshake(t, f.conn, f.params(ca, "kafka.internal")).Evidence()

	if got := evidence.State(); got != domain.StatePass {
		t.Fatalf("state = %s, want PASS", got)
	}
	if got := hostAttr(t, evidence, AttrServerName); got != "kafka.internal" {
		t.Errorf("%s = %q, want the override", AttrServerName, got)
	}
	// The subject stays the concrete peer, so the report still says where the
	// connection went rather than what it verified.
	if got := evidence.Subject().Ref(); got == "kafka.internal" {
		t.Error("the override became the evidence subject; it names what was " +
			"verified, not what was reached")
	}
}

// TestACommonNameIsNeverAnIdentity is ADR 0058 §6's refusal, held as a fact
// about Go rather than as a promise about svcdoctor.
//
// Go ignores `CN` for hostname verification. svcdoctor deliberately adds no
// custom verification to resurrect it: accepting a CN-only certificate would
// mean reporting a success no modern client can reproduce.
func TestACommonNameIsNeverAnIdentity(t *testing.T) {
	ca := newTestCA(t)
	// No SANs at all. The fixture's CommonName is the CA's own subject, so any
	// name asked for here is one the certificate does not carry as a SAN.
	cert := ca.issue(t, leafOptions{})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	evidence := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	if got := evidence.State(); got != domain.StateFail {
		t.Fatalf("state = %s, want FAIL: a certificate with no SAN identifies nothing", got)
	}
	if boolAttr(t, evidence, AttrVerified) {
		t.Error("tls.verified is true for a certificate carrying no subject alternative name")
	}
}
