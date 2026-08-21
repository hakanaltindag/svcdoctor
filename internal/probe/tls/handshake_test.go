package tls

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

func handshake(t *testing.T, conn net.Conn, params Params) *Result {
	t.Helper()

	r, err := Handshake(context.Background(), conn, params)
	if err != nil {
		t.Fatalf("Handshake: unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func attribute(t *testing.T, e domain.Evidence, key domain.AttributeKey) domain.AttrValue {
	t.Helper()

	v, ok := e.Attribute(key)
	if !ok {
		t.Fatalf("attribute %s is missing; present: %v", key, e.Attributes())
	}
	return v
}

func stringAttr(t *testing.T, e domain.Evidence, key domain.AttributeKey) string {
	t.Helper()

	s, ok := attribute(t, e, key).Str()
	if !ok {
		t.Fatalf("attribute %s is not a string", key)
	}
	return s
}

func boolAttr(t *testing.T, e domain.Evidence, key domain.AttributeKey) bool {
	t.Helper()

	b, ok := attribute(t, e, key).Bool()
	if !ok {
		t.Fatalf("attribute %s is not a bool", key)
	}
	return b
}

func listAttr(t *testing.T, e domain.Evidence, key domain.AttributeKey) []string {
	t.Helper()

	list, ok := attribute(t, e, key).HostList()
	if !ok {
		t.Fatalf("attribute %s is not a host list", key)
	}
	return list
}

// hostAttr reads a declared identity value. The distinct accessor is the point:
// an identity-bearing value is a different kind from a plain string, so
// redaction can recognize it without guessing (ADR 0022).
func hostAttr(t *testing.T, e domain.Evidence, key domain.AttributeKey) string {
	t.Helper()

	host, ok := attribute(t, e, key).Host()
	if !ok {
		t.Fatalf("attribute %s is not a host", key)
	}
	return host
}

// --- verified success -----------------------------------------------------

func TestVerifiedHandshake(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	before := time.Now()
	r := handshake(t, f.conn, f.params(ca, "server.test"))
	e := r.Evidence()

	if e.State() != domain.StatePass {
		t.Fatalf("state = %s, want PASS", e.State())
	}
	if e.FailureClass() != domain.FailureNone {
		t.Errorf("failure class = %s, want NONE", e.FailureClass())
	}
	if got, want := e.Layer(), domain.LayerTLS; got != want {
		t.Errorf("layer = %s, want %s", got, want)
	}
	if got, want := e.Step(), StepHandshake; got != want {
		t.Errorf("step = %s, want %s", got, want)
	}
	if got, want := e.Subject().Ref(), f.addr.String(); got != want {
		t.Errorf("subject ref = %q, want the concrete peer %q", got, want)
	}
	if !boolAttr(t, e, AttrVerified) {
		t.Error("tls.verified = false after a verified handshake")
	}
	if got := stringAttr(t, e, AttrTrustSource); got != trustSourceCustom {
		t.Errorf("tls.trust_source = %q, want %q", got, trustSourceCustom)
	}
	if e.StartedAt().IsZero() {
		t.Error("startedAt is zero")
	}
	if e.StartedAt().Before(before.UTC().Add(-time.Second)) {
		t.Errorf("startedAt = %s, want at or after %s", e.StartedAt(), before)
	}
	if e.Duration() < 0 {
		t.Errorf("duration = %s, want non-negative", e.Duration())
	}
	if !r.Connected() {
		t.Error("a successful handshake produced no transferable connection")
	}
}

func TestNegotiatedFactsAreRecorded(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})

	for _, tc := range []struct {
		name        string
		maxVersion  uint16
		wantVersion string
	}{
		{"tls 1.3", cryptotls.VersionTLS13, "TLS1.3"},
		{"tls 1.2", cryptotls.VersionTLS12, "TLS1.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dialFixture(t, peerTLS, serverConfig(cert, tc.maxVersion))
			e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

			if got := stringAttr(t, e, AttrVersion); got != tc.wantVersion {
				t.Errorf("tls.version = %q, want %q", got, tc.wantVersion)
			}
			cipher := stringAttr(t, e, AttrCipherSuite)
			if cipher == "" || strings.HasPrefix(cipher, "0x") {
				t.Errorf("tls.cipher_suite = %q, want a named suite", cipher)
			}
		})
	}
}

// TestVersionNameIsStableForUnknownValues covers the future-version path
// without pretending svcdoctor can negotiate one.
func TestVersionNameIsStableForUnknownValues(t *testing.T) {
	if got, want := versionName(0x0399), "0x0399"; got != want {
		t.Errorf("versionName(0x0399) = %q, want %q", got, want)
	}
	if got, want := versionName(cryptotls.VersionTLS12), "TLS1.2"; got != want {
		t.Errorf("versionName(TLS1.2) = %q, want %q", got, want)
	}
}

func TestCertificateFactsAreRecorded(t *testing.T) {
	ca := newTestCA(t)
	notBefore := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	cert := ca.issue(t, leafOptions{
		dnsNames:  []string{"server.test", "alias.test"},
		ips:       []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("2001:db8::5")},
		notBefore: notBefore,
		notAfter:  notAfter,
	})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	count, ok := attribute(t, e, AttrPeerCertificateCount).Int()
	if !ok || count != 1 {
		t.Errorf("tls.peer_certificate_count = %d, want 1", count)
	}

	gotNotAfter, ok := attribute(t, e, AttrPeerNotAfter).Time()
	if !ok || !gotNotAfter.Equal(notAfter.UTC()) {
		t.Errorf("tls.peer_not_after = %s, want %s", gotNotAfter, notAfter.UTC())
	}
	gotNotBefore, ok := attribute(t, e, AttrPeerNotBefore).Time()
	if !ok || !gotNotBefore.Equal(notBefore.UTC()) {
		t.Errorf("tls.peer_not_before = %s, want %s", gotNotBefore, notBefore.UTC())
	}

	if got, want := listAttr(t, e, AttrPeerDNSNames), []string{"alias.test", "server.test"}; !equal(got, want) {
		t.Errorf("tls.peer_dns_names = %v, want %v (sorted)", got, want)
	}
	if got, want := listAttr(t, e, AttrPeerIPAddresses), []string{"10.0.0.5", "2001:db8::5"}; !equal(got, want) {
		t.Errorf("tls.peer_ip_addresses = %v, want %v (sorted, canonical)", got, want)
	}
}

// TestNoExpiryJudgement pins the probe-versus-diagnosis line. A certificate
// close to expiry is recorded as a date, never as a degraded state.
func TestNoExpiryJudgement(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{
		dnsNames: []string{"server.test"},
		notAfter: time.Now().Add(30 * time.Second),
	})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	if e.State() != domain.StatePass {
		t.Errorf("state = %s, want PASS: an imminent expiry is a fact, not a verdict", e.State())
	}
	if _, ok := attribute(t, e, AttrPeerNotAfter).Time(); !ok {
		t.Error("the expiry instant should be recorded")
	}
}

func TestSANOrderingIsDeterministic(t *testing.T) {
	ca := newTestCA(t)
	forward := ca.issue(t, leafOptions{dnsNames: []string{"a.test", "b.test", "c.test"}})
	shuffled := ca.issue(t, leafOptions{dnsNames: []string{"c.test", "a.test", "b.test"}})

	first := dialFixture(t, peerTLS, serverConfig(forward, 0))
	second := dialFixture(t, peerTLS, serverConfig(shuffled, 0))

	a := handshake(t, first.conn, first.params(ca, "a.test")).Evidence()
	b := handshake(t, second.conn, second.params(ca, "a.test")).Evidence()

	if got, want := listAttr(t, a, AttrPeerDNSNames), listAttr(t, b, AttrPeerDNSNames); !equal(got, want) {
		t.Errorf("certificate name order reached the evidence: %v vs %v", got, want)
	}
}

// --- verification failures ------------------------------------------------

func TestVerificationFailures(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()

	tests := []struct {
		name        string
		leaf        leafOptions
		serverName  string
		trustCA     bool
		wantFailure domain.FailureClass
	}{
		{
			name: "unknown authority", leaf: leafOptions{dnsNames: []string{"server.test"}},
			serverName: "server.test", trustCA: false,
			wantFailure: domain.FailureTLSUnknownAuthority,
		},
		{
			name: "hostname mismatch", leaf: leafOptions{dnsNames: []string{"server.test"}},
			serverName: "other.test", trustCA: true,
			wantFailure: domain.FailureTLSHostnameMismatch,
		},
		{
			name: "expired certificate",
			leaf: leafOptions{
				dnsNames:  []string{"server.test"},
				notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-24 * time.Hour),
			},
			serverName: "server.test", trustCA: true,
			wantFailure: domain.FailureTLSCertificateExpired,
		},
		{
			name: "certificate not yet valid",
			leaf: leafOptions{
				dnsNames:  []string{"server.test"},
				notBefore: now.Add(24 * time.Hour), notAfter: now.Add(48 * time.Hour),
			},
			serverName: "server.test", trustCA: true,
			wantFailure: domain.FailureTLSCertificateNotYetValid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := ca.issue(t, tt.leaf)
			f := dialFixture(t, peerTLS, serverConfig(cert, 0))

			params := f.params(ca, tt.serverName)
			if !tt.trustCA {
				params.RootCAs = x509.NewCertPool() // empty: trusts nothing
			}

			r := handshake(t, f.conn, params)
			e := r.Evidence()

			if e.State() != domain.StateFail {
				t.Errorf("state = %s, want FAIL", e.State())
			}
			if e.FailureClass() != tt.wantFailure {
				t.Errorf("failure class = %s, want %s", e.FailureClass(), tt.wantFailure)
			}
			if boolAttr(t, e, AttrVerified) {
				t.Error("tls.verified = true after a rejected certificate")
			}
			if r.Connected() {
				t.Error("a failed handshake produced a connection")
			}
		})
	}
}

// TestRejectedCertificateStillReportsItsNames is what makes a failure
// actionable: the report can say which names the certificate actually carried.
func TestRejectedCertificateStillReportsItsNames(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test", "alias.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	e := handshake(t, f.conn, f.params(ca, "other.test")).Evidence()

	if e.FailureClass() != domain.FailureTLSHostnameMismatch {
		t.Fatalf("failure class = %s, want TLS_HOSTNAME_MISMATCH", e.FailureClass())
	}
	if got, want := listAttr(t, e, AttrPeerDNSNames), []string{"alias.test", "server.test"}; !equal(got, want) {
		t.Errorf("tls.peer_dns_names = %v, want %v", got, want)
	}
	if got, want := hostAttr(t, e, AttrServerName), "other.test"; got != want {
		t.Errorf("tls.server_name = %q, want the name that was checked, %q", got, want)
	}
}

func TestPeerThatDoesNotSpeakTLS(t *testing.T) {
	ca := newTestCA(t)
	f := dialFixture(t, peerPlaintext, nil)

	e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	if e.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", e.State())
	}
	if e.FailureClass() != domain.FailureTLSPeerNotTLS {
		t.Errorf("failure class = %s, want TLS_PEER_NOT_TLS", e.FailureClass())
	}
}

func TestGenericHandshakeFailure(t *testing.T) {
	ca := newTestCA(t)
	f := dialFixture(t, peerHangsUp, nil)

	e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	if e.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", e.State())
	}
	if e.FailureClass() != domain.FailureTLSHandshakeFailure {
		t.Errorf("failure class = %s, want TLS_HANDSHAKE_FAILURE", e.FailureClass())
	}
}

// TestVersionMismatchIsRecordedConservatively documents a distinction the
// standard library does not expose. A received protocol_version alert arrives as
// an unexported error type, so this is a generic handshake failure rather than
// TLS_VERSION_MISMATCH. Reading the class out of the error's text is exactly the
// precision this probe refuses to invent.
func TestVersionMismatchIsRecordedConservatively(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, cryptotls.VersionTLS12))

	params := f.params(ca, "server.test")
	params.MinVersion = cryptotls.VersionTLS13

	e := handshake(t, f.conn, params).Evidence()

	if e.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", e.State())
	}
	if got := e.FailureClass(); got != domain.FailureTLSHandshakeFailure {
		t.Errorf("failure class = %s, want TLS_HANDSHAKE_FAILURE", got)
	}
}

// TestReservedClassesAreNeverProduced pins the classes this probe deliberately
// cannot evidence. Each needs something the standard library does not expose
// structurally, or a feature this phase did not implement, and guessing one
// would be exactly the false precision the claim discipline forbids.
func TestReservedClassesAreNeverProduced(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()

	scenarios := []func(t *testing.T) domain.Evidence{
		func(t *testing.T) domain.Evidence {
			cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
			f := dialFixture(t, peerTLS, serverConfig(cert, cryptotls.VersionTLS12))
			p := f.params(ca, "server.test")
			p.MinVersion = cryptotls.VersionTLS13
			return handshake(t, f.conn, p).Evidence()
		},
		func(t *testing.T) domain.Evidence {
			f := dialFixture(t, peerPlaintext, nil)
			return handshake(t, f.conn, f.params(ca, "server.test")).Evidence()
		},
		func(t *testing.T) domain.Evidence {
			f := dialFixture(t, peerHangsUp, nil)
			return handshake(t, f.conn, f.params(ca, "server.test")).Evidence()
		},
		func(t *testing.T) domain.Evidence {
			cert := ca.issue(t, leafOptions{
				dnsNames:  []string{"server.test"},
				notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-24 * time.Hour),
			})
			f := dialFixture(t, peerTLS, serverConfig(cert, 0))
			return handshake(t, f.conn, f.params(ca, "server.test")).Evidence()
		},
	}

	reserved := map[domain.FailureClass]bool{
		domain.FailureTLSVersionMismatch:           true,
		domain.FailureTLSClientCertificateRequired: true,
		domain.FailureTLSClientCertificateRejected: true,
	}

	for _, scenario := range scenarios {
		if class := scenario(t).FailureClass(); reserved[class] {
			t.Errorf("produced reserved class %s without the evidence to justify it", class)
		}
	}
}

// --- context --------------------------------------------------------------

// TestCallerDeadlineIsNotAPeerFailure is the claim-discipline test, matching the
// DNS and TCP probes. A handshake cut short by svcdoctor's own deadline proves
// nothing about the peer.
func TestCallerDeadlineIsNotAPeerFailure(t *testing.T) {
	ca := newTestCA(t)
	f := dialFixture(t, peerSilent, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	r, err := Handshake(ctx, f.conn, f.params(ca, "server.test"))
	if err != nil {
		t.Fatalf("Handshake: unexpected error: %v", err)
	}
	defer func() { _ = r.Close() }()

	e := r.Evidence()
	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", e.State())
	}
	if e.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("failure class = %s, want EXEC_LOCAL_TIMEOUT", e.FailureClass())
	}
}

func TestCancellationIsNotAPeerFailure(t *testing.T) {
	ca := newTestCA(t)
	f := dialFixture(t, peerSilent, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	r, err := Handshake(ctx, f.conn, f.params(ca, "server.test"))
	if err != nil {
		t.Fatalf("Handshake: unexpected error: %v", err)
	}
	defer func() { _ = r.Close() }()

	e := r.Evidence()
	if e.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", e.State())
	}
	if e.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("failure class = %s, want EXEC_CANCELLED", e.FailureClass())
	}
}

// TestPeerFailureIsNotBlamedOnTheLocalBudget is the converse: a peer that
// rejected the handshake must not be recorded as svcdoctor running out of time,
// even when the context is fine.
func TestPeerFailureIsNotBlamedOnTheLocalBudget(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	params := f.params(ca, "server.test")
	params.RootCAs = x509.NewCertPool()

	e := handshake(t, f.conn, params).Evidence()

	if e.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", e.State())
	}
	if e.FailureClass() == domain.FailureExecLocalTimeout {
		t.Error("a peer-side rejection was recorded as a local timeout")
	}
}

// TestCompletedHandshakeSurvivesLaterContextExpiry pins the ordering rule: a
// handshake that completed is a measurement that happened.
func TestCompletedHandshakeSurvivesLaterContextExpiry(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	ctx, cancel := context.WithCancel(context.Background())
	r, err := Handshake(ctx, f.conn, f.params(ca, "server.test"))
	cancel()
	if err != nil {
		t.Fatalf("Handshake: unexpected error: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got := r.Evidence().State(); got != domain.StatePass {
		t.Errorf("state = %s, want PASS", got)
	}
	if !r.Connected() {
		t.Error("the established connection was discarded")
	}
}

// --- verification disabled ------------------------------------------------

// TestInsecureHandshakeDoesNotClaimVerification is the security contract. An
// unverified handshake proves encryption, not identity, and the evidence has to
// say so — diagnosis reads only the graph, so a fact recorded solely in
// report-level metadata would be invisible to it.
func TestInsecureHandshakeDoesNotClaimVerification(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	params := Params{
		Endpoint:           "primary.internal:9092",
		Address:            f.addr,
		ServerName:         "wrong.test", // would fail verification
		InsecureSkipVerify: true,
	}

	r := handshake(t, f.conn, params)
	e := r.Evidence()

	if e.State() != domain.StatePass {
		t.Fatalf("state = %s, want PASS: the channel was established", e.State())
	}
	if boolAttr(t, e, AttrVerified) {
		t.Error("tls.verified = true although verification was disabled")
	}
	if _, ok := e.Attribute(AttrTrustSource); ok {
		t.Error("a trust source was recorded although none was consulted")
	}
	if !r.Connected() {
		t.Error("an insecure handshake produced no connection")
	}
}

// TestVerificationFailureDoesNotRetryInsecurely proves there is no fallback: a
// rejected certificate stays a failure, and the probe never opens a second,
// unverified handshake behind the caller's back.
func TestVerificationFailureDoesNotRetryInsecurely(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	params := f.params(ca, "other.test")
	e := handshake(t, f.conn, params).Evidence()

	if e.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", e.State())
	}
	if boolAttr(t, e, AttrVerified) {
		t.Error("tls.verified = true after a failed verification")
	}
	if _, ok := e.Attribute(AttrVersion); ok {
		t.Error("a negotiated version was recorded for a handshake that never completed")
	}
}

func TestTrustSourceReflectsWhereRootsCameFrom(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})

	f := dialFixture(t, peerTLS, serverConfig(cert, 0))
	custom := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()
	if got := stringAttr(t, custom, AttrTrustSource); got != trustSourceCustom {
		t.Errorf("tls.trust_source = %q, want %q", got, trustSourceCustom)
	}

	// With no pool supplied the system store is what a client would use; the
	// fixture CA is not in it, so the handshake fails and the recorded trust
	// source still says where the roots came from.
	second := dialFixture(t, peerTLS, serverConfig(cert, 0))
	params := second.params(ca, "server.test")
	params.RootCAs = nil
	system := handshake(t, second.conn, params).Evidence()
	if got := stringAttr(t, system, AttrTrustSource); got != trustSourceSystem {
		t.Errorf("tls.trust_source = %q, want %q", got, trustSourceSystem)
	}
}

// --- identifiers and subjects ---------------------------------------------

func TestEvidenceIDDistinguishesTLSFromTCP(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	want := domain.EvidenceID("tls.handshake/primary.internal:9092/" + f.addr.Addr().String())
	if got := e.ID(); got != want {
		t.Errorf("id = %q, want %q", got, want)
	}
	if strings.HasPrefix(e.ID().String(), "tcp.") {
		t.Error("the TLS node shares the TCP step prefix")
	}
}

func TestEvidenceIDIsDeterministic(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})

	first := dialFixture(t, peerTLS, serverConfig(cert, 0))
	second := dialFixture(t, peerTLS, serverConfig(cert, 0))

	a := handshake(t, first.conn, Params{
		Endpoint: "e:9092", Address: netip.MustParseAddrPort("10.0.0.1:9092"),
		ServerName: "server.test", RootCAs: ca.pool,
	}).Evidence()
	b := handshake(t, second.conn, Params{
		Endpoint: "e:9092", Address: netip.MustParseAddrPort("10.0.0.1:9092"),
		ServerName: "server.test", RootCAs: ca.pool,
	}).Evidence()

	if a.ID() != b.ID() {
		t.Errorf("identifiers differ for the same attempt: %q and %q", a.ID(), b.ID())
	}
}

// TestSubjectIsThePeerNotTheServerName keeps the two identities apart. The
// socket went to an address; the certificate was checked against a name.
func TestSubjectIsThePeerNotTheServerName(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	if got, want := e.Subject().Ref(), f.addr.String(); got != want {
		t.Errorf("subject ref = %q, want %q", got, want)
	}
	if strings.Contains(e.Subject().Ref(), "server.test") {
		t.Error("the server name leaked into the subject")
	}
	if got := hostAttr(t, e, AttrServerName); got != "server.test" {
		t.Errorf("tls.server_name = %q, want %q", got, "server.test")
	}
}

// --- input validation -----------------------------------------------------

func TestHandshakeRejectsUnusableInput(t *testing.T) {
	valid := netip.MustParseAddrPort("10.0.0.1:9092")

	tests := map[string]Params{
		"empty endpoint":      {Address: valid, ServerName: "server.test"},
		"empty server name":   {Endpoint: "e:9092", Address: valid},
		"padded server name":  {Endpoint: "e:9092", Address: valid, ServerName: " server.test"},
		"control character":   {Endpoint: "e:9092", Address: valid, ServerName: "server\n.test"},
		"unspecified address": {Endpoint: "e:9092", ServerName: "server.test"},
		"zero port": {
			Endpoint: "e:9092", ServerName: "server.test",
			Address: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 0),
		},
		"inverted version bounds": {
			Endpoint: "e:9092", Address: valid, ServerName: "server.test",
			MinVersion: cryptotls.VersionTLS13, MaxVersion: cryptotls.VersionTLS12,
		},
	}

	for name, params := range tests {
		t.Run(name, func(t *testing.T) {
			conn := &countingConn{Conn: acceptedConn(t)}

			r, err := Handshake(context.Background(), conn, params)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if r != nil {
				t.Error("a result was produced for unusable input")
			}
			if conn.closes != 1 {
				t.Errorf("closes = %d, want 1: the connection was already ours", conn.closes)
			}
		})
	}
}

func TestHandshakeRejectsNilConnection(t *testing.T) {
	r, err := Handshake(context.Background(), nil, Params{
		Endpoint: "e:9092", Address: netip.MustParseAddrPort("10.0.0.1:9092"), ServerName: "server.test",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if r != nil {
		t.Error("a result was produced without a connection")
	}
}

//nolint:staticcheck // passing a nil context is exactly what this guard is for.
func TestHandshakeRejectsNilContext(t *testing.T) {
	conn := &countingConn{Conn: acceptedConn(t)}

	r, err := Handshake(nil, conn, Params{
		Endpoint: "e:9092", Address: netip.MustParseAddrPort("10.0.0.1:9092"), ServerName: "server.test",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if r != nil {
		t.Error("a result was produced without a context")
	}
	if conn.closes != 1 {
		t.Errorf("closes = %d, want 1", conn.closes)
	}
}

// --- no raw runtime values ------------------------------------------------

// TestHandshakeErrorTextNeverReachesEvidence guards ADR 0010. A TLS error names
// certificates, authorities and sometimes the peer, in prose structural
// redaction cannot recognize.
func TestHandshakeErrorTextNeverReachesEvidence(t *testing.T) {
	ca := newTestCA(t)
	const canary = "canary-authority-192.0.2.9"
	cert := ca.issue(t, leafOptions{dnsNames: []string{canary + ".test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	params := f.params(ca, "asked-for.test")
	e := handshake(t, f.conn, params).Evidence()

	encoded, err := e.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	// The certificate's own names are recorded deliberately; what must not
	// appear is the error's prose around them.
	for _, phrase := range []string{"x509:", "tls:", "certificate is valid for", "failed to verify"} {
		if strings.Contains(string(encoded), phrase) {
			t.Errorf("canonical evidence contains error prose %q: %s", phrase, encoded)
		}
	}
}

// TestEvidenceCarriesNoPrivateMaterial checks the obvious catastrophe: nothing
// resembling a key or a raw certificate blob may be serialized.
func TestEvidenceCarriesNoPrivateMaterial(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	encoded, err := e.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, forbidden := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE", "-----"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("canonical evidence contains %q", forbidden)
		}
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	allowed := map[string]bool{
		"id": true, "subject": true, "layer": true, "step": true, "state": true,
		"failureClass": true, "attributes": true, "startedAt": true, "duration": true,
	}
	for field := range fields {
		if !allowed[field] {
			t.Errorf("canonical evidence carries an unexpected field %q", field)
		}
	}
}

// TestAttributeShapesStayRedactable guards the security contract of the
// attribute vocabulary: every identity-bearing value is one address or one name
// per entry, which is the only shape structural redaction recognizes.
func TestAttributeShapesStayRedactable(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{
		dnsNames: []string{"server.test"},
		ips:      []net.IP{net.ParseIP("10.0.0.5")},
	})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	e := handshake(t, f.conn, f.params(ca, "server.test")).Evidence()

	for _, name := range listAttr(t, e, AttrPeerDNSNames) {
		if strings.ContainsAny(name, " ,;") {
			t.Errorf("DNS name %q is not a bare name", name)
		}
	}
	for _, address := range listAttr(t, e, AttrPeerIPAddresses) {
		if _, err := netip.ParseAddr(address); err != nil {
			t.Errorf("IP SAN %q does not parse as an address: %v", address, err)
		}
	}
	if strings.ContainsAny(hostAttr(t, e, AttrServerName), " ,;") {
		t.Error("tls.server_name is not a bare name")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// acceptedConn returns a connection to a listener that accepts and ignores it,
// for tests that need a real connection the probe will close without a
// handshake.
func acceptedConn(t *testing.T) net.Conn {
	t.Helper()

	f := dialFixture(t, peerSilent, nil)
	return f.conn
}
