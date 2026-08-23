package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The adversarial security suite for `app.DiagnoseKafka`.
//
// Every test here drives the **production composition root**. Nothing
// hand-authors evidence and nothing calls an adapter directly, because what
// ADR 0050 decided is a property of a *run*: the question is not whether
// `MeasureAdvertised` can hold a credential — it structurally cannot — but
// whether the layer above it ever tries to give one to a discovered endpoint.
// Only a run can answer that.
//
// The canaries below are distinctive enough that finding one anywhere is proof
// rather than coincidence.

const (
	bootstrapCanaryHost = "kafka-bootstrap.canary.svcdoctor.test"
	hostileCanaryHost   = "attacker.canary.svcdoctor.test"
	siblingCanaryHost   = "broker-2.canary.svcdoctor.test"

	identityCanary = "svcdoctor-composition-canary-identity"
	secretCanary   = "svcdoctor-composition-canary-secret-9d3f1a"
)

// Synthetic addresses the routing dialer maps onto real listeners. They are
// documentation addresses, so nothing here can accidentally reach a real host.
var (
	addrPrimary = netip.MustParseAddr("198.51.100.10")
	addrSibling = netip.MustParseAddr("198.51.100.11")
	addrHostile = netip.MustParseAddr("198.51.100.20")
	addrRefused = netip.MustParseAddr("198.51.100.99")
)

// scenario is one controlled run of the production composition.
type scenario struct {
	resolver   tableResolver
	dialer     *routingDialer
	tls        *transport.TLSOptions
	credential security.Credential
	mechanism  string
	host       string
	port       uint16
	timeout    time.Duration
}

func (s *scenario) run(t *testing.T) app.Result {
	t.Helper()
	return s.runCtx(t, context.Background())
}

func (s *scenario) runCtx(t *testing.T, ctx context.Context) app.Result {
	t.Helper()

	mechanism := s.mechanism
	if mechanism == "" {
		mechanism = "PLAIN"
	}
	timeout := s.timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	vantage, err := domain.NewLocalVantage("svcdoctor-composition-test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	result, err := app.DiagnoseKafka(ctx, app.KafkaParams{
		Host:        s.host,
		Port:        s.port,
		Mechanism:   mechanism,
		Credential:  s.credential,
		Resolver:    s.resolver,
		Dialer:      s.dialer,
		TLS:         s.tls,
		StepTimeout: timeout,
		Vantage:     vantage,
		Version:     "0.0.0-composition-test",
	})
	if err != nil {
		t.Fatalf("DiagnoseKafka: %v", err)
	}
	return result
}

// credentialFor mints the one credential a run is allowed to carry, bound to the
// logical endpoint the operator named.
func credentialFor(t *testing.T, host string, port uint16) security.Credential {
	t.Helper()

	endpoint, err := security.NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("security.NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(endpoint, identityCanary, security.NewSecret(secretCanary))
	if err != nil {
		t.Fatalf("security.NewCredential: %v", err)
	}
	return credential
}

// --- A. a malicious Metadata response ---------------------------------------

// TestAMaliciousMetadataResponseGetsNoCredential is ADR 0050 section 5,
// executed.
//
// The bootstrap broker authenticates successfully and then advertises an
// endpoint the operator never named. **The hostile peer holds a valid
// certificate for its own name, signed by the CA this run trusts**, so the
// advertised TLS handshake to it succeeds and svcdoctor ends up holding a
// verified TLS channel to the attacker. That is the point: TLS proves *"you are
// talking to attacker.canary"*, and there is no assertion anywhere in the Kafka
// protocol that proves *"attacker.canary is a broker of the cluster you asked
// about"*.
//
// So the only thing standing between the operator's password and the attacker is
// the composition's refusal to treat peer-supplied data as an authorization
// source. This measures that refusal at the attacker's socket, above its TLS
// layer, where the count is exactly what svcdoctor's protocol layer sent.
func TestAMaliciousMetadataResponseGetsNoCredential(t *testing.T) {
	ca := newAuthority(t)

	hostile := newPeer(t, ca, peerConfig{serverName: hostileCanaryHost, hostile: true})
	bootstrap := newPeer(t, ca, peerConfig{
		serverName: bootstrapCanaryHost,
		advertised: []brokerEntry{advertise(2, hostileCanaryHost, int32(hostile.addr.Port()))},
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: bootstrap.addr.Port(),
		resolver: tableResolver{
			bootstrapCanaryHost: {addrPrimary},
			hostileCanaryHost:   {addrHostile},
		},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: bootstrap.addr},
			addrHostile: {to: hostile.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, bootstrap.addr.Port()),
	}
	result := s.run(t)

	bootstrap.awaitIdle(t)
	hostile.awaitIdle(t)

	// The credential really travelled, to the endpoint that was authorized for
	// it. Without this half the test could pass because nothing happened at all.
	payloads := bootstrap.sasl()
	if len(payloads) != 1 {
		t.Fatalf("the bootstrap peer received %d SaslAuthenticate payloads, want 1", len(payloads))
	}
	if !bytes.Contains(payloads[0], []byte(secretCanary)) {
		t.Fatal("the bootstrap peer did not receive the secret; the test proves nothing")
	}

	// And the hostile peer received a transport probe and nothing above it.
	if hostile.connectionCount() == 0 {
		t.Error("the hostile endpoint was never probed; the advertised sweep did not run")
	}
	if got := hostile.bytes(); got != 0 {
		t.Errorf("the hostile endpoint received %d application bytes, want 0", got)
	}
	if got := hostile.keys(); len(got) != 0 {
		t.Errorf("the hostile endpoint received Kafka requests %v, want none", got)
	}
	for _, payload := range hostile.sasl() {
		t.Errorf("the hostile endpoint received a SASL payload: %q", payload)
	}

	// The advertisement is nonetheless in the report, measured at transport.
	// Refusing to authenticate it is not refusing to look at it.
	assertAdvertised(t, result, hostileCanaryHost)
	s.dialer.requireBalanced(t)
}

// TestAHostileAdvertisementIsMeasuredOnlyAtTransport pins the boundary from the
// evidence side.
//
// The graph beneath a `kafka.broker_advertised` node must contain transport
// steps and nothing else. A protocol or authentication node there would mean the
// sweep had grown a second hop, which ADR 0050 section 1 forbids and which no
// byte counter would notice if the endpoint happened to answer.
func TestAHostileAdvertisementIsMeasuredOnlyAtTransport(t *testing.T) {
	ca := newAuthority(t)

	hostile := newPeer(t, ca, peerConfig{serverName: hostileCanaryHost, hostile: true})
	bootstrap := newPeer(t, ca, peerConfig{
		serverName: bootstrapCanaryHost,
		advertised: []brokerEntry{advertise(2, hostileCanaryHost, int32(hostile.addr.Port()))},
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: bootstrap.addr.Port(),
		resolver: tableResolver{
			bootstrapCanaryHost: {addrPrimary},
			hostileCanaryHost:   {addrHostile},
		},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: bootstrap.addr},
			addrHostile: {to: hostile.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, bootstrap.addr.Port()),
	}
	result := s.run(t)
	graph := result.Report().Graph()

	allowed := []domain.Step{
		vocabulary.StepDNSLookup, vocabulary.StepTCPConnect, vocabulary.StepTLSHandshake,
	}
	for _, node := range graph.Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		for _, id := range descendants(graph, node.ID()) {
			child, _ := graph.Node(id)
			if !slices.Contains(allowed, child.Step()) {
				t.Errorf("an advertised sweep produced %s beneath %s.\n\n"+
					"Advertised measurement stops at transport: no ApiVersions, no "+
					"SaslHandshake, no SaslAuthenticate, no second Metadata. "+
					"See ADR 0050 section 1.", child.Step(), node.Subject().Ref())
			}
		}
	}
	s.dialer.requireBalanced(t)
}

// --- B, C. authentication cardinality ---------------------------------------

// TestSeveralUsableBootstrapPathsProduceOneAttempt is the credential-spraying
// guard, measured rather than reasoned about.
//
// Two bootstrap addresses both resolve, both connect, both complete TLS, both
// answer ApiVersions and both accept the mechanism. Discovery therefore visits
// both — which is the point of measuring every path — and **exactly one of them
// receives a credential**.
//
// A run that authenticated both would look healthier, not less healthy, which is
// precisely why this needs a test rather than a review: the failure is invisible
// in the report and visible only in the target's audit log.
func TestSeveralUsableBootstrapPathsProduceOneAttempt(t *testing.T) {
	ca := newAuthority(t)

	first := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})
	second := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})

	s := &scenario{
		host: bootstrapCanaryHost, port: first.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary, addrSibling}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: first.addr},
			addrSibling: {to: second.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, first.addr.Port()),
	}
	result := s.run(t)

	first.awaitIdle(t)
	second.awaitIdle(t)

	// Both were discovered: ApiVersions and the handshake reached each of them,
	// and neither costs the broker an authentication attempt.
	for name, p := range map[string]*peer{"first": first, "second": second} {
		keys := p.keys()
		if !slices.Contains(keys, keyAPIVersions) || !slices.Contains(keys, keySASLHandshake) {
			t.Errorf("the %s peer saw %v; discovery should have reached both paths", name, keys)
		}
	}

	// Exactly one was authenticated.
	attempts := len(first.sasl()) + len(second.sasl())
	if attempts != 1 {
		t.Errorf("credential-bearing attempts = %d, want exactly 1.\n\n"+
			"A second attempt is a second entry in the target's audit log and, in a "+
			"directory-backed deployment, a second step towards lockout. See ADR 0028.",
			attempts)
	}
	if got := authenticationNodes(result); got != 1 {
		t.Errorf("kafka.sasl_authenticate nodes = %d, want 1", got)
	}
	s.dialer.requireBalanced(t)
}

// TestSelectionIsDeterministicAcrossRuns pins that "one path" is also "the same
// path", which is what makes the choice reviewable.
//
// Canonical address order is a tie-break among paths that were **all** measured
// through TLS, ApiVersions and the SASL handshake before anything was selected.
// It is not a preference for a family, and nothing here depends on which
// listener answered first.
func TestSelectionIsDeterministicAcrossRuns(t *testing.T) {
	ca := newAuthority(t)

	var chosen []string
	for range 4 {
		lower := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})
		higher := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})

		s := &scenario{
			host: bootstrapCanaryHost, port: lower.addr.Port(),
			resolver: tableResolver{bootstrapCanaryHost: {addrSibling, addrPrimary}},
			dialer: &routingDialer{routes: map[netip.Addr]route{
				// The canonically smaller synthetic address routes to `lower`.
				addrPrimary: {to: lower.addr},
				addrSibling: {to: higher.addr},
			}},
			tls:        &transport.TLSOptions{RootCAs: ca.pool},
			credential: credentialFor(t, bootstrapCanaryHost, lower.addr.Port()),
		}
		result := s.run(t)
		lower.awaitIdle(t)
		higher.awaitIdle(t)

		if len(lower.sasl()) != 1 || len(higher.sasl()) != 0 {
			t.Fatalf("the canonically smallest address was not the authenticated one: "+
				"lower=%d higher=%d", len(lower.sasl()), len(higher.sasl()))
		}
		// The address, not the endpoint: each iteration starts fresh listeners
		// on fresh ports, so the port is the test's own noise. What must not
		// vary is *which resolved address* received the credential.
		chosen = append(chosen, authenticatedAddress(t, result))
		s.dialer.requireBalanced(t)
	}

	for _, address := range chosen[1:] {
		if address != chosen[0] {
			t.Errorf("selection is not deterministic: %v", chosen)
			break
		}
	}
	if chosen[0] != addrPrimary.String() {
		t.Errorf("selection chose %s, want the canonically smallest address %s",
			chosen[0], addrPrimary)
	}
}

// TestAFailedPathIsNeverAuthenticated covers the sibling case.
//
// One address refuses at TCP and the other works. The refusal is evidence, the
// working path is selected, and the credential goes to exactly one place —
// the place that could receive it.
func TestAFailedPathIsNeverAuthenticated(t *testing.T) {
	ca := newAuthority(t)
	working := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})

	s := &scenario{
		host: bootstrapCanaryHost, port: working.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrRefused, addrPrimary}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: working.addr},
			addrRefused: {}, // refuses
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, working.addr.Port()),
	}
	result := s.run(t)
	working.awaitIdle(t)

	if len(working.sasl()) != 1 {
		t.Errorf("the usable path received %d authentications, want 1", len(working.sasl()))
	}
	if got := authenticationNodes(result); got != 1 {
		t.Errorf("kafka.sasl_authenticate nodes = %d, want 1", got)
	}
	// The refused address kept its evidence rather than being forgotten.
	if !hasNode(result, vocabulary.StepTCPConnect, domain.StateFail) {
		t.Error("the refused address produced no failing tcp.connect node")
	}
	s.dialer.requireBalanced(t)
}

// --- D, E. a path that is not usable is not selectable ----------------------

// TestATLSFailureSendsNoKafkaByte proves the strongest form of the transport
// gate: not that a broken path is filtered out downstream, but that it never
// becomes a path at all.
//
// The peer accepts TCP and presents a certificate for a name nobody asked about.
// The handshake fails, the chain hands back no continuation, and the Kafka
// adapter is never called for that address — so the peer sees no Kafka byte.
func TestATLSFailureSendsNoKafkaByte(t *testing.T) {
	ca := newAuthority(t)
	broken := newPeer(t, ca, peerConfig{
		serverName:     bootstrapCanaryHost,
		certificateFor: "somebody-else.canary.svcdoctor.test",
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: broken.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broken.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, broken.addr.Port()),
	}
	result := s.run(t)
	broken.awaitIdle(t)

	if got := broken.bytes(); got != 0 {
		t.Errorf("a peer whose TLS failed received %d application bytes, want 0", got)
	}
	if len(broken.sasl()) != 0 {
		t.Error("a peer whose TLS failed received a credential")
	}
	if got := authenticationNodes(result); got != 0 {
		t.Errorf("kafka.sasl_authenticate nodes = %d, want 0", got)
	}
	// The failure is owned, not silent. This is the ADR 0053 rule firing on the
	// producer Phase 6.1c introduced.
	assertFinding(t, result, "TLS_IDENTITY_MISMATCH")
	s.dialer.requireBalanced(t)
}

// TestATLSFailureOnOneAddressStillAuthenticatesTheOther is the mixed case, and
// it pins two decisions at once.
//
// The endpoint-scoped TLS finding fires for the broken address **even though a
// sibling succeeded** — ADR 0053 section 3 refuses partial-success withholding,
// because a certificate is presented by an endpoint and a client may select that
// endpoint. And the credential goes to the working path only.
func TestATLSFailureOnOneAddressStillAuthenticatesTheOther(t *testing.T) {
	ca := newAuthority(t)
	broken := newPeer(t, ca, peerConfig{
		serverName:     bootstrapCanaryHost,
		certificateFor: "somebody-else.canary.svcdoctor.test",
	})
	working := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})

	s := &scenario{
		host: bootstrapCanaryHost, port: working.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary, addrSibling}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broken.addr},
			addrSibling: {to: working.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, working.addr.Port()),
	}
	result := s.run(t)
	broken.awaitIdle(t)
	working.awaitIdle(t)

	if got := broken.bytes(); got != 0 {
		t.Errorf("the broken-TLS address received %d application bytes, want 0", got)
	}
	if len(working.sasl()) != 1 {
		t.Errorf("the usable address received %d authentications, want 1", len(working.sasl()))
	}
	assertFinding(t, result, "TLS_IDENTITY_MISMATCH")
	s.dialer.requireBalanced(t)
}

// TestALocallyTimedOutHandshakeIsNotSelected covers the UNKNOWN case, which is
// the one a filter written against `State != FAIL` would get wrong.
//
// The peer accepts TCP and never speaks TLS. The handshake ends UNKNOWN with a
// local class — svcdoctor's own budget, not the target's failure — so the path
// produces no continuation and receives no credential. The sibling does.
func TestALocallyTimedOutHandshakeIsNotSelected(t *testing.T) {
	ca := newAuthority(t)
	silent := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost, silent: true})
	working := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})

	s := &scenario{
		host: bootstrapCanaryHost, port: working.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary, addrSibling}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: silent.addr},
			addrSibling: {to: working.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, working.addr.Port()),
		timeout:    300 * time.Millisecond,
	}
	result := s.run(t)
	working.awaitIdle(t)

	if len(silent.sasl()) != 0 {
		t.Error("a path whose handshake never completed received a credential")
	}
	if len(working.sasl()) != 1 {
		t.Errorf("the usable path received %d authentications, want 1", len(working.sasl()))
	}
	// A local timeout is not a target failure, so no TLS finding is produced for
	// it, and the run says so at the run level instead.
	if !hasNode(result, vocabulary.StepTLSHandshake, domain.StateUnknown) {
		t.Error("the silent peer produced no UNKNOWN tls.handshake node")
	}
	for _, f := range result.Report().Findings() {
		if f.Code() == "TLS_HANDSHAKE_NOT_COMPLETED" {
			t.Error("a local timeout was reported as a target-side TLS failure")
		}
	}
}

// --- F, G, H, S. the four authentication outcomes ---------------------------

// TestNoCredentialConfiguredSendsNothingAndSaysSo is the Kafka twin of
// PostgreSQL's `POSTGRES_CREDENTIAL_NOT_CONFIGURED` invariant.
//
// It is measured on a **plaintext** path deliberately. Plaintext is the one
// place an exact zero-transmission claim is available on svcdoctor's own socket:
// there is no close_notify alert to move the counter, so "the peer decoded
// exactly ApiVersions and SaslHandshake, and nothing else arrived" is the whole
// truth about what was written.
//
// Zero `SecretFor`, zero `Reveal` and zero authentication bytes, and the run
// still says what happened rather than reporting silence.
func TestNoCredentialConfiguredSendsNothingAndSaysSo(t *testing.T) {
	ca := newAuthority(t)
	broker := newPeer(t, ca, peerConfig{}) // plaintext

	s := &scenario{
		host: bootstrapCanaryHost, port: broker.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broker.addr},
		}},
		// No TLS plan and no credential.
	}
	result := s.run(t)
	broker.awaitIdle(t)

	if got := broker.keys(); !slices.Equal(got, []int16{keyAPIVersions, keySASLHandshake}) {
		t.Errorf("the peer decoded %v, want exactly [ApiVersions SaslHandshake]", got)
	}
	if len(broker.sasl()) != 0 {
		t.Error("a run holding no credential wrote authentication bytes")
	}
	assertClientWroteExactlyWhatArrived(t, s.dialer, broker)
	assertAuthOutcome(t, result, domain.StateSkipped, domain.FailureExecRequiredInputMissing)

	// The three product facts, separately. An operator must be able to see that
	// nothing is broken, that the run finished, and that no session exists.
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK: no target-side problem was proven",
			result.Report().Summary().Status())
	}
	if result.Incomplete() {
		t.Error("a run that answered the question it was asked is not incomplete")
	}
	if hasNode(result, servicekafka.StepMetadata, domain.StatePass) {
		t.Error("Kafka metadata was obtained without a credential")
	}
	s.dialer.requireBalanced(t)
}

// TestAnUnsupportedMechanismSendsNothing pins Phase 6.1a's ordering through the
// composition.
//
// The peer offers only SCRAM-SHA-256 and the run asks for it. svcdoctor cannot
// perform it, and the guard runs **first** — before the credential is looked at,
// before the channel policy, before the endpoint binding, before `SecretFor` and
// before `Reveal`. So a run carrying a perfectly good credential over verified
// TLS still transmits nothing.
//
// The outcome is UNKNOWN rather than FAIL: a capability svcdoctor lacks is a gap
// in svcdoctor, not a defect in the target, and reporting it as a rejected
// credential would send an operator to a secret store for no reason.
func TestAnUnsupportedMechanismSendsNothing(t *testing.T) {
	ca := newAuthority(t)
	broker := newPeer(t, ca, peerConfig{mechanisms: []string{"SCRAM-SHA-256"}}) // plaintext

	s := &scenario{
		host: bootstrapCanaryHost, port: broker.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broker.addr},
		}},
		mechanism:  "SCRAM-SHA-256",
		credential: credentialFor(t, bootstrapCanaryHost, broker.addr.Port()),
	}
	result := s.run(t)
	broker.awaitIdle(t)

	if got := broker.keys(); !slices.Equal(got, []int16{keyAPIVersions, keySASLHandshake}) {
		t.Errorf("the peer decoded %v, want exactly [ApiVersions SaslHandshake]", got)
	}
	if len(broker.sasl()) != 0 {
		t.Error("a mechanism svcdoctor cannot perform still produced authentication bytes")
	}
	assertAuthOutcome(t, result, domain.StateUnknown, domain.FailureAuthMechanismUnsupported)

	// The mechanism gap outranks the channel policy. This run is on plaintext
	// with a credential configured, so a weaker ordering would have reported
	// EXEC_SKIPPED_BY_POLICY — which reads as "establish TLS and this will work",
	// and is false when svcdoctor cannot frame the exchange at all.
	if hasAuthClass(result, domain.FailureExecSkippedByPolicy) {
		t.Error("an unsupported mechanism was reported as a channel-policy refusal")
	}
	s.dialer.requireBalanced(t)
}

// TestAnUnverifiedChannelWithholdsTheCredential is the fail-closed transport
// policy, exercised through composition.
//
// A credential is configured, the mechanism is one svcdoctor can perform, and
// the broker is willing. The channel is plaintext, so nothing is written.
//
// **There is no Kafka bypass and no "the operator supplied it, so send it"
// branch.** The composition passes the policy through and does not second-guess
// it; the channel stays authoritative.
func TestAnUnverifiedChannelWithholdsTheCredential(t *testing.T) {
	ca := newAuthority(t)
	broker := newPeer(t, ca, peerConfig{}) // plaintext

	s := &scenario{
		host: bootstrapCanaryHost, port: broker.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broker.addr},
		}},
		credential: credentialFor(t, bootstrapCanaryHost, broker.addr.Port()),
	}
	result := s.run(t)
	broker.awaitIdle(t)

	if got := broker.keys(); !slices.Equal(got, []int16{keyAPIVersions, keySASLHandshake}) {
		t.Errorf("the peer decoded %v, want exactly [ApiVersions SaslHandshake]", got)
	}
	if len(broker.sasl()) != 0 {
		t.Error("a credential crossed an unverified channel")
	}
	assertClientWroteExactlyWhatArrived(t, s.dialer, broker)
	assertAuthOutcome(t, result, domain.StateSkipped, domain.FailureExecSkippedByPolicy)
	s.dialer.requireBalanced(t)
}

// TestARejectedCredentialIsAProblemAndNotSilence is the outcome that stopped the
// first attempt at this phase.
//
// Before Phase 6.1c-P2 a wrong password would have arrived as `findings: []`,
// `status: OK`, exit 0 — a rejected credential rendered as a clean bill of
// health. This asserts the opposite in the shape the report actually has.
func TestARejectedCredentialIsAProblemAndNotSilence(t *testing.T) {
	ca := newAuthority(t)
	broker := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost, rejectAuth: true})

	s := &scenario{
		host: bootstrapCanaryHost, port: broker.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broker.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, broker.addr.Port()),
	}
	result := s.run(t)
	broker.awaitIdle(t)

	assertAuthOutcome(t, result, domain.StateFail, domain.FailureAuthCredentialsRejected)
	if result.Report().Summary().Status() == domain.SummaryStatusOK {
		t.Error("a rejected credential produced status OK")
	}
	if len(result.Report().Findings()) == 0 {
		t.Fatal("a rejected credential produced no finding at all")
	}
	if result.Incomplete() {
		t.Error("a peer that answered is a complete run; the target refused, svcdoctor did not stop")
	}

	// One attempt, and no retry against the same or any other path.
	if len(broker.sasl()) != 1 {
		t.Errorf("a rejected credential was presented %d times, want 1", len(broker.sasl()))
	}
	s.dialer.requireBalanced(t)
}

// --- I, J. Metadata gates the sweep -----------------------------------------

// TestAFailedMetadataExchangeRunsNoAdvertisedSweep pins ADR 0051 section 15's
// gate.
//
// The peer authenticates and then hangs up mid-Metadata. There is no topology to
// measure, and the run must not invent one. The advertised endpoint in this
// scenario is a live listener, so a sweep that ran anyway would be visible as a
// connection at it.
func TestAFailedMetadataExchangeRunsNoAdvertisedSweep(t *testing.T) {
	ca := newAuthority(t)
	sibling := newPeer(t, ca, peerConfig{serverName: siblingCanaryHost, hostile: true})
	broker := newPeer(t, ca, peerConfig{
		serverName:    bootstrapCanaryHost,
		breakMetadata: true,
		advertised:    []brokerEntry{advertise(2, siblingCanaryHost, int32(sibling.addr.Port()))},
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: broker.addr.Port(),
		resolver: tableResolver{
			bootstrapCanaryHost: {addrPrimary},
			siblingCanaryHost:   {addrSibling},
		},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broker.addr},
			addrSibling: {to: sibling.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, broker.addr.Port()),
	}
	result := s.run(t)
	broker.awaitIdle(t)

	if got := sibling.connectionCount(); got != 0 {
		t.Errorf("the advertised endpoint received %d connections after a failed "+
			"Metadata exchange, want 0", got)
	}
	if hasNode(result, servicekafka.StepBrokerAdvertised, domain.StatePass) {
		t.Error("a broken Metadata exchange produced advertisements")
	}
	// The failure is owned. Phase 6.1c-P2's table covers kafka.metadata FAIL.
	if !hasNode(result, servicekafka.StepMetadata, domain.StateFail) {
		t.Error("the broken exchange produced no failing kafka.metadata node")
	}
	if result.Report().Summary().Status() == domain.SummaryStatusOK {
		t.Error("a failed Metadata exchange produced status OK")
	}
	s.dialer.requireBalanced(t)
}

// TestASuccessfulMetadataExchangeSweepsAdvertisedEndpoints is the positive
// counterpart, and it also pins that the advertised sweep verifies each endpoint
// against **its own** name.
//
// The sibling holds a certificate for its advertised hostname, not for the
// bootstrap's. A composition that copied the bootstrap's `ServerName` onto the
// advertised plan would report an identity mismatch here that no real client
// would ever see.
func TestASuccessfulMetadataExchangeSweepsAdvertisedEndpoints(t *testing.T) {
	ca := newAuthority(t)
	sibling := newPeer(t, ca, peerConfig{serverName: siblingCanaryHost, hostile: true})
	broker := newPeer(t, ca, peerConfig{
		serverName: bootstrapCanaryHost,
		advertised: []brokerEntry{advertise(2, siblingCanaryHost, int32(sibling.addr.Port()))},
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: broker.addr.Port(),
		resolver: tableResolver{
			bootstrapCanaryHost: {addrPrimary},
			siblingCanaryHost:   {addrSibling},
		},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broker.addr},
			addrSibling: {to: sibling.addr},
		}},
		// An explicit server name for the bootstrap, which must not travel.
		tls: &transport.TLSOptions{RootCAs: ca.pool, ServerName: bootstrapCanaryHost},
		credential: credentialFor(
			t, bootstrapCanaryHost, broker.addr.Port()),
	}
	result := s.run(t)
	broker.awaitIdle(t)
	sibling.awaitIdle(t)

	if sibling.connectionCount() == 0 {
		t.Fatal("the advertised endpoint was never measured")
	}
	if got := sibling.bytes(); got != 0 {
		t.Errorf("the advertised endpoint received %d application bytes, want 0", got)
	}
	// The handshake to the sibling completed, which is only possible if it was
	// verified against the advertised hostname rather than the bootstrap's.
	if !hasAdvertisedHandshake(result, domain.StatePass) {
		t.Error("the advertised TLS handshake did not pass.\n\n" +
			"An explicit --tls-server-name for the bootstrap endpoint must not be " +
			"applied to endpoints a peer named: it would verify every broker's " +
			"certificate against one name and report mismatches no client sees.")
	}
	if result.Incomplete() {
		t.Error("every advertisement was measured; the run is complete")
	}
	s.dialer.requireBalanced(t)
}

// --- the credential-authority input gate ------------------------------------

// TestACredentialBoundElsewhereIsRefusedBeforeAnyNetworkWork is ADR 0050
// section 4's "the composition root may not rebind", from the input side.
//
// `security.NewCredential` is unrestricted, so a credential naming an advertised
// broker, a resolved address or an unrelated host is constructible. The
// composition refuses one at the door: it costs the target zero connections and
// zero authentication attempts, and it is an input defect rather than a
// diagnostic result — so it comes back as an error and never as evidence.
func TestACredentialBoundElsewhereIsRefusedBeforeAnyNetworkWork(t *testing.T) {
	ca := newAuthority(t)
	broker := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})

	vantage, err := domain.NewLocalVantage("svcdoctor-composition-test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	dialer := &routingDialer{routes: map[netip.Addr]route{addrPrimary: {to: broker.addr}}}

	_, err = app.DiagnoseKafka(context.Background(), app.KafkaParams{
		Host: bootstrapCanaryHost, Port: broker.addr.Port(),
		Mechanism: "PLAIN",
		// Bound to the endpoint a hostile Metadata response would have named.
		Credential: credentialFor(t, hostileCanaryHost, broker.addr.Port()),
		Resolver:   tableResolver{bootstrapCanaryHost: {addrPrimary}},
		Dialer:     dialer,
		Vantage:    vantage,
		Version:    "0.0.0-composition-test",
	})
	if err == nil {
		t.Fatal("a credential bound to a different endpoint was accepted")
	}
	if broker.connectionCount() != 0 {
		t.Errorf("the target received %d connections before the input was refused",
			broker.connectionCount())
	}
	if len(dialer.ledger()) != 0 {
		t.Error("a connection was opened for a run that could not be performed")
	}
}

// --- cancellation -----------------------------------------------------------

// TestACancelledRunIsIncompleteAndLeaksNothing pins the two things cancellation
// must do at once: stay visible, and release every socket.
func TestACancelledRunIsIncompleteAndLeaksNothing(t *testing.T) {
	ca := newAuthority(t)
	broker := newPeer(t, ca, peerConfig{serverName: bootstrapCanaryHost})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := &scenario{
		host: bootstrapCanaryHost, port: broker.addr.Port(),
		resolver: tableResolver{bootstrapCanaryHost: {addrPrimary}},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: broker.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, broker.addr.Port()),
	}
	result := s.runCtx(t, ctx)

	if !result.Incomplete() {
		t.Error("a cancelled run reported itself complete")
	}
	if len(broker.sasl()) != 0 {
		t.Error("a cancelled run still presented a credential")
	}
	// The anchor survives: a cancelled run still says what it was asked about.
	if !hasNode(result, vocabulary.StepTargetRequested, domain.StatePass) {
		t.Error("cancellation removed the requested-target anchor")
	}
	s.dialer.requireBalanced(t)
}

// --- shared assertions ------------------------------------------------------

func authenticationNodes(result app.Result) int {
	count := 0
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() == servicekafka.StepSASLAuthenticate {
			count++
		}
	}
	return count
}

// authenticatedAddress returns the resolved address the run presented its
// credential to.
func authenticatedAddress(t *testing.T, result app.Result) string {
	t.Helper()
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() != servicekafka.StepSASLAuthenticate {
			continue
		}
		endpoint, err := netip.ParseAddrPort(node.Subject().Ref())
		if err != nil {
			t.Fatalf("the authentication subject %q is not an endpoint: %v",
				node.Subject().Ref(), err)
		}
		return endpoint.Addr().String()
	}
	t.Fatal("no kafka.sasl_authenticate node was recorded")
	return ""
}

func assertAuthOutcome(
	t *testing.T, result app.Result, state domain.State, class domain.FailureClass,
) {
	t.Helper()

	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() != servicekafka.StepSASLAuthenticate {
			continue
		}
		if node.State() != state || node.FailureClass() != class {
			t.Errorf("kafka.sasl_authenticate is %s/%s, want %s/%s",
				node.State(), node.FailureClass(), state, class)
		}
		return
	}
	t.Errorf("no kafka.sasl_authenticate node was recorded; want %s/%s", state, class)
}

func hasAuthClass(result app.Result, class domain.FailureClass) bool {
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() == servicekafka.StepSASLAuthenticate && node.FailureClass() == class {
			return true
		}
	}
	return false
}

func hasNode(result app.Result, step domain.Step, state domain.State) bool {
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() == step && node.State() == state {
			return true
		}
	}
	return false
}

// hasAdvertisedHandshake reports whether a tls.handshake node beneath an
// advertisement reached the given state.
func hasAdvertisedHandshake(result app.Result, state domain.State) bool {
	graph := result.Report().Graph()
	for _, node := range graph.Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		for _, id := range descendants(graph, node.ID()) {
			child, _ := graph.Node(id)
			if child.Step() == vocabulary.StepTLSHandshake && child.State() == state {
				return true
			}
		}
	}
	return false
}

func assertAdvertised(t *testing.T, result app.Result, host string) {
	t.Helper()
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() == servicekafka.StepBrokerAdvertised &&
			bytes.Contains([]byte(node.Subject().Ref()), []byte(host)) {
			return
		}
	}
	t.Errorf("no advertisement was recorded for %s", host)
}

func assertFinding(t *testing.T, result app.Result, code domain.FindingCode) {
	t.Helper()
	for _, f := range result.Report().Findings() {
		if f.Code() == code {
			return
		}
	}
	var got []domain.FindingCode
	for _, f := range result.Report().Findings() {
		got = append(got, f.Code())
	}
	t.Errorf("no %s finding; got %v", code, got)
}

// descendants returns every node transitively beneath one node.
func descendants(graph domain.Graph, root domain.EvidenceID) []domain.EvidenceID {
	var out []domain.EvidenceID
	seen := map[domain.EvidenceID]bool{}

	var walk func(domain.EvidenceID)
	walk = func(id domain.EvidenceID) {
		for _, child := range graph.Children(id) {
			if seen[child] {
				continue
			}
			seen[child] = true
			out = append(out, child)
			walk(child)
		}
	}
	walk(root)
	return out
}

// --- redaction over the production composition ------------------------------

// TestAComposedKafkaReportRedactsWithoutLeaking runs the output boundary over a
// graph only `DiagnoseKafka` can produce.
//
// The per-layer redaction tests beside this file each build their evidence by
// hand. This one does not: it takes a **whole composed run** — anchor, bootstrap
// sweep, TLS, four protocol steps, Metadata, an advertisement the operator never
// named and its transport sweep — and pushes it through `redaction.Redact`.
//
// That is the case a hand-built fixture cannot cover, because the risk is
// composition-shaped: a field that is safe in isolation and identity-bearing
// once a run puts a real hostname in it, or a node kind that only exists when a
// bootstrap sweep and an advertised sweep are in one graph.
//
// Six canaries travel: the identity and the secret, the logical bootstrap host,
// the resolved address, the advertised hostname, and the attacker-controlled
// hostname a hostile Metadata response chose.
func TestAComposedKafkaReportRedactsWithoutLeaking(t *testing.T) {
	ca := newAuthority(t)
	hostile := newPeer(t, ca, peerConfig{serverName: hostileCanaryHost, hostile: true})
	bootstrap := newPeer(t, ca, peerConfig{
		serverName: bootstrapCanaryHost,
		advertised: []brokerEntry{
			advertise(2, hostileCanaryHost, int32(hostile.addr.Port())),
			advertise(3, siblingCanaryHost, 9093),
		},
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: bootstrap.addr.Port(),
		resolver: tableResolver{
			bootstrapCanaryHost: {addrPrimary},
			hostileCanaryHost:   {addrHostile},
			siblingCanaryHost:   {addrRefused},
		},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: bootstrap.addr},
			addrHostile: {to: hostile.addr},
			addrRefused: {},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, bootstrap.addr.Port()),
	}
	result := s.run(t)
	local := result.Report()

	// The local report is where the identity canaries live, and the credential
	// canaries must already be absent from it: a secret has no place in evidence
	// at any output mode, and redaction is not what keeps it out.
	localJSON := mustJSONString(t, local)
	for _, canary := range []string{bootstrapCanaryHost, hostileCanaryHost} {
		if !strings.Contains(localJSON, canary) {
			t.Fatalf("the local report does not contain %q; the test proves nothing", canary)
		}
	}
	for _, canary := range []string{secretCanary, identityCanary} {
		if strings.Contains(localJSON, canary) {
			t.Errorf("the LOCAL_FULL report contains credential material %q.\n\n"+
				"Redaction is not what keeps a secret out of a report; nothing "+
				"should have put one in.", canary)
		}
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("redaction.Redact: %v", err)
	}
	shareableJSON := mustJSONString(t, shareable)

	for _, canary := range []string{
		secretCanary, identityCanary,
		bootstrapCanaryHost, hostileCanaryHost, siblingCanaryHost,
		addrPrimary.String(), addrHostile.String(), addrRefused.String(),
	} {
		if strings.Contains(shareableJSON, canary) {
			t.Errorf("the shareable report leaks %q", canary)
		}
	}

	// Correlation survives: the same number of nodes, the same edges, the same
	// findings, and every evidence reference still resolves.
	if shareable.Graph().Len() != local.Graph().Len() {
		t.Errorf("shareable graph has %d nodes, local has %d",
			shareable.Graph().Len(), local.Graph().Len())
	}
	if shareable.FindingCount() != local.FindingCount() {
		t.Errorf("shareable report has %d findings, local has %d",
			shareable.FindingCount(), local.FindingCount())
	}
	for _, f := range shareable.Findings() {
		for _, ref := range f.EvidenceRefs() {
			if _, ok := shareable.Graph().Node(ref); !ok {
				t.Errorf("finding %s references %s, which the redacted graph does not hold",
					f.Code(), ref)
			}
		}
	}

	// The diagnosis survives verbatim. A shareable report a reader cannot act on
	// is not a safer report, it is a useless one.
	localCodes := findingCodes(local)
	if !slices.Equal(findingCodes(shareable), localCodes) {
		t.Errorf("finding codes changed: %v -> %v", localCodes, findingCodes(shareable))
	}
	for i, f := range shareable.Findings() {
		original := local.Findings()[i]
		if f.Severity() != original.Severity() || f.Confidence() != original.Confidence() ||
			f.Kind() != original.Kind() || f.VantageDependent() != original.VantageDependent() {
			t.Errorf("%s lost a semantic field in redaction", f.Code())
		}
	}

	// Idempotent: redacting a redacted report changes nothing.
	again, err := redaction.Redact(shareable)
	if err != nil {
		t.Fatalf("redacting a redacted report: %v", err)
	}
	if mustJSONString(t, again) != shareableJSON {
		t.Error("redaction is not idempotent over a composed Kafka report")
	}
}

func findingCodes(r domain.Report) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, r.FindingCount())
	for _, f := range r.Findings() {
		out = append(out, f.Code())
	}
	return out
}

func mustJSONString(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return string(encoded)
}

// TestTheGuardFileStillExists is the reciprocal of
// TestTheCompositionSecuritySuiteStillExists in
// kafka_production_reachability_test.go. See that test for why two files vouch
// for each other rather than one guarding itself.
func TestTheGuardFileStillExists(t *testing.T) {
	source, err := os.ReadFile("kafka_production_reachability_test.go")
	if err != nil {
		t.Fatalf("the Kafka production closure guard is missing: %v", err)
	}
	for _, required := range []string{
		"func TestExactlyOneProductionPackageReachesTheKafkaAdapter",
		"func TestExactlyOneKafkaCompositionEntryPointExists",
		"func TestTheCompositionWiresEveryOwnerOfWhatItCanProduce",
		"func TestTheCompositionMintsNoCredential",
		"func TestAtMostOneAuthenticationCallSiteExists",
		"func TestNoSharedSCRAMPackageExists",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("the closure guard no longer contains %q.\n\n"+
				"Weakening it to make a commit pass is the exact failure ADR 0054 "+
				"exists to prevent.", required)
		}
	}
}

// assertClientWroteExactlyWhatArrived compares svcdoctor's own socket writes
// against what the peer consumed.
//
// Two counters, deliberately. The peer's counts bytes that **arrived and were
// read**; the client's counts bytes that **left**. A careless write of credential
// material that never forms a legal Kafka frame moves the second and can leave
// the first untouched, so equality is the assertion that closes that gap.
//
// Plaintext only. On TLS the client counter includes record framing and a
// close_notify alert, and the two numbers are not comparable — see
// routingDialer.bytesWrittenByClient.
func assertClientWroteExactlyWhatArrived(t *testing.T, dialer *routingDialer, p *peer) {
	t.Helper()

	if written, arrived := dialer.bytesWrittenByClient(), p.bytes(); written != arrived {
		t.Errorf("svcdoctor wrote %d bytes and the peer consumed %d.\n\n"+
			"On a plaintext path those must be equal: a difference is a write that "+
			"never became a Kafka request, which is the shape a leaked credential has.",
			written, arrived)
	}
}
