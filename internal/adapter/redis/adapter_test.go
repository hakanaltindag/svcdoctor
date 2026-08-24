package redis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/redis/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// canaryPassword is a value that appears nowhere else, so a test asserting its
// absence from a socket is asserting something a coincidence cannot satisfy.
//
//nolint:gosec // G101: a leak-test canary, not a credential.
const canaryPassword = "canary-pw-8c1f2e"

// --- HELLO normalization --------------------------------------------------

func TestHelloRecordsRedisIdentity(t *testing.T) {
	p := newPeer(t, behaviour{hello: helloRedis})
	result, builder := sessions(t, p)
	session := one(t, result)

	if !session.Hello().Answered() {
		t.Fatalf("HELLO did not answer: prefix %q", session.Hello().Prefix)
	}

	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if node.State() != domain.StatePass {
		t.Fatalf("hello state = %s, want PASS", node.State())
	}
	for key, want := range map[domain.AttributeKey]string{
		serviceredis.AttrServer:        "redis",
		serviceredis.AttrServerVersion: "8.2.1",
		serviceredis.AttrMode:          "standalone",
		serviceredis.AttrRole:          "master",
	} {
		got, ok := attr(t, node, key)
		if !ok || got != want {
			t.Errorf("%s = %q (present=%v), want %q", key, got, ok, want)
		}
	}
}

// TestHelloRecordsValkeyIdentity is the row that proves one adapter serves both.
//
// Same code path, same command, same assertions — a different self-description,
// carried through to the graph without a branch anywhere.
func TestHelloRecordsValkeyIdentity(t *testing.T) {
	p := newPeer(t, behaviour{hello: helloValkey})
	result, builder := sessions(t, p)
	_ = one(t, result)

	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	server, _ := attr(t, node, serviceredis.AttrServer)
	version, _ := attr(t, node, serviceredis.AttrServerVersion)
	if server != "valkey" || version != "8.1.1" {
		t.Fatalf("identity = %q/%q, want valkey/8.1.1", server, version)
	}
}

func TestHelloRecordsNoUnauthorizedAttribute(t *testing.T) {
	p := newPeer(t, behaviour{hello: helloRedis})
	result, builder := sessions(t, p)
	_ = one(t, result)

	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	authorized := map[domain.AttributeKey]bool{
		serviceredis.AttrServer:        true,
		serviceredis.AttrServerVersion: true,
		serviceredis.AttrProto:         true,
		serviceredis.AttrMode:          true,
		serviceredis.AttrRole:          true,
		serviceredis.AttrErrorPrefix:   true,
		serviceredis.AttrAuthRequired:  true,
	}
	for key := range node.Attributes() {
		if !authorized[key] {
			t.Errorf("hello node carries %s, which ADR 0066 section 4 does not authorize", key)
		}
	}
	for _, forbidden := range []string{"redis.id", "redis.modules", "redis.availability_zone"} {
		if _, ok := node.Attribute(domain.AttributeKey(forbidden)); ok {
			t.Errorf("hello node carries %s; it is parsed and discarded", forbidden)
		}
	}
}

func TestHelloRecordsClusterModeAsAnObservation(t *testing.T) {
	p := newPeer(t, behaviour{hello: helloCluster})
	result, builder := sessions(t, p)
	_ = one(t, result)

	graph := freeze(t, builder)
	node := nodeAt(t, graph, serviceredis.StepHello)
	if mode, _ := attr(t, node, serviceredis.AttrMode); mode != "cluster" {
		t.Fatalf("mode = %q, want cluster", mode)
	}
	if node.State() != domain.StatePass {
		t.Errorf("cluster mode must not change the state: got %s", node.State())
	}
	// No topology node exists, and none may.
	for _, n := range graph.Nodes() {
		if strings.Contains(n.Step().String(), "topology") ||
			strings.Contains(n.Step().String(), "shard") ||
			strings.Contains(n.Step().String(), "slot") {
			t.Errorf("cluster mode produced a topology node %s; v1 measures none", n.Step())
		}
	}
}

func TestHelloDetectsSentinel(t *testing.T) {
	p := newPeer(t, behaviour{hello: helloSentinel})
	result, builder := sessions(t, p)
	session := one(t, result)

	if !session.IsSentinel() {
		t.Fatal("mode=sentinel must be detected")
	}
	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if mode, _ := attr(t, node, serviceredis.AttrMode); mode != "sentinel" {
		t.Fatalf("mode = %q, want sentinel", mode)
	}
	if _, ok := attr(t, node, serviceredis.AttrRole); ok {
		t.Error("a Sentinel reply carries no role field; recording one would invent it")
	}
}

func TestHelloRecordsAuthRequired(t *testing.T) {
	p := newPeer(t, behaviour{hello: errNoAuth, requireAuth: true})
	result, builder := sessions(t, p)
	session := one(t, result)

	if !session.AuthRequired() {
		t.Fatal("NOAUTH must read as authentication required")
	}
	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if node.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN: the endpoint answered, but the identity "+
			"this step collects was not collected", node.State())
	}
	if node.FailureClass() != domain.FailureNone {
		t.Errorf("failure class = %s, want none: requiring a credential is not a failure",
			node.FailureClass())
	}
	if prefix, _ := attr(t, node, serviceredis.AttrErrorPrefix); prefix != "NOAUTH" {
		t.Errorf("error prefix = %q, want NOAUTH", prefix)
	}
}

// TestHelloUnsupportedIsACapabilityFactNotAFailure pins the pre-6.0 and proxy
// case ADR 0063 section 9 describes.
func TestHelloUnsupportedIsACapabilityFactNotAFailure(t *testing.T) {
	p := newPeer(t, behaviour{hello: errHelloUnknown})
	result, builder := sessions(t, p)
	session := one(t, result)

	if !session.Hello().Unsupported() {
		t.Fatalf("prefix %q must read as unsupported", session.Hello().Prefix)
	}
	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if node.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", node.State())
	}
	if node.FailureClass() != domain.FailureProtocolUnsupportedCapability {
		t.Errorf("failure class = %s, want PROTOCOL_UNSUPPORTED_CAPABILITY", node.FailureClass())
	}
	if _, ok := attr(t, node, serviceredis.AttrMode); ok {
		t.Error("mode must be absent when HELLO is unsupported: svcdoctor never found out")
	}
}

func TestHelloPeerCloseIsAFailure(t *testing.T) {
	p := newPeer(t, behaviour{hello: helloRedis, closeOn: "HELLO"})
	result, builder := sessions(t, p)
	if got := len(result.Sessions()); got != 0 {
		t.Fatalf("got %d sessions, want 0: a dead connection cannot be continued", got)
	}
	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if node.State() != domain.StateFail || node.FailureClass() != domain.FailureProtocolPeerClosed {
		t.Fatalf("state/class = %s/%s, want FAIL/PROTOCOL_PEER_CLOSED",
			node.State(), node.FailureClass())
	}
}

// TestHelloRecordsReplicaRoleAsAnObservation pins that a replica changes the
// recorded role and nothing else.
//
// The integration suite measures this against a real replica. This is the unit
// half, and it exists so the observation-only rule is pinned even when Docker is
// unavailable.
func TestHelloRecordsReplicaRoleAsAnObservation(t *testing.T) {
	p := newPeer(t, behaviour{hello: helloReplica})
	result, builder := sessions(t, p)
	_ = one(t, result)

	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if role, _ := attr(t, node, serviceredis.AttrRole); role != "replica" {
		t.Fatalf("observed role = %q, want replica", role)
	}
	if node.State() != domain.StatePass {
		t.Errorf("role=replica changed the state to %s; it is an observation", node.State())
	}
	if node.FailureClass() != domain.FailureNone {
		t.Errorf("role=replica produced the failure class %s", node.FailureClass())
	}
}

// --- the frame that leaves the socket -------------------------------------

// TestHelloPutsExactlyTheZeroArgumentFrameOnTheSocket is ADR 0064's structural
// defence measured on a real connection.
func TestHelloPutsExactlyTheZeroArgumentFrameOnTheSocket(t *testing.T) {
	p := newPeer(t, behaviour{hello: helloRedis})
	result, _ := sessions(t, p)
	_ = one(t, result)

	frames := p.frames()
	if len(frames) != 1 {
		t.Fatalf("got %d frames %q, want exactly 1", len(frames), frames)
	}
	if frames[0] != "*1\r\n$5\r\nHELLO\r\n" {
		t.Fatalf("HELLO frame on the wire was %q, want the bare zero-argument form", frames[0])
	}
}

// --- AUTH -----------------------------------------------------------------

func authParams(t *testing.T, username, password string) AuthParams {
	t.Helper()
	endpoint, err := security.NewEndpoint("endpoint.internal", 6379)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(endpoint, username, security.NewSecret(password))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return AuthParams{
		Endpoint:   endpoint,
		Credential: credential,
		Username:   username,
		// Every AUTH test states the permissive policy explicitly. The zero value
		// requires verified TLS and would skip the exchange, which is asserted
		// separately in TestAuthIsWithheldOnAPlaintextChannel.
		Policy: permissivePolicy,
	}
}

// permissivePolicy is a policy value that permits a plaintext channel.
//
// security.CredentialTransportPolicy has exactly one member, RequireVerifiedTLS,
// and every other integer denies. There is deliberately no way to construct a
// permissive one — which is the point of ADR 0029 section 7 — so these tests
// cannot fabricate one either, and the AUTH exchange is instead driven through
// the wire package directly where the channel is not in scope.
const permissivePolicy = security.CredentialTransportPolicy(0)

func TestAuthIsWithheldOnAPlaintextChannel(t *testing.T) {
	p := newPeer(t, behaviour{hello: errNoAuth, requireAuth: true})
	result, builder := sessions(t, p)
	session := one(t, result)

	if err := Authenticate(context.Background(), builder, session, authParams(t, "app", "pw")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	node := nodeAt(t, freeze(t, builder), serviceredis.StepAuthentication)
	if node.State() != domain.StateSkipped ||
		node.FailureClass() != domain.FailureExecSkippedByPolicy {
		t.Fatalf("state/class = %s/%s, want SKIPPED/EXEC_SKIPPED_BY_POLICY",
			node.State(), node.FailureClass())
	}
	if p.count("AUTH") != 0 {
		t.Fatalf("AUTH reached the socket %d time(s); a policy refusal must write zero "+
			"credential bytes", p.count("AUTH"))
	}
	for _, frame := range p.frames() {
		if strings.Contains(frame, "pw") {
			t.Fatalf("a credential byte reached the socket in %q", frame)
		}
	}
}

func TestAuthWithNoCredentialRecordsWhy(t *testing.T) {
	p := newPeer(t, behaviour{hello: errNoAuth, requireAuth: true})
	result, builder := sessions(t, p)
	session := one(t, result)

	if err := Authenticate(context.Background(), builder, session, AuthParams{}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	node := nodeAt(t, freeze(t, builder), serviceredis.StepAuthentication)
	if node.State() != domain.StateSkipped ||
		node.FailureClass() != domain.FailureExecRequiredInputMissing {
		t.Fatalf("state/class = %s/%s, want SKIPPED/EXEC_REQUIRED_INPUT_MISSING",
			node.State(), node.FailureClass())
	}
	if p.count("AUTH") != 0 {
		t.Fatal("no credential means no AUTH on the socket")
	}
}

// authParamsFor mints AuthParams whose credential is bound to one endpoint and
// whose run names another, which is the shape every credential-authority test
// needs and no other test needs.
func authParamsFor(t *testing.T, credentialHost string, credentialPort uint16,
	runHost string, runPort uint16, password string) AuthParams {
	t.Helper()
	bound, err := security.NewEndpoint(credentialHost, credentialPort)
	if err != nil {
		t.Fatalf("NewEndpoint(credential): %v", err)
	}
	named, err := security.NewEndpoint(runHost, runPort)
	if err != nil {
		t.Fatalf("NewEndpoint(run): %v", err)
	}
	credential, err := security.NewCredential(bound, "", security.NewSecret(password))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return AuthParams{
		Endpoint:   named,
		Credential: credential,
		Policy:     permissivePolicy,
	}
}

// TestAdapterRefusesACredentialBoundToAnotherEndpoint is the adapter half of the
// Redis credential-authority invariant.
//
// # Why a behavioural test and not a structural one
//
// `TestExactlyOneRedisRevealAndSecretForExist` proves that exactly one
// `SecretFor` call exists and that it lives in this file. It cannot prove that
// the call *decides* anything: replacing its argument with
// `params.Credential.Endpoint()` keeps the call, keeps the file, and asks the
// credential whether it is authorized for itself — which it always is. That
// mutation was measured to survive the whole suite, and this test is what ends
// it.
//
// The invariant: a credential authorized for one operator-named endpoint may not
// be presented at another, whatever intermediate layer changed the endpoint.
//
// Three things are asserted, and the third is the one that matters. The error
// identifies the authority refusal; no evidence node is recorded, because
// nothing was asked of the endpoint and a node would state a fact about a peer
// that was never addressed; and **zero credential bytes reach the socket**.
func TestAdapterRefusesACredentialBoundToAnotherEndpoint(t *testing.T) {
	for _, tt := range []struct {
		name           string
		credentialHost string
		credentialPort uint16
	}{
		{"a different host", "other.internal", 6379},
		{"the same host on a different port", "endpoint.internal", 6380},
		{"a resolved address cannot widen authority", "10.0.0.1", 6379},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := newPeer(t, behaviour{hello: errNoAuth, requireAuth: true})
			result, builder := sessions(t, p)
			session := one(t, result)

			err := Authenticate(context.Background(), builder, session,
				authParamsFor(t, tt.credentialHost, tt.credentialPort,
					"endpoint.internal", 6379, canaryPassword))

			if !errors.Is(err, security.ErrEndpointMismatch) {
				t.Fatalf("err = %v, want ErrEndpointMismatch.\n\n"+
					"A credential bound elsewhere must be refused by the adapter, not "+
					"quietly downgraded to an empty secret.", err)
			}
			for _, node := range freeze(t, builder).Nodes() {
				if node.Step() == serviceredis.StepAuthentication {
					t.Errorf("an endpoint mismatch recorded a %s node (%s/%s); a local "+
						"invocation error is not a fact about the endpoint",
						node.Step(), node.State(), node.FailureClass())
				}
			}
			if got := p.count("AUTH"); got != 0 {
				t.Fatalf("AUTH reached the socket %d time(s); an unauthorized endpoint "+
					"must receive zero credential bytes", got)
			}
			for _, frame := range p.frames() {
				if strings.Contains(frame, canaryPassword) {
					t.Fatalf("a credential byte reached the socket in %q", frame)
				}
			}
		})
	}
}

// TestLocalInvalidInputIsNotAPeerClose pins the truthfulness half.
//
// A refusal svcdoctor raises before writing anything must never be classified as
// the endpoint closing the connection. The two are different facts about
// different parties, and `PROTOCOL_PEER_CLOSED` on a socket that was never
// written to accuses a peer of something it did not do.
//
// This asserts the semantic result — the state and the failure class the
// classifier produces — rather than the name of the branch that produced it.
func TestLocalInvalidInputIsNotAPeerClose(t *testing.T) {
	obs := authObservation{
		outcome: authAttempted,
		err:     fmt.Errorf("%w: AUTH requires a credential", wire.ErrInvalidInput),
	}
	state, failureClass := obs.classify()

	if failureClass == domain.FailureProtocolPeerClosed {
		t.Fatal("a local input refusal was classified as PROTOCOL_PEER_CLOSED.\n\n" +
			"Nothing was written to the socket, so no peer behaviour was observed " +
			"and no class naming the peer may be used.")
	}
	if state == domain.StateFail {
		t.Errorf("state = FAIL; svcdoctor's own refusal did not prove a target failure")
	}
	if state != domain.StateUnknown || failureClass != domain.FailureExecRequiredInputMissing {
		t.Errorf("state/class = %s/%s, want UNKNOWN/EXEC_REQUIRED_INPUT_MISSING",
			state, failureClass)
	}
}

// TestPingIsSkippedWhenAuthenticationDidNotHold pins the layered short-circuit.
func TestPingIsSkippedWhenAuthenticationDidNotHold(t *testing.T) {
	p := newPeer(t, behaviour{hello: errNoAuth, requireAuth: true})
	result, builder := sessions(t, p)
	session := one(t, result)

	if err := Authenticate(context.Background(), builder, session, AuthParams{}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := Ping(context.Background(), builder, session, Params{}); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	graph := freeze(t, builder)
	node := nodeAt(t, graph, serviceredis.StepPing)
	if node.State() != domain.StateSkipped ||
		node.FailureClass() != domain.FailureExecSkippedPrerequisiteFailed {
		t.Fatalf("state/class = %s/%s, want SKIPPED/EXEC_SKIPPED_PREREQUISITE_FAILED",
			node.State(), node.FailureClass())
	}
	if p.count("PING") != 0 {
		t.Fatal("a skipped probe must not reach the socket")
	}
	if len(graph.BlockedBy(node.ID())) == 0 {
		t.Error("a skipped node must record what blocked it")
	}
}

// --- PING outcomes --------------------------------------------------------

func TestPingOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reply  string
		state  domain.State
		class  domain.FailureClass
		prefix string
	}{
		{"pong", "+PONG\r\n", domain.StatePass, domain.FailureNone, ""},
		{"noperm", errNoPerm, domain.StateUnknown, domain.FailureAuthzDenied, "NOPERM"},
		{"loading", errLoading, domain.StateUnknown,
			domain.FailureProtocolUnexpectedResponse, "LOADING"},
		{"masterdown", errMasterDown, domain.StateUnknown,
			domain.FailureProtocolUnexpectedResponse, "MASTERDOWN"},
		{"unknown prefix", errUnknownPrefix, domain.StateUnknown,
			domain.FailureProtocolUnexpectedResponse, "UNRECOGNIZED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPeer(t, behaviour{hello: helloRedis, ping: tc.reply})
			result, builder := sessions(t, p)
			session := one(t, result)

			if err := Ping(context.Background(), builder, session, Params{}); err != nil {
				t.Fatalf("Ping: %v", err)
			}
			node := nodeAt(t, freeze(t, builder), serviceredis.StepPing)
			if node.State() != tc.state || node.FailureClass() != tc.class {
				t.Fatalf("state/class = %s/%s, want %s/%s",
					node.State(), node.FailureClass(), tc.state, tc.class)
			}
			got, ok := attr(t, node, serviceredis.AttrErrorPrefix)
			if tc.prefix == "" {
				if ok {
					t.Errorf("a passing probe recorded the prefix %q", got)
				}
				return
			}
			if got != tc.prefix {
				t.Errorf("error prefix = %q, want %q", got, tc.prefix)
			}
		})
	}
}

// TestNoPeerMessageTextReachesTheGraph plants canaries in every error a peer can
// send during the journey and proves none of them becomes evidence.
func TestNoPeerMessageTextReachesTheGraph(t *testing.T) {
	const canary = "CANARY-s3cr3t-leak"
	p := newPeer(t, behaviour{
		hello: "-ERR unknown command 'HELLO', with args beginning with: '" + canary + "' \r\n",
		ping:  "-NOPERM User " + canary + " has no permissions to run the 'ping' command\r\n",
	})
	result, builder := sessions(t, p)
	session := one(t, result)
	if err := Ping(context.Background(), builder, session, Params{}); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	graph := freeze(t, builder)
	for _, node := range graph.Nodes() {
		rendered := node.ID().String() + " " + node.Subject().String()
		for key, value := range node.Attributes() {
			rendered += " " + string(key) + "=" + value.String()
		}
		if strings.Contains(rendered, canary) {
			t.Fatalf("peer message text reached the graph: %q", rendered)
		}
	}
}

// --- resource-limit refusal -----------------------------------------------

// TestOversizedReplyIsSvcdoctorsLimitNotThePeersDefect is ADR 0061 section 28's
// lesson at this layer.
func TestOversizedReplyIsSvcdoctorsLimitNotThePeersDefect(t *testing.T) {
	huge := "$536870912\r\n" // a declared half-gigabyte bulk, with nothing behind it
	p := newPeer(t, behaviour{hello: huge})
	_, builder := sessions(t, p)

	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if node.State() != domain.StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN", node.State())
	}
	if node.FailureClass() != domain.FailureExecUnsupportedBySvcdoctor {
		t.Fatalf("failure class = %s, want EXEC_UNSUPPORTED_BY_SVCDOCTOR; a legal reply "+
			"svcdoctor declines to read is svcdoctor's limit, not a peer defect",
			node.FailureClass())
	}
	if node.FailureClass() == domain.FailureProtocolMalformedResponse {
		t.Fatal("a resource refusal must never accuse the peer of malformed framing")
	}
}

func TestMalformedFramingIsThePeersDefect(t *testing.T) {
	p := newPeer(t, behaviour{hello: "%2\r\n+a\r\n+b\r\n"}) // a RESP3 map on a RESP2 connection
	_, builder := sessions(t, p)

	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if node.State() != domain.StateFail ||
		node.FailureClass() != domain.FailureProtocolMalformedResponse {
		t.Fatalf("state/class = %s/%s, want FAIL/PROTOCOL_MALFORMED_RESPONSE",
			node.State(), node.FailureClass())
	}
}

// --- the second HELLO -----------------------------------------------------

// TestIdentifyRecordsASecondScopedNode pins the shape ADR 0032 provides for.
func TestIdentifyRecordsASecondScopedNode(t *testing.T) {
	p := newPeer(t, behaviour{hello: errNoAuth, helloAfterAuth: helloRedis, requireAuth: true})
	result, builder := sessions(t, p)
	session := one(t, result)

	// Authenticate through the adapter so the node exists as Identify's parent.
	if err := Authenticate(context.Background(), builder, session, AuthParams{}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := Identify(context.Background(), builder, session, Params{}); err != nil {
		t.Fatalf("Identify: %v", err)
	}

	graph := freeze(t, builder)
	var hellos []domain.Evidence
	for _, node := range graph.Nodes() {
		if node.Step() == serviceredis.StepHello {
			hellos = append(hellos, node)
		}
	}
	if len(hellos) != 2 {
		t.Fatalf("got %d hello nodes, want 2: the second is a scoped node, never an "+
			"amendment of the first", len(hellos))
	}
	if hellos[0].ID() == hellos[1].ID() {
		t.Fatal("the two hello nodes share an identifier")
	}
	if p.count("HELLO") != 2 {
		t.Fatalf("HELLO reached the socket %d time(s), want 2", p.count("HELLO"))
	}
	for _, frame := range p.frames() {
		if strings.HasPrefix(frame, "*1\r\n$5\r\nHELLO") {
			continue
		}
		if strings.Contains(frame, "HELLO") {
			t.Fatalf("a HELLO frame carried arguments: %q", frame)
		}
	}
}

// TestStepTimeoutSurfacesAsALocalLimit pins that svcdoctor's own budget never
// becomes a claim about the endpoint.
func TestStepTimeoutSurfacesAsALocalLimit(t *testing.T) {
	// A peer that accepts the connection and never answers HELLO.
	silent := newPeer(t, behaviour{hello: "", closeOn: "\x00never"})

	builder := domain.NewGraphBuilder()
	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     "endpoint.internal",
		Port:     6379,
		Resolver: fixedResolver{addresses: parseAddrs(t, "10.0.0.1")},
		Dialer:   peerDialer{target: silent.addr},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = paths.Close() })

	result, err := Run(context.Background(), builder, paths.Continuations(),
		Params{ExchangeTimeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	node := nodeAt(t, freeze(t, builder), serviceredis.StepHello)
	if node.State() != domain.StateUnknown {
		t.Fatalf("state = %s, want UNKNOWN: a local budget is not a remote failure",
			node.State())
	}
	switch node.FailureClass() {
	case domain.FailureExecLocalTimeout, domain.FailureExecCancelled:
	default:
		t.Fatalf("failure class = %s, want a local execution class", node.FailureClass())
	}
}
