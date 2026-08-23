package transport

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// handshakeOutcome is one address's TLS result, beneath a passing connection.
type handshakeOutcome struct {
	address string
	state   domain.State
	class   domain.FailureClass
}

func tlsFail(address string, class domain.FailureClass) handshakeOutcome {
	return handshakeOutcome{address: address, state: domain.StateFail, class: class}
}

func tlsPass(address string) handshakeOutcome {
	return handshakeOutcome{address: address, state: domain.StatePass, class: domain.FailureNone}
}

func tlsUnknown(address string, class domain.FailureClass) handshakeOutcome {
	return handshakeOutcome{address: address, state: domain.StateUnknown, class: class}
}

func tlsSkipped(address string) handshakeOutcome {
	return handshakeOutcome{
		address: address,
		state:   domain.StateSkipped,
		class:   domain.FailureExecSkippedPrerequisiteFailed,
	}
}

// requestedTLS builds the shape the generic rule owns:
//
//	target.requested -> dns.lookup -> tcp.connect -> tls.handshake
func requestedTLS(t *testing.T, outcomes ...handshakeOutcome) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	anchor := b.anchor("db.example.com:5432")
	lookup := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
	for _, o := range outcomes {
		connect := b.connect(lookup, o.address, domain.StatePass, domain.FailureNone)
		handshake(b, connect, o.address, o.state, o.class)
	}
	return b.freeze()
}

// handshake mints a TLS node beneath a connection, with the concrete endpoint as
// its subject — which is what internal/probe/tls records.
func handshake(
	b *builder, parent domain.EvidenceID, address string,
	state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	b.t.Helper()
	return b.add(domain.EvidenceInput{
		ID:           domain.EvidenceID("tls.handshake/endpoint/" + address),
		Subject:      b.endpointSubject(address),
		Layer:        domain.LayerTLS,
		Step:         vocabulary.StepTLSHandshake,
		State:        state,
		FailureClass: class,
		StartedAt:    b.now,
	}, parent)
}

// TestAuthorizedTLSFailuresProduceTheirCode is the closed mapping, driven from
// the six FailureClasses internal/probe/tls actually produces.
func TestAuthorizedTLSFailuresProduceTheirCode(t *testing.T) {
	tests := []struct {
		class domain.FailureClass
		want  domain.FindingCode
	}{
		{domain.FailureTLSPeerNotTLS, CodeTLSEndpointDoesNotSpeakTLS},
		{domain.FailureTLSHostnameMismatch, CodeTLSIdentityMismatch},
		{domain.FailureTLSUnknownAuthority, CodeTLSChainNotTrusted},
		{domain.FailureTLSCertificateExpired, CodeTLSCertificateNotValidNow},
		{domain.FailureTLSCertificateNotYetValid, CodeTLSCertificateNotValidNow},
		{domain.FailureTLSHandshakeFailure, CodeTLSHandshakeNotCompleted},
	}

	for _, tt := range tests {
		t.Run(tt.class.String(), func(t *testing.T) {
			graph := requestedTLS(t, tlsFail("10.0.0.1:5432", tt.class))
			finding := requireOne(t, TLS(graph), tt.want)

			// Endpoint-scoped: the concrete peer that presented what was seen,
			// never the logical target.
			if got := finding.Subject().Ref(); got != "10.0.0.1:5432" {
				t.Errorf("subject = %q, want the concrete endpoint 10.0.0.1:5432", got)
			}
			if got := finding.Layer(); got != domain.LayerTLS {
				t.Errorf("layer = %s, want TLS", got)
			}
			if got := finding.Kind(); got != domain.FindingKindConfirmed {
				t.Errorf("kind = %s, want CONFIRMED", got)
			}
			if got := finding.Severity(); got != domain.SeverityError {
				t.Errorf("severity = %s, want ERROR", got)
			}
			if got := finding.Confidence(); got != domain.ConfidenceHigh {
				t.Errorf("confidence = %s, want HIGH", got)
			}
			if !finding.VantageDependent() {
				t.Error("vantageDependent = false; what an endpoint presents, and the " +
					"trust context and clock it is judged against, are all local")
			}

			// The handshake and its connection, and nothing above them.
			refs := finding.EvidenceRefs()
			if len(refs) != 2 {
				t.Fatalf("refs = %v, want exactly the handshake and its connection", refs)
			}
			for _, ref := range refs {
				if _, ok := graph.Node(ref); !ok {
					t.Errorf("ref %s does not resolve in the graph", ref)
				}
				if strings.Contains(string(ref), "dns.lookup") ||
					strings.Contains(string(ref), "target.requested") {
					t.Errorf("ref %s cites the lookup or the anchor; this finding makes "+
						"no resolution claim and no claim about the logical target", ref)
				}
			}
		})
	}
}

// TestTLSPassProducesNothing is the base case.
func TestTLSPassProducesNothing(t *testing.T) {
	requireNone(t, TLS(requestedTLS(t, tlsPass("10.0.0.1:5432"))))
}

// TestLocalExecutionOutcomesProduceNoTLSClaim is the safety boundary.
//
// A cancelled or budget-exhausted handshake learned nothing about the endpoint.
// Turning either into a TLS claim is the local-timeout-as-remote-failure mistake
// the claim discipline exists to prevent; they reach Result.Incomplete through
// the application boundary instead. A SKIPPED handshake was blocked by a failed
// prerequisite, which docs/FINDINGS.md forbids citing as a cause.
func TestLocalExecutionOutcomesProduceNoTLSClaim(t *testing.T) {
	for _, tt := range []struct {
		name    string
		outcome handshakeOutcome
	}{
		{"local timeout", tlsUnknown("10.0.0.1:5432", domain.FailureExecLocalTimeout)},
		{"cancelled", tlsUnknown("10.0.0.1:5432", domain.FailureExecCancelled)},
		{"skipped by prerequisite", tlsSkipped("10.0.0.1:5432")},

		// **The state gate, tested on its own.** The three rows above carry
		// execution classes, which the closed mapping rejects anyway — so they
		// would still pass if the state check were removed, and would prove
		// only that the mapping works. These carry an *authorized* TLS class
		// with a non-FAIL state, so nothing but the state check stands between
		// them and a finding. A mutation relaxing that check is caught here and
		// nowhere else.
		{"UNKNOWN carrying a TLS class",
			tlsUnknown("10.0.0.1:5432", domain.FailureTLSHostnameMismatch)},
		{"SKIPPED carrying a TLS class",
			handshakeOutcome{
				address: "10.0.0.1:5432",
				state:   domain.StateSkipped,
				class:   domain.FailureTLSUnknownAuthority,
			}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requireNone(t, TLS(requestedTLS(t, tt.outcome)))
		})
	}
}

// TestUnproducedAndUnknownClassesProduceNothing pins the closed mapping.
//
// The three declared-but-unproduced classes must not gain a claim, and neither
// must a class added to the domain later. A default branch folding anything
// unrecognized into the floor would grant a new producer a claim nobody
// reviewed, and the floor's "could not attribute" wording would become a
// statement about a class that may be perfectly attributable.
func TestUnproducedAndUnknownClassesProduceNothing(t *testing.T) {
	for _, class := range []domain.FailureClass{
		domain.FailureTLSVersionMismatch,
		domain.FailureTLSClientCertificateRequired,
		domain.FailureTLSClientCertificateRejected,
		// Not a TLS class at all, standing in for one added later.
		domain.FailureProtocolMalformedResponse,
	} {
		t.Run(class.String(), func(t *testing.T) {
			requireNone(t, TLS(requestedTLS(t, tlsFail("10.0.0.1:5432", class))))
		})
	}
}

// TestAPassingSiblingDoesNotSuppressAFailingEndpoint is the endpoint-scope
// decision, and it is the one place this rule deliberately differs from DNS and
// TCP beside it.
//
// Those aggregate at the anchor and withhold on partial success, because their
// claims are about reachability and one working path falsifies the negative. A
// certificate is presented by one endpoint, so a sibling succeeding cannot
// falsify what this one presented — and a client selecting the failing address
// gets the failure.
func TestAPassingSiblingDoesNotSuppressAFailingEndpoint(t *testing.T) {
	graph := requestedTLS(t,
		tlsPass("10.0.0.1:5432"),
		tlsFail("10.0.0.2:5432", domain.FailureTLSHostnameMismatch),
	)

	finding := requireOne(t, TLS(graph), CodeTLSIdentityMismatch)
	if got := finding.Subject().Ref(); got != "10.0.0.2:5432" {
		t.Errorf("subject = %q, want the failing endpoint", got)
	}
}

// TestEachFailingEndpointProducesItsOwnFinding: no aggregation.
func TestEachFailingEndpointProducesItsOwnFinding(t *testing.T) {
	graph := requestedTLS(t,
		tlsFail("10.0.0.1:5432", domain.FailureTLSUnknownAuthority),
		tlsFail("10.0.0.2:5432", domain.FailureTLSCertificateExpired),
	)

	findings := TLS(graph)
	if len(findings) != 2 {
		t.Fatalf("got %d findings %v, want one per failing endpoint",
			len(findings), codesOf(findings))
	}
	subjects := map[string]domain.FindingCode{}
	for _, f := range findings {
		subjects[f.Subject().Ref()] = f.Code()
	}
	if subjects["10.0.0.1:5432"] != CodeTLSChainNotTrusted {
		t.Errorf("10.0.0.1 got %s, want %s", subjects["10.0.0.1:5432"], CodeTLSChainNotTrusted)
	}
	if subjects["10.0.0.2:5432"] != CodeTLSCertificateNotValidNow {
		t.Errorf("10.0.0.2 got %s, want %s",
			subjects["10.0.0.2:5432"], CodeTLSCertificateNotValidNow)
	}
}

// TestPostgreSQLInBandTLSIsNotOwned proves disjointness structurally.
//
// PostgreSQL's handshake is a child of postgres.ssl_request, a *grandchild* of
// the connection, so it is never collected as a direct upgrade. There is no
// suppression, no precedence and no service-name check — the shape decides.
func TestPostgreSQLInBandTLSIsNotOwned(t *testing.T) {
	b := newBuilder(t)
	anchor := b.anchor("db.example.com:5432")
	lookup := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
	connect := b.connect(lookup, "10.0.0.1:5432", domain.StatePass, domain.FailureNone)
	negotiation := b.node(connect, "postgres.ssl_request/endpoint/10.0.0.1:5432",
		domain.Step("postgres.ssl_request"), domain.LayerTLS,
		domain.StatePass, domain.FailureNone)
	b.node(negotiation, "tls.handshake/endpoint/10.0.0.1:5432",
		vocabulary.StepTLSHandshake, domain.LayerTLS,
		domain.StateFail, domain.FailureTLSHostnameMismatch)

	requireNone(t, TLS(b.freeze()))
}

// TestPostgreSQLShapeStillProducesItsTransportFindings guards the regression the
// sweep change could have caused.
//
// collectSweep ignores a connect child it does not recognize rather than
// rejecting it. Rejecting would make every PostgreSQL sweep ill-formed and
// silence the DNS and TCP findings that already work.
func TestPostgreSQLShapeStillProducesItsTransportFindings(t *testing.T) {
	b := newBuilder(t)
	anchor := b.anchor("db.example.com:5432")
	lookup := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
	connect := b.connect(lookup, "10.0.0.1:5432",
		domain.StateFail, domain.FailureTCPConnectionRefused)
	b.node(connect, "postgres.ssl_request/endpoint/10.0.0.1:5432",
		domain.Step("postgres.ssl_request"), domain.LayerTLS,
		domain.StateSkipped, domain.FailureExecSkippedPrerequisiteFailed)

	graph := b.freeze()
	requireOne(t, TCP(graph), CodeConnectionNotEstablished)
	requireNone(t, TLS(graph))
}

// TestKafkaAdvertisedTLSIsNotOwned proves the other disjointness.
//
// The advertised sweep is the identical lookup/connect/handshake shape, so
// nothing shallower than the full chain separates it. Its lookup hangs off
// kafka.broker_advertised rather than a requested-target anchor, so it forms no
// sweep here at all — even though it sits transitively below a bootstrap target.
func TestKafkaAdvertisedTLSIsNotOwned(t *testing.T) {
	b := newBuilder(t)
	anchor := b.anchor("bootstrap.example.com:9093")
	bootstrapLookup := b.lookup(anchor, "bootstrap.example.com",
		domain.StatePass, domain.FailureNone)
	bootstrapConnect := b.connect(bootstrapLookup, "10.0.0.1:9093",
		domain.StatePass, domain.FailureNone)
	metadata := b.node(bootstrapConnect, "kafka.metadata/endpoint/10.0.0.1:9093",
		domain.Step("kafka.metadata"), domain.LayerTopology,
		domain.StatePass, domain.FailureNone)
	advertised := b.node(metadata, "kafka.broker_advertised/broker-2",
		domain.Step("kafka.broker_advertised"), domain.LayerTopology,
		domain.StatePass, domain.FailureNone)

	// The advertised sweep: the same three steps, a different parent.
	advLookup := b.lookup(advertised, "broker-2.internal",
		domain.StatePass, domain.FailureNone)
	advConnect := b.connect(advLookup, "10.0.0.9:9093",
		domain.StatePass, domain.FailureNone)
	b.node(advConnect, "tls.handshake/advertised/10.0.0.9:9093",
		vocabulary.StepTLSHandshake, domain.LayerTLS,
		domain.StateFail, domain.FailureTLSUnknownAuthority)

	requireNone(t, TLS(b.freeze()))
}

// TestMalformedShapesProduceNothing: a shape no producer makes is declined, not
// guessed at.
func TestMalformedShapesProduceNothing(t *testing.T) {
	t.Run("lookup parent is not the anchor", func(t *testing.T) {
		b := newBuilder(t)
		anchor := b.anchor("db.example.com:5432")
		other := b.node(anchor, "kafka.broker_advertised/broker-1",
			domain.Step("kafka.broker_advertised"), domain.LayerTopology,
			domain.StatePass, domain.FailureNone)
		lookup := b.lookup(other, "db.example.com", domain.StatePass, domain.FailureNone)
		connect := b.connect(lookup, "10.0.0.1:5432", domain.StatePass, domain.FailureNone)
		b.node(connect, "tls.handshake/endpoint/10.0.0.1:5432",
			vocabulary.StepTLSHandshake, domain.LayerTLS,
			domain.StateFail, domain.FailureTLSUnknownAuthority)

		requireNone(t, TLS(b.freeze()))
	})

	t.Run("two lookups under one anchor", func(t *testing.T) {
		b := newBuilder(t)
		anchor := b.anchor("db.example.com:5432")
		first := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
		b.lookup(anchor, "other.example.com", domain.StatePass, domain.FailureNone)
		connect := b.connect(first, "10.0.0.1:5432", domain.StatePass, domain.FailureNone)
		b.node(connect, "tls.handshake/endpoint/10.0.0.1:5432",
			vocabulary.StepTLSHandshake, domain.LayerTLS,
			domain.StateFail, domain.FailureTLSUnknownAuthority)

		requireNone(t, TLS(b.freeze()))
	})

	t.Run("handshake on the wrong layer", func(t *testing.T) {
		b := newBuilder(t)
		anchor := b.anchor("db.example.com:5432")
		lookup := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
		connect := b.connect(lookup, "10.0.0.1:5432", domain.StatePass, domain.FailureNone)
		b.node(connect, "tls.handshake/endpoint/10.0.0.1:5432",
			vocabulary.StepTLSHandshake, domain.LayerProtocol,
			domain.StateFail, domain.FailureTLSUnknownAuthority)

		requireNone(t, TLS(b.freeze()))
	})
}

// TestTLSFindingsAreDeterministic: same graph, same findings, same order.
func TestTLSFindingsAreDeterministic(t *testing.T) {
	graph := requestedTLS(t,
		tlsFail("10.0.0.2:5432", domain.FailureTLSCertificateExpired),
		tlsFail("10.0.0.1:5432", domain.FailureTLSUnknownAuthority),
		tlsPass("10.0.0.3:5432"),
	)

	first := codesOf(TLS(graph))
	for range 20 {
		next := codesOf(TLS(graph))
		if len(next) != len(first) {
			t.Fatalf("finding count varies: %v then %v", first, next)
		}
		for i := range first {
			if next[i] != first[i] {
				t.Fatalf("order varies: %v then %v", first, next)
			}
		}
	}
}

// TestTLSClaimProseStaysScopedToThisAttempt is the claim-discipline guard
// ADR 0053 section 6 makes mandatory.
//
// The codes are stable and concise, and a reader could take
// TLS_ENDPOINT_DOES_NOT_SPEAK_TLS for a capability claim about the endpoint in
// general. The prose is what stops that, so the prose is what is pinned.
//
// # Why it checks sentences, and why cues are whole words
//
// The safest prose *names* the claims it is not making — "it does not establish
// that the endpoint never speaks TLS", "a host whose clock is wrong ... are
// indistinguishable". A flat substring ban would fail exactly the wording it
// exists to encourage, so a banned phrase is a defect only in a sentence that
// asserts rather than disclaims.
//
// The cues are matched as whole words. A substring match would find "not" inside
// "another" and treat an ordinary assertion as a disclaimer, which is how this
// guard would quietly stop guarding.
func TestTLSClaimProseStaysScopedToThisAttempt(t *testing.T) {
	for class, claim := range tlsClaims {
		prose := strings.ToLower(claim.summary + ". " + claim.detail + ". " + claim.recommendation)
		for _, sentence := range splitSentences(prose) {
			if disclaims(sentence) {
				continue
			}
			for _, phrase := range forbiddenTLSPhrases {
				if strings.Contains(sentence, phrase) {
					t.Errorf("%s asserts %q in %q; the claim must stay an observation "+
						"scoped to this endpoint and this attempt", class, phrase,
						strings.TrimSpace(sentence))
				}
			}
		}
	}
}

// TestTheProseGuardIsNotVacuous proves the scan would catch a real regression,
// since a guard that passes everything protects nothing.
func TestTheProseGuardIsNotVacuous(t *testing.T) {
	// An assertive capability claim, with no disclaimer anywhere in it.
	offending := "this endpoint does support tls on a different port"

	if disclaims(offending) {
		t.Fatalf("the offending fixture reads as a disclaimer, so the scan would skip "+
			"it and this test would prove nothing: %q", offending)
	}
	caught := false
	for _, phrase := range forbiddenTLSPhrases {
		if strings.Contains(offending, phrase) {
			caught = true
		}
	}
	if !caught {
		t.Errorf("the scan would not flag %q; the forbidden list no longer covers a "+
			"plain capability claim", offending)
	}
}

// forbiddenTLSPhrases would turn an observation into a global or causal claim.
var forbiddenTLSPhrases = []string{
	"support tls", "cannot speak tls", "never speaks tls", "tls-capable",
	"wrong port", "proxy", "firewall", "load balancer",
	"man-in-the-middle", "mitm", "will fail", "always",
	"certificate is invalid", "chain is broken", "cipher",
}

// disclaims reports whether a sentence denies or withholds rather than asserts.
//
// Cues are whole words, so "another" is not read as "not".
func disclaims(sentence string) bool {
	cues := map[string]bool{
		"not": true, "never": true, "no": true, "nothing": true,
		"neither": true, "none": true, "nor": true,
		// Non-attribution markers: a sentence saying two causes cannot be told
		// apart is the opposite of asserting one of them.
		"indistinguishable": true, "identical": true, "may": true,
	}
	for _, word := range strings.FieldsFunc(strings.ToLower(sentence), func(r rune) bool {
		return r < 'a' || r > 'z'
	}) {
		if cues[word] {
			return true
		}
	}
	return false
}

// splitSentences breaks prose into sentence-sized pieces for the scan.
func splitSentences(prose string) []string {
	return strings.FieldsFunc(prose, func(r rune) bool {
		return r == '.' || r == '\n'
	})
}

// TestSensitiveClaimsNameTheLocalHalf pins the three details ADR 0053 section 7
// requires, because each is a claim a reader could otherwise take as being about
// the target alone.
func TestSensitiveClaimsNameTheLocalHalf(t *testing.T) {
	chain := strings.ToLower(tlsClaims[domain.FailureTLSUnknownAuthority].detail)
	for _, want := range []string{"trust", "this run"} {
		if !strings.Contains(chain, want) {
			t.Errorf("the chain-not-trusted detail does not mention %q; the trust context "+
				"is this run's and is frequently the half that is wrong", want)
		}
	}

	validity := strings.ToLower(tlsClaims[domain.FailureTLSCertificateExpired].detail)
	if !strings.Contains(validity, "clock") {
		t.Error("the certificate-validity detail does not mention the clock; the comparison " +
			"depends on the host's clock as much as on the certificate")
	}

	peer := strings.ToLower(tlsClaims[domain.FailureTLSPeerNotTLS].detail)
	for _, want := range []string{"this attempt", "vantage"} {
		if !strings.Contains(peer, want) {
			t.Errorf("the peer-not-TLS detail does not mention %q; without it the code "+
				"reads as a capability claim", want)
		}
	}

	floor := strings.ToLower(tlsClaims[domain.FailureTLSHandshakeFailure].detail)
	if !strings.Contains(floor, "not attribute") {
		t.Error("the floor detail does not say the cause was not attributed; the floor is " +
			"certain about non-completion and nothing else")
	}
}

// TestTheMappingCoversExactlyTheProducedClasses ties the table to the probe.
//
// If internal/probe/tls gains a producer for a class this table does not carry,
// the outcome would be a FAIL node with no finding — the silence ADR 0054
// forbids. If the table gains a class the probe cannot produce, it authorizes a
// claim for evidence that cannot occur.
func TestTheMappingCoversExactlyTheProducedClasses(t *testing.T) {
	produced := []domain.FailureClass{
		domain.FailureTLSPeerNotTLS,
		domain.FailureTLSHostnameMismatch,
		domain.FailureTLSUnknownAuthority,
		domain.FailureTLSCertificateExpired,
		domain.FailureTLSCertificateNotYetValid,
		domain.FailureTLSHandshakeFailure,
	}

	if len(tlsClaims) != len(produced) {
		t.Errorf("tlsClaims has %d entries, want %d — one per class the probe produces",
			len(tlsClaims), len(produced))
	}
	for _, class := range produced {
		if _, ok := tlsClaims[class]; !ok {
			t.Errorf("%s is produced by internal/probe/tls and has no claim; a FAIL node "+
				"with no finding is the silence ADR 0054 forbids", class)
		}
	}

	codes := map[domain.FindingCode]bool{}
	for _, claim := range tlsClaims {
		codes[claim.code] = true
	}
	if len(codes) != 5 {
		t.Errorf("the mapping yields %d codes, want exactly 5", len(codes))
	}
}
