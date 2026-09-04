package postgres

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The ADR 0044 acceptance matrix.
//
// The graphs are hand-built because the semantics are a pure function of graph
// shape, and because several rows — a handshake with two parents, a subject
// mismatch, a certificate outside its validity window — are states a real server
// cannot be asked to produce on demand. The shapes themselves come from
// internal/adapter/postgres rather than from the record's prose; the report-level
// claims are verified against real runs in internal/app and test/security.

// --- rows 2 to 7: the class mapping --------------------------------------------

func TestTheClassMapping(t *testing.T) {
	cases := []struct {
		name  string
		class domain.FailureClass
		want  domain.FindingCode
	}{
		{"row 2: peer did not speak TLS", domain.FailureTLSPeerNotTLS, CodeTLSUpgradeNotHonored},
		{"row 3: identity mismatch", domain.FailureTLSHostnameMismatch, CodeTLSIdentityMismatch},
		{"row 4: chain not trusted", domain.FailureTLSUnknownAuthority, CodeTLSChainNotTrusted},
		{"row 5: certificate expired", domain.FailureTLSCertificateExpired, CodeTLSCertificateNotValidNow},
		{"row 6: certificate not yet valid", domain.FailureTLSCertificateNotYetValid, CodeTLSCertificateNotValidNow},
		{"row 7: unclassified handshake failure", domain.FailureTLSHandshakeFailure, CodeTLSHandshakeFailed},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			graph := inBandTLS(t, domain.StateFail, c.class)

			finding := only(t, TLS(rctx(graph)))
			if got := finding.Code(); got != c.want {
				t.Fatalf("code = %s, want %s", got, c.want)
			}

			// Endpoint-scoped: the handshake's own concrete subject, never the
			// logical target and never rebuilt.
			if got := finding.Subject().Ref(); got != addr {
				t.Errorf("subject = %q, want the concrete endpoint %q", got, addr)
			}
			if got := finding.Layer(); got != domain.LayerTLS {
				t.Errorf("layer = %s, want L3", got)
			}

			// Both halves of the proof, and nothing else.
			refs := finding.EvidenceRefs()
			if len(refs) != 2 {
				t.Fatalf("refs = %v, want the negotiation and the handshake", refs)
			}
			want := map[domain.EvidenceID]bool{idSSL: true, idTLS: true}
			for _, ref := range refs {
				if !want[ref] {
					t.Errorf("unexpected reference %s", ref)
				}
			}

			// No other PostgreSQL rule reads this graph.
			if got := len(allFindings(graph)); got != 1 {
				t.Errorf("the whole rule set produced %d findings, want 1: %v",
					got, codesOf(allFindings(graph)))
			}
		})
	}
}

// TestTheSemanticFieldsArePinnedPerCode makes each value an explicit decision.
//
// ADR 0044 §7 says all five are vantage-dependent and states a ground for each.
// Asserting the values per code rather than in a loop over one constant means a
// future change to any one of them has to be written down here.
func TestTheSemanticFieldsArePinnedPerCode(t *testing.T) {
	cases := []struct {
		class domain.FailureClass
		code  domain.FindingCode
	}{
		{domain.FailureTLSPeerNotTLS, CodeTLSUpgradeNotHonored},
		{domain.FailureTLSHostnameMismatch, CodeTLSIdentityMismatch},
		{domain.FailureTLSUnknownAuthority, CodeTLSChainNotTrusted},
		{domain.FailureTLSCertificateExpired, CodeTLSCertificateNotValidNow},
		{domain.FailureTLSCertificateNotYetValid, CodeTLSCertificateNotValidNow},
		{domain.FailureTLSHandshakeFailure, CodeTLSHandshakeFailed},
	}

	for _, c := range cases {
		t.Run(string(c.code)+"/"+c.class.String(), func(t *testing.T) {
			finding := only(t, TLS(rctx(inBandTLS(t, domain.StateFail, c.class))))

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
				t.Error("vantageDependent = false; ADR 0044 section 7 states a ground for true " +
					"on every one of these")
			}
			if finding.Discriminator() != "" {
				t.Errorf("a CONFIRMED finding carries discriminator %q", finding.Discriminator())
			}
			if got := len(finding.Recommendations()); got != 1 {
				t.Errorf("got %d recommendations, want exactly 1", got)
			}
		})
	}
}

// --- rows 1, 12 to 14: states that are not a failure ---------------------------

func TestNonFailingHandshakesProduceNothing(t *testing.T) {
	cases := []struct {
		name  string
		state domain.State
		class domain.FailureClass
	}{
		{"row 1: the handshake succeeded", domain.StatePass, domain.FailureNone},
		{"row 12: unknown", domain.StateUnknown, domain.FailureNone},
		{"row 13: cancelled", domain.StateUnknown, domain.FailureExecCancelled},
		{"row 14: budget expired", domain.StateUnknown, domain.FailureExecLocalTimeout},
		{"skipped", domain.StateSkipped, domain.FailureExecSkippedPrerequisiteFailed},
		// A shape no producer emits, included to isolate the state check from
		// the closed mapping. Every state above carries a class the mapping
		// rejects anyway, so without these rows a rule that accepted UNKNOWN
		// would still pass — the two conditions would be testing each other.
		{"unknown carrying a mapped class", domain.StateUnknown, domain.FailureTLSHostnameMismatch},
		{"skipped carrying a mapped class", domain.StateSkipped, domain.FailureTLSPeerNotTLS},
		{"degraded carrying a mapped class", domain.StateDegraded, domain.FailureTLSUnknownAuthority},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			graph := inBandTLS(t, c.state, c.class)
			if got := TLS(rctx(graph)); len(got) != 0 {
				t.Errorf("got %v, want no finding", codesOf(got))
			}
		})
	}
}

// TestAnUnauthorizedClassProducesNothing pins the closed mapping at the rule.
//
// The three unproduced TLS classes matter most: they exist in the domain, and a
// rule that folded anything unrecognized into the floor would give them a claim
// the moment a producer appeared, with no review.
func TestAnUnauthorizedClassProducesNothing(t *testing.T) {
	for _, class := range []domain.FailureClass{
		domain.FailureTLSVersionMismatch,
		domain.FailureTLSClientCertificateRequired,
		domain.FailureTLSClientCertificateRejected,
		domain.FailureProtocolPeerClosed,
		domain.FailureAuthCredentialsRejected,
	} {
		t.Run(class.String(), func(t *testing.T) {
			if got := TLS(rctx(inBandTLS(t, domain.StateFail, class))); len(got) != 0 {
				t.Errorf("got %v, want no finding", codesOf(got))
			}
		})
	}
}

// --- rows 8 to 11: endpoint scope ----------------------------------------------

// multiPath builds two independent endpoints under one run, each with its own
// negotiation and handshake.
func multiPath(t *testing.T, outcomes ...struct {
	address string
	state   domain.State
	class   domain.FailureClass
},
) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	for _, o := range outcomes {
		// The identifier derives from the address, exactly as the producers'
		// does. Deriving it from loop position instead would make a reordered
		// argument list a *different* graph rather than the same one built in a
		// different order, and the determinism test below would then be
		// measuring the fixture.
		ssl := b.add(nodeSpec{
			id: "postgres.ssl_request/db.internal:5432/" + o.address, subject: o.address,
			layer: domain.LayerTLS, step: servicepostgres.StepSSLRequest,
			state: domain.StatePass, class: domain.FailureNone,
			attrs: map[domain.AttributeKey]domain.AttrValue{
				servicepostgres.AttrSSLOffered: domain.BoolAttr(true),
			},
		})
		b.add(nodeSpec{
			id: "tls.handshake/db.internal:5432/" + o.address, subject: o.address,
			layer: domain.LayerTLS, step: vocabulary.StepTLSHandshake,
			state: o.state, class: o.class, parent: string(ssl),
		})
	}
	return b.freeze()
}

type pathOutcome = struct {
	address string
	state   domain.State
	class   domain.FailureClass
}

// TestAFailingEndpointIsDiagnosedEvenWhenAnotherSucceeds is the decision ADR 0044
// section 8 makes and the one most likely to be "corrected" later.
//
// ADR 0043's transport finding withholds when any path works, because its claim
// is about the requested target. This claim is about **this endpoint**, and a
// second endpoint working does not make it false. A dual-stack target whose IPv4
// address presents a bad certificate is a defect every client that selects IPv4
// will meet.
func TestAFailingEndpointIsDiagnosedEvenWhenAnotherSucceeds(t *testing.T) {
	graph := multiPath(t,
		pathOutcome{"10.0.0.5:5432", domain.StateFail, domain.FailureTLSHostnameMismatch},
		pathOutcome{"[2001:db8::1]:5432", domain.StatePass, domain.FailureNone},
	)

	finding := only(t, TLS(rctx(graph)))
	if got := finding.Code(); got != CodeTLSIdentityMismatch {
		t.Errorf("code = %s, want %s", got, CodeTLSIdentityMismatch)
	}
	if got := finding.Subject().Ref(); got != "10.0.0.5:5432" {
		t.Errorf("subject = %q, want the failing endpoint", got)
	}
}

// TestAFailingEndpointIsDiagnosedEvenWhenAnotherIsUnmeasured pins that an
// unmeasured path is not aggregated with a measured one.
func TestAFailingEndpointIsDiagnosedEvenWhenAnotherIsUnmeasured(t *testing.T) {
	graph := multiPath(t,
		pathOutcome{"10.0.0.5:5432", domain.StateFail, domain.FailureTLSPeerNotTLS},
		pathOutcome{"[2001:db8::1]:5432", domain.StateUnknown, domain.FailureExecCancelled},
	)

	finding := only(t, TLS(rctx(graph)))
	if got := finding.Subject().Ref(); got != "10.0.0.5:5432" {
		t.Errorf("subject = %q, want the failing endpoint", got)
	}
}

func TestEveryFailingEndpointGetsItsOwnFinding(t *testing.T) {
	t.Run("row 9: same class", func(t *testing.T) {
		graph := multiPath(t,
			pathOutcome{"10.0.0.5:5432", domain.StateFail, domain.FailureTLSUnknownAuthority},
			pathOutcome{"10.0.0.6:5432", domain.StateFail, domain.FailureTLSUnknownAuthority},
		)
		findings := TLS(rctx(graph))
		if len(findings) != 2 {
			t.Fatalf("got %d findings, want one per failing endpoint", len(findings))
		}
		for _, f := range findings {
			if f.Code() != CodeTLSChainNotTrusted {
				t.Errorf("code = %s, want %s", f.Code(), CodeTLSChainNotTrusted)
			}
		}
	})

	t.Run("row 10: mixed classes", func(t *testing.T) {
		graph := multiPath(t,
			pathOutcome{"10.0.0.5:5432", domain.StateFail, domain.FailureTLSCertificateExpired},
			pathOutcome{"10.0.0.6:5432", domain.StateFail, domain.FailureTLSPeerNotTLS},
		)
		findings := TLS(rctx(graph))
		if len(findings) != 2 {
			t.Fatalf("got %d findings, want one per failing endpoint", len(findings))
		}
		seen := map[domain.FindingCode]bool{}
		for _, f := range findings {
			seen[f.Code()] = true
		}
		if !seen[CodeTLSCertificateNotValidNow] || !seen[CodeTLSUpgradeNotHonored] {
			t.Errorf("codes = %v; each endpoint keeps its own class-specific claim",
				codesOf(findings))
		}
	})
}

// --- rows 15, 16, 21 to 26: ownership and malformed shapes ---------------------

// TestADeclinedNegotiationOwnsItsOwnFailure pins the separation from
// POSTGRES_TLS_DECLINED.
//
// When the negotiation fails the adapter records the handshake as SKIPPED and
// blocked by it. Two conditions exclude that independently: the handshake is not
// FAIL, and the parent is not PASS.
func TestADeclinedNegotiationOwnsItsOwnFailure(t *testing.T) {
	b := newBuilder(t)
	b.sslNode(domain.StateFail, domain.FailureProtocolUnsupportedCapability, boolPtr(false))
	b.add(nodeSpec{
		id: idTLS, subject: addr, layer: domain.LayerTLS,
		step: vocabulary.StepTLSHandshake, state: domain.StateSkipped,
		class: domain.FailureExecSkippedPrerequisiteFailed, parent: idSSL, blocker: idSSL,
	})
	graph := b.freeze()

	if got := TLS(rctx(graph)); len(got) != 0 {
		t.Errorf("the TLS rule produced %v; the negotiation owns this failure", codesOf(got))
	}
	finding := only(t, allFindings(graph))
	if got := finding.Code(); got != CodeTLSDeclined {
		t.Errorf("code = %s, want %s", got, CodeTLSDeclined)
	}
}

// TestAFailedHandshakeUnderAFailedNegotiationProducesNothing covers the shape no
// producer emits but a hand-built graph can.
func TestAFailedHandshakeUnderAFailedNegotiationProducesNothing(t *testing.T) {
	b := newBuilder(t)
	b.sslNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, nil)
	b.tlsNode(domain.StateFail, domain.FailureTLSPeerNotTLS)

	if got := TLS(rctx(b.freeze())); len(got) != 0 {
		t.Errorf("got %v; the negotiation did not pass, so nothing agreed to encrypt",
			codesOf(got))
	}
}

func TestMalformedShapesWithhold(t *testing.T) {
	fail := domain.FailureTLSHostnameMismatch

	t.Run("row 21: no parent", func(t *testing.T) {
		b := newBuilder(t)
		b.add(nodeSpec{
			id: idTLS, subject: addr, layer: domain.LayerTLS,
			step: vocabulary.StepTLSHandshake, state: domain.StateFail, class: fail,
		})
		if got := TLS(rctx(b.freeze())); len(got) != 0 {
			t.Errorf("got %v, want none", codesOf(got))
		}
	})

	t.Run("row 22: two parents", func(t *testing.T) {
		b := newBuilder(t)
		b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
		b.add(nodeSpec{
			id: idTCP, subject: addr, layer: domain.LayerTCP,
			step: vocabulary.StepTCPConnect, state: domain.StatePass, class: domain.FailureNone,
		})
		id := b.add(nodeSpec{
			id: idTLS, subject: addr, layer: domain.LayerTLS,
			step: vocabulary.StepTLSHandshake, state: domain.StateFail, class: fail, parent: idSSL,
		})
		if err := b.b.AddParent(id, domain.EvidenceID(idTCP)); err != nil {
			t.Fatalf("second parent: %v", err)
		}
		if got := TLS(rctx(b.freeze())); len(got) != 0 {
			t.Errorf("got %v; two layers cannot both own one execution", codesOf(got))
		}
	})

	t.Run("row 23: parent is a transport node", func(t *testing.T) {
		b := newBuilder(t)
		b.add(nodeSpec{
			id: idTCP, subject: addr, layer: domain.LayerTCP,
			step: vocabulary.StepTCPConnect, state: domain.StatePass, class: domain.FailureNone,
		})
		b.add(nodeSpec{
			id: idTLS, subject: addr, layer: domain.LayerTLS,
			step: vocabulary.StepTLSHandshake, state: domain.StateFail, class: fail, parent: idTCP,
		})
		if got := TLS(rctx(b.freeze())); len(got) != 0 {
			t.Errorf("got %v; this is generic transport TLS and belongs elsewhere", codesOf(got))
		}
	})

	t.Run("row 25: subject mismatch", func(t *testing.T) {
		b := newBuilder(t)
		b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
		b.add(nodeSpec{
			id: idTLS, subject: "10.0.0.99:5432", layer: domain.LayerTLS,
			step: vocabulary.StepTLSHandshake, state: domain.StateFail, class: fail, parent: idSSL,
		})
		if got := TLS(rctx(b.freeze())); len(got) != 0 {
			t.Errorf("got %v; the two nodes describe different endpoints", codesOf(got))
		}
	})

	t.Run("row 26: wrong layer", func(t *testing.T) {
		b := newBuilder(t)
		b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
		b.add(nodeSpec{
			id: idTLS, subject: addr, layer: domain.LayerProtocol,
			step: vocabulary.StepTLSHandshake, state: domain.StateFail, class: fail, parent: idSSL,
		})
		if got := TLS(rctx(b.freeze())); len(got) != 0 {
			t.Errorf("got %v; the node disagrees with itself", codesOf(got))
		}
	})
}

// TestRows27And28GenericAndDiscoveredHandshakesAreNotOwned reproduces the two
// shapes whose handshake hangs off a connection.
//
// Both are the same structural case — a `tcp.connect` parent — which is why one
// predicate excludes generic requested-target TLS and Kafka advertised TLS at
// once, without either being named.
func TestRows27And28GenericAndDiscoveredHandshakesAreNotOwned(t *testing.T) {
	for _, c := range []struct{ name, connect, handshake string }{
		{"generic requested target", "tcp.connect/db.internal:5432/10.0.0.5",
			"tls.handshake/db.internal:5432/10.0.0.5"},
		{"discovered sweep", "tcp.connect/advertised.abc/broker:9093/10.20.0.1",
			"tls.handshake/advertised.abc/broker:9093/10.20.0.1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newBuilder(t)
			b.add(nodeSpec{
				id: c.connect, subject: addr, layer: domain.LayerTCP,
				step: vocabulary.StepTCPConnect, state: domain.StatePass,
				class: domain.FailureNone,
			})
			b.add(nodeSpec{
				id: c.handshake, subject: addr, layer: domain.LayerTLS,
				step: vocabulary.StepTLSHandshake, state: domain.StateFail,
				class: domain.FailureTLSUnknownAuthority, parent: c.connect,
			})
			if got := TLS(rctx(b.freeze())); len(got) != 0 {
				t.Errorf("got %v, want none", codesOf(got))
			}
		})
	}
}

// --- rows 18 to 20: later stages keep their own findings ------------------------

func TestASucceedingHandshakeLeavesLaterStagesAlone(t *testing.T) {
	t.Run("row 18: bad credential", func(t *testing.T) {
		b := newBuilder(t)
		b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
		b.tlsNode(domain.StatePass, domain.FailureNone)
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "scram-sha-256")
		b.authNode(domain.StateFail, domain.FailureAuthCredentialsRejected, "28P01", boolPtr(true), "")
		graph := b.freeze()

		if got := TLS(rctx(graph)); len(got) != 0 {
			t.Errorf("the TLS rule produced %v on a passing handshake", codesOf(got))
		}
		if got := only(t, allFindings(graph)).Code(); got != CodeCredentialsRejected {
			t.Errorf("code = %s, want %s", got, CodeCredentialsRejected)
		}
	})

	t.Run("row 19: missing database", func(t *testing.T) {
		b := newBuilder(t)
		b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
		b.tlsNode(domain.StatePass, domain.FailureNone)
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "scram-sha-256")
		b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
		b.sessionNode(domain.StateFail, domain.FailureResourceNotFound, "3D000", boolPtr(true), idAuth)
		graph := b.freeze()

		if got := TLS(rctx(graph)); len(got) != 0 {
			t.Errorf("the TLS rule produced %v", codesOf(got))
		}
		if got := only(t, allFindings(graph)).Code(); got != CodeDatabaseNotFound {
			t.Errorf("code = %s, want %s", got, CodeDatabaseNotFound)
		}
	})

	t.Run("row 20: healthy", func(t *testing.T) {
		b := newBuilder(t)
		b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
		b.tlsNode(domain.StatePass, domain.FailureNone)
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "scram-sha-256")
		b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
		b.sessionNode(domain.StatePass, domain.FailureNone, "", nil, idAuth)

		if got := allFindings(b.freeze()); len(got) != 0 {
			t.Errorf("a healthy run produced %v", codesOf(got))
		}
	})
}

// --- row 30: determinism -------------------------------------------------------

// TestOutputIsIndependentOfInsertionOrder pins that the rule's own output does
// not depend on how the graph was assembled.
func TestOutputIsIndependentOfInsertionOrder(t *testing.T) {
	forward := multiPath(t,
		pathOutcome{"10.0.0.5:5432", domain.StateFail, domain.FailureTLSPeerNotTLS},
		pathOutcome{"10.0.0.6:5432", domain.StateFail, domain.FailureTLSUnknownAuthority},
	)
	reversed := multiPath(t,
		pathOutcome{"10.0.0.6:5432", domain.StateFail, domain.FailureTLSUnknownAuthority},
		pathOutcome{"10.0.0.5:5432", domain.StateFail, domain.FailureTLSPeerNotTLS},
	)

	a, b := TLS(rctx(forward)), TLS(rctx(reversed))
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("got %d and %d findings, want 2 each", len(a), len(b))
	}
	for i := range a {
		if a[i].Subject().Ref() != b[i].Subject().Ref() || a[i].Code() != b[i].Code() {
			t.Errorf("position %d differs: %s/%s vs %s/%s", i,
				a[i].Code(), a[i].Subject().Ref(), b[i].Code(), b[i].Subject().Ref())
		}
	}
}

// --- claim discipline ----------------------------------------------------------

// everyTLSFinding produces one of each authorized code.
func everyTLSFinding(t *testing.T) []domain.Finding {
	t.Helper()

	var out []domain.Finding
	for _, class := range []domain.FailureClass{
		domain.FailureTLSPeerNotTLS,
		domain.FailureTLSHostnameMismatch,
		domain.FailureTLSUnknownAuthority,
		domain.FailureTLSCertificateExpired,
		domain.FailureTLSHandshakeFailure,
	} {
		out = append(out, TLS(rctx(inBandTLS(t, domain.StateFail, class)))...)
	}
	if len(out) != 5 {
		t.Fatalf("got %d findings, want one of each authorized code", len(out))
	}
	return out
}

// TestNoTLSFindingClaimsACauseItDidNotObserve is the prose guard.
//
// Each phrase is one an operator would act on and which the evidence does not
// support. "Proxy" and "load balancer" are the ones most likely to be added in
// good faith on TLS_PEER_NOT_TLS — that observation really is what a plaintext
// listener behind a rewrite looks like, and equally what several other things
// look like.
func TestNoTLSFindingClaimsACauseItDidNotObserve(t *testing.T) {
	banned := map[string]string{
		"firewall":            "svcdoctor observed no filtering",
		"load balancer":       "svcdoctor observed no topology",
		"proxy":               "a peer that does not speak TLS is not an observed proxy",
		"middlebox":           "nothing observed identifies an intermediary",
		"is not postgres":     "the endpoint's implementation was never established",
		"forged":              "nothing observed establishes intent",
		"malicious":           "nothing observed establishes intent",
		"misconfigured":       "svcdoctor observed values, never how they were produced",
		"renew":               "certificate lifecycle is not diagnosis",
		"clock is wrong":      "the comparison is reported, not adjudicated",
		"invalid certificate": "validity was evaluated against one context, not globally",
		"ca is broken":        "a chain that does not verify here may verify elsewhere",
	}

	for _, finding := range everyTLSFinding(t) {
		text := strings.ToLower(finding.Summary() + " " + finding.Detail())
		for _, r := range finding.Recommendations() {
			text += " " + strings.ToLower(r.Action())
		}
		for phrase, why := range banned {
			if strings.Contains(text, phrase) {
				t.Errorf("%s says %q: %s", finding.Code(), phrase, why)
			}
		}
	}
}

// TestTheTLSProseScanWouldCatchABannedPhrase is the control.
func TestTheTLSProseScanWouldCatchABannedPhrase(t *testing.T) {
	sample := strings.ToLower(
		"A proxy or load balancer is misconfigured, the firewall dropped it, the certificate " +
			"is forged, the ca is broken, an invalid certificate needs renew, the clock is " +
			"wrong, a middlebox intercepted it, and the peer is not postgres")
	for phrase := range map[string]bool{
		"firewall": true, "load balancer": true, "proxy": true, "middlebox": true,
		"is not postgres": true, "forged": true, "misconfigured": true, "renew": true,
		"clock is wrong": true, "invalid certificate": true, "ca is broken": true,
	} {
		if !strings.Contains(sample, phrase) {
			t.Errorf("the scan cannot see %q; the guard above is vacuous", phrase)
		}
	}
}

// TestTLSFindingsSurvivePseudonymization is FINDINGS.md's readability test.
//
// The certificate names, the requested identity and the validity window are all
// structured attributes on the cited node, where redaction transforms them. None
// of them may appear in prose, which is also what stops a shared report leaking
// through a sentence.
func TestTLSFindingsSurvivePseudonymization(t *testing.T) {
	for _, finding := range everyTLSFinding(t) {
		text := finding.Summary() + " " + finding.Detail()
		for _, r := range finding.Recommendations() {
			text += " " + r.Action()
		}
		for _, identity := range []string{"10.0.0.5", "db.internal", "5432"} {
			if strings.Contains(text, identity) {
				t.Errorf("%s puts %q in prose", finding.Code(), identity)
			}
		}
	}
}

// TestEveryTLSFindingNamesTheInBandContext pins the qualification that keeps the
// claims distinguishable from a generic transport TLS claim.
func TestEveryTLSFindingNamesTheInBandContext(t *testing.T) {
	for _, finding := range everyTLSFinding(t) {
		text := strings.ToLower(finding.Summary() + " " + finding.Detail())
		if !strings.Contains(text, "postgresql") && !strings.Contains(text, "encrypt") {
			t.Errorf("%s does not say the endpoint agreed to encrypt: %q",
				finding.Code(), finding.Summary())
		}
	}
}
