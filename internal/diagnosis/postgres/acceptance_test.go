package postgres

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The ADR 0040 section 24 acceptance matrix, row for row.
//
// Every "no finding" row is a decision rather than an omission, and each is
// asserted as loudly as a positive row: a rule that started firing on transport
// evidence, on a healthy session, or on svcdoctor's own expired budget would
// fail here rather than in review.
//
// `want` is the empty code for the rows that must produce nothing.
func TestAcceptanceMatrix(t *testing.T) {
	const none domain.FindingCode = ""

	tests := []struct {
		row      string
		graph    func(b *builder)
		want     domain.FindingCode
		severity domain.Severity
		vantage  bool
	}{
		// --- postgres.ssl_request -----------------------------------------
		{
			row: "1 declined negotiation under a required-TLS plan",
			graph: func(b *builder) {
				b.sslNode(domain.StateFail, domain.FailureProtocolUnsupportedCapability, boolPtr(false))
			},
			want: CodeTLSDeclined, severity: domain.SeverityError, vantage: false,
		},
		{
			row: "2 an E-shaped answer to SSLRequest",
			graph: func(b *builder) {
				b.sslNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, nil)
			},
			want: none,
		},
		{
			row: "2b unsupported-capability with no answer recorded",
			graph: func(b *builder) {
				// The producer records postgres.ssl.offered only when a real
				// answer arrived, so this shape is "svcdoctor never found out"
				// and must not read as "the endpoint declined".
				b.sslNode(domain.StateFail, domain.FailureProtocolUnsupportedCapability, nil)
			},
			want: none,
		},
		{
			row: "3 the run asked for no TLS",
			graph: func(b *builder) {
				b.sslNode(domain.StateSkipped, domain.FailureExecSkippedByPolicy, nil)
			},
			want: none,
		},
		// --- generic transport, owned by nobody ---------------------------
		{
			row: "4 a TLS handshake failure",
			graph: func(b *builder) {
				b.add(nodeSpec{
					id: idTLS, subject: addr, layer: domain.LayerTLS, step: "tls.handshake",
					state: domain.StateFail, class: domain.FailureTLSUnknownAuthority,
				})
			},
			want: none,
		},
		{
			row: "6 a refused TCP connection",
			graph: func(b *builder) {
				b.add(nodeSpec{
					id: idTCP, subject: addr, layer: domain.LayerTCP, step: "tcp.connect",
					state: domain.StateFail, class: domain.FailureTCPConnectionRefused,
				})
			},
			want: none,
		},
		// --- postgres.startup ---------------------------------------------
		{
			row: "7 host-based access refusal at startup",
			graph: func(b *builder) {
				b.startupNode(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", boolPtr(true), "")
			},
			want: CodeConnectionNotPermitted, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "8 pooled 08P01 before authentication",
			graph: func(b *builder) {
				b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", boolPtr(false), "")
			},
			want: CodeStartupFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "9 the endpoint is not accepting connections",
			graph: func(b *builder) {
				b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "57P03", boolPtr(true), "")
			},
			want: CodeStartupFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "9b the peer closed during startup",
			graph: func(b *builder) {
				b.startupNode(domain.StateFail, domain.FailureProtocolPeerClosed, "", nil, "")
			},
			want: CodeStartupFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "10 an unsupported protocol version",
			graph: func(b *builder) {
				b.startupNode(domain.StateFail, domain.FailureProtocolUnsupportedVersion, "0A000", boolPtr(true), "")
			},
			want: CodeStartupFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "11 a 3D000 at startup is never database-not-found",
			graph: func(b *builder) {
				b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "3D000", boolPtr(true), "")
			},
			want: CodeStartupFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "12 a 42501 at startup is never connect-denied",
			graph: func(b *builder) {
				b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "42501", boolPtr(true), "")
			},
			want: CodeStartupFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "13 startup skipped by a failed prerequisite",
			graph: func(b *builder) {
				b.sslNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, nil)
				b.add(nodeSpec{
					id: idStartup, subject: addr, layer: domain.LayerProtocol,
					step: "postgres.startup", state: domain.StateSkipped,
					class: domain.FailureExecSkippedPrerequisiteFailed, parent: idSSL, blocker: idSSL,
				})
			},
			want: none,
		},
		// --- postgres.authentication --------------------------------------
		{
			row: "14 28P01",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureAuthCredentialsRejected, "28P01", boolPtr(true), "")
			},
			want: CodeCredentialsRejected, severity: domain.SeverityError, vantage: false,
		},
		{
			row: "15 a SCRAM refusal token, no SQLSTATE",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureAuthCredentialsRejected, "", nil, "")
			},
			want: CodeCredentialsRejected, severity: domain.SeverityError, vantage: false,
		},
		{
			row: "15c a server-signature mismatch",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureAuthPeerVerificationFailed, "", nil, "")
			},
			want: CodePeerVerificationFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "15d an encoding fault in the username field",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "", nil, "")
			},
			want: CodeAuthenticationFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "16 pooled 08P01 during authentication",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", boolPtr(false), "")
			},
			want: CodeAuthenticationFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "19 host-based access refusal during authentication",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", boolPtr(true), "")
			},
			want: CodeConnectionNotPermitted, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "20 the endpoint offers nothing svcdoctor performs",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureAuthMechanismNotOffered, "", nil, "")
			},
			want: CodeMechanismUnavailable, severity: domain.SeverityWarn, vantage: true,
		},
		{
			row: "21 the endpoint demands something svcdoctor cannot perform",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "md5")
				b.authNode(domain.StateUnknown, domain.FailureAuthMechanismUnsupported, "", nil, "")
			},
			want: CodeMechanismUnavailable, severity: domain.SeverityInfo, vantage: true,
		},
		{
			row: "22 a svcdoctor limitation during the mechanism",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor, "", nil, "")
			},
			want: CodeUnsupportedBySvcdoctor, severity: domain.SeverityInfo, vantage: true,
		},
		{
			row: "23 the credential-transport policy refused this channel",
			graph: func(b *builder) {
				b.sslNode(domain.StateSkipped, domain.FailureExecSkippedByPolicy, nil)
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateSkipped, domain.FailureExecSkippedByPolicy, "", nil, idSSL)
			},
			want: CodeCredentialWithheld, severity: domain.SeverityWarn, vantage: false,
		},
		{
			row: "24 svcdoctor's own budget expired during authentication",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateUnknown, domain.FailureExecLocalTimeout, "", nil, "")
			},
			want: none,
		},
		{
			row: "24b the run was cancelled during authentication",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateUnknown, domain.FailureExecCancelled, "", nil, "")
			},
			want: none,
		},
		// --- postgres.session ---------------------------------------------
		{
			row: "25 3D000 with a passing authentication parent",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
				b.sessionNode(domain.StateFail, domain.FailureResourceNotFound, "3D000", boolPtr(true), idAuth)
			},
			want: CodeDatabaseNotFound, severity: domain.SeverityError, vantage: false,
		},
		{
			row: "26 3D000 on the trust path",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "ok")
				b.sessionNode(domain.StateFail, domain.FailureResourceNotFound, "3D000", boolPtr(true), idStartup)
			},
			want: CodeDatabaseNotFound, severity: domain.SeverityError, vantage: false,
		},
		{
			row: "27 42501 in the session window",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
				b.sessionNode(domain.StateFail, domain.FailureAuthzDenied, "42501", boolPtr(true), idAuth)
			},
			want: CodeDatabaseConnectDenied, severity: domain.SeverityError, vantage: false,
		},
		{
			row: "28 a connection-limit refusal",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
				b.sessionNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "53300", boolPtr(true), idAuth)
			},
			want: CodeSessionEstablishmentFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "28b an 08P01 in the session window",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
				b.sessionNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", boolPtr(false), idAuth)
			},
			want: CodeSessionEstablishmentFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "29 the peer closed during the session window",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
				b.sessionNode(domain.StateFail, domain.FailureProtocolPeerClosed, "", nil, idAuth)
			},
			want: CodeSessionEstablishmentFailed, severity: domain.SeverityError, vantage: true,
		},
		{
			row: "30 a healthy session",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
				b.sessionNode(domain.StatePass, domain.FailureNone, "", nil, idAuth)
			},
			want: none,
		},
		{
			row: "32 svcdoctor's own budget expired during the session window",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
				b.sessionNode(domain.StateUnknown, domain.FailureExecLocalTimeout, "", nil, idAuth)
			},
			want: none,
		},
		{
			row: "32b a failed session whose parent proves no authentication",
			graph: func(b *builder) {
				// A shape no producer emits: the startup node demanded SASL and
				// there is no authentication node beneath it. The rule withholds
				// rather than inventing the half of its claim it cannot cite.
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.sessionNode(domain.StateFail, domain.FailureResourceNotFound, "3D000", boolPtr(true), idStartup)
			},
			want: none,
		},
		{
			row: "32c a failed session whose authentication parent did not pass",
			graph: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureAuthCredentialsRejected, "28P01", boolPtr(true), "")
				b.sessionNode(domain.StateFail, domain.FailureResourceNotFound, "3D000", boolPtr(true), idAuth)
			},
			// The authentication node still yields its own finding; the session
			// node yields none.
			want: CodeCredentialsRejected, severity: domain.SeverityError, vantage: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.row, func(t *testing.T) {
			b := newBuilder(t)
			tt.graph(b)
			findings := allFindings(b.freeze())

			if tt.want == "" {
				if len(findings) != 0 {
					t.Fatalf("want no finding, got %v", codesOf(findings))
				}
				return
			}

			got := only(t, findings)
			if got.Code() != tt.want {
				t.Fatalf("code = %s, want %s", got.Code(), tt.want)
			}
			if got.Severity() != tt.severity {
				t.Errorf("severity = %s, want %s", got.Severity(), tt.severity)
			}
			// Every row asserts the vantage flag: a row that produced the right
			// code with the wrong flag is a failing row (ADR 0040 section 24).
			if got.VantageDependent() != tt.vantage {
				t.Errorf("vantageDependent = %v, want %v", got.VantageDependent(), tt.vantage)
			}
			// No finding in this package is a hypothesis, and none carries a
			// discriminator: every claim is about something observed.
			if got.Kind() != domain.FindingKindConfirmed {
				t.Errorf("kind = %s, want CONFIRMED", got.Kind())
			}
			if got.Confidence() != domain.ConfidenceHigh {
				t.Errorf("confidence = %s, want HIGH", got.Confidence())
			}
			if got.Discriminator() != "" {
				t.Errorf("discriminator = %q, want none", got.Discriminator())
			}
		})
	}
}

// TestPooledMissingDatabaseEndToEnd is acceptance row 33, written as the whole
// graph a pooler really produces rather than as one node.
//
// It is the shape the record exists for: the same condition that is a
// RESOURCE_NOT_FOUND at the session step against a direct endpoint arrives
// before authentication as a generic code, and svcdoctor must say where the
// connection died instead of guessing which of six causes it was.
func TestPooledMissingDatabaseEndToEnd(t *testing.T) {
	b := newBuilder(t)
	b.add(nodeSpec{
		id: idTCP, subject: addr, layer: domain.LayerTCP, step: "tcp.connect",
		state: domain.StatePass,
	})
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", boolPtr(false), "")

	got := only(t, allFindings(b.freeze()))

	if got.Code() != CodeStartupFailed {
		t.Fatalf("code = %s, want %s", got.Code(), CodeStartupFailed)
	}
	if got.Code() == CodeDatabaseNotFound || got.Code() == CodeCredentialsRejected {
		t.Fatal("a pooled generic code became a specific cause")
	}
}

// TestHealthyPathProducesNothingAtAll covers acceptance rows 30, 31 and 34 in
// the shape a real run produces.
//
// Row 31 is the one worth stating twice: a pooler served a complete passing
// session with its PostgreSQL backend stopped, so a passing session node cannot
// support any claim about what is behind the endpoint. The graph below is
// byte-identical to a healthy direct run, which is exactly the point — svcdoctor
// cannot tell them apart and therefore says nothing about either.
func TestHealthyPathProducesNothingAtAll(t *testing.T) {
	b := newBuilder(t)
	b.add(nodeSpec{
		id: idTCP, subject: addr, layer: domain.LayerTCP, step: "tcp.connect",
		state: domain.StatePass,
	})
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.add(nodeSpec{
		id: idTLS, subject: addr, layer: domain.LayerTLS, step: "tls.handshake",
		state: domain.StatePass, parent: idSSL,
	})
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
	b.sessionNode(domain.StatePass, domain.FailureNone, "", nil, idAuth)

	if findings := allFindings(b.freeze()); len(findings) != 0 {
		t.Fatalf("a healthy run produced %v; it must produce nothing", codesOf(findings))
	}
}

// TestTransportOnlyFailureProducesNoPostgreSQLFinding is acceptance row 21 and
// the honest cost of ADR 0040 section 2.
//
// A run whose endpoint fails at DNS, TCP or TLS produces complete evidence, a
// correct firstBrokenLayer, and **no finding from this package**. That is
// deliberate: those are generic transport nodes and a PostgreSQL rule reading
// one would be inferring provenance from graph shape. It is tracked as a product
// release gate rather than fixed by widening a service rule.
func TestTransportOnlyFailureProducesNoPostgreSQLFinding(t *testing.T) {
	b := newBuilder(t)
	b.add(nodeSpec{
		id: "dns.lookup/db.internal", subject: "db.internal:5432", layer: domain.LayerDNS,
		step: "dns.lookup", state: domain.StateFail, class: domain.FailureDNSNoAddress,
	})
	b.add(nodeSpec{
		id: idTCP, subject: addr, layer: domain.LayerTCP, step: "tcp.connect",
		state: domain.StateSkipped, class: domain.FailureExecSkippedPrerequisiteFailed,
		parent: "dns.lookup/db.internal", blocker: "dns.lookup/db.internal",
	})

	if findings := allFindings(b.freeze()); len(findings) != 0 {
		t.Fatalf("transport failure produced %v; PostgreSQL owns none of it", codesOf(findings))
	}
}
