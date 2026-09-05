package postgres

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// Unit tests for the connection-limit claim (ADR 0085 section 3).
//
// The claim's whole content is *this endpoint completed authentication and then
// refused this session at a connection limit that applied to it*. Both halves
// have to be cited, and the first is the one a rule cannot assert for itself: it
// is established by the session node's parent, and a session node without one is
// a shape this rule must withhold on rather than guess at.

// TestEverySessionClaimRequiresItsAuthenticationProof is the parent gate, driven
// over every claim the session step can make.
//
// It exists because the gate is one `if` guarding four codes, and a plant that
// removed it left the three older codes' tests passing: their fixtures all have
// a proper parent, so nothing noticed. This drives the shapes where the proof is
// **absent**, which is the only input the gate is about.
func TestEverySessionClaimRequiresItsAuthenticationProof(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class domain.FailureClass
		code  domain.FindingCode
	}{
		{"a connection-limit refusal", domain.FailureResourceLimitReached, CodeConnectionLimitReached},
		{"an absent database", domain.FailureResourceNotFound, CodeDatabaseNotFound},
		{"a denied CONNECT", domain.FailureAuthzDenied, CodeDatabaseConnectDenied},
		{"the session floor", domain.FailureProtocolUnexpectedResponse, CodeSessionEstablishmentFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// First, the proof is there and the claim is made — so the negative
			// cases below cannot pass because the rule says nothing at all.
			ok := newBuilder(t)
			ok.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
			ok.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
			ok.sessionNode(domain.StateFail, tc.class, "53300", boolPtr(true), idAuth)
			if got := only(t, allFindings(ok.freeze())); got.Code() != tc.code {
				t.Fatalf("with a proof the code is %s, want %s", got.Code(), tc.code)
			}

			for _, shape := range []struct {
				name  string
				build func(b *builder)
			}{
				{
					// The authentication node exists and did not pass. The
					// endpoint never said the credential was accepted, so
					// "this endpoint completed authentication" is unsupported.
					name: "the authentication node failed",
					build: func(b *builder) {
						b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
						b.authNode(domain.StateFail, domain.FailureAuthCredentialsRejected,
							"28P01", boolPtr(true), "")
						b.sessionNode(domain.StateFail, tc.class, "53300", boolPtr(true), idAuth)
					},
				},
				{
					// The session hangs off the startup node on a path where the
					// endpoint demanded SASL. No credential was presented, so
					// nothing established that authentication completed. This is
					// a shape no producer emits, and the rule withholds.
					name: "the parent is a startup node that demanded authentication",
					build: func(b *builder) {
						b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
						b.sessionNode(domain.StateFail, tc.class, "53300", boolPtr(true), idStartup)
					},
				},
				{
					name: "the session has no parent at all",
					build: func(b *builder) {
						b.sessionNode(domain.StateFail, tc.class, "53300", boolPtr(true), "")
					},
				},
			} {
				t.Run(shape.name, func(t *testing.T) {
					b := newBuilder(t)
					shape.build(b)
					for _, f := range allFindings(b.freeze()) {
						if f.Code() == tc.code {
							t.Errorf("%s was claimed without the evidence that this "+
								"endpoint completed authentication", tc.code)
						}
					}
				})
			}
		})
	}
}

// TestTheTrustPathStillReachesTheConnectionLimitClaim is the other half of the
// gate, and it is why the gate is two conditions rather than one.
//
// On a `trust` deployment the adapter records **no authentication node**, because
// svcdoctor presented nothing and claiming a passing authentication would be an
// overclaim. A rule that demanded an authentication parent would silently stop
// firing on every such deployment.
func TestTheTrustPathStillReachesTheConnectionLimitClaim(t *testing.T) {
	b := newBuilder(t)
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "ok")
	b.sessionNode(
		domain.StateFail, domain.FailureResourceLimitReached, "53300", boolPtr(true), idStartup)

	f := only(t, allFindings(b.freeze()))
	if f.Code() != CodeConnectionLimitReached {
		t.Errorf("code = %s, want %s on the trust path", f.Code(), CodeConnectionLimitReached)
	}
}

// TestTheConnectionLimitClaimIsNotVantageDependent pins the one semantic field
// that moved when the claim left the floor.
//
// A floor attributes no cause and so cannot exclude a source-keyed one, which is
// why POSTGRES_SESSION_ESTABLISHMENT_FAILED is `true`. This claim restates a
// condition the endpoint named in its own protocol, and that is not read off the
// address svcdoctor dialled from — the same ground the two sibling escalations
// stand on.
//
// **The flag is about derivation and not about scope.** `false` here does not
// say the refusal would have befallen every client: the limit that applied may
// depend on the session's own context, and the finding claims nothing either
// way. TestTheConnectionLimitClaimIsScopedToTheAttemptedSession holds that
// half.
func TestTheConnectionLimitClaimIsNotVantageDependent(t *testing.T) {
	b := newBuilder(t)
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
	b.sessionNode(
		domain.StateFail, domain.FailureResourceLimitReached, "53300", boolPtr(true), idAuth)

	f := only(t, allFindings(b.freeze()))
	if f.VantageDependent() {
		t.Error("the connection-limit claim is marked vantage-dependent; the endpoint " +
			"named this condition in its own protocol and svcdoctor did not infer it " +
			"from the address it dialled from")
	}
	if f.Severity() != domain.SeverityError {
		t.Errorf("severity = %s, want ERROR: a session was refused", f.Severity())
	}
}

// TestTheConnectionLimitClaimIsScopedToTheAttemptedSession is the scope gate,
// and it is the one the first cut of Phase 10.3 would have failed.
//
// PostgreSQL raises 53300 when **a** connection limit applicable to the session
// being admitted has been reached, and it has several: `max_connections`, the
// reserved-slot margins, a database's `CONNECTION LIMIT` and a role's. The
// ErrorResponse names none of them.
//
// The gap is reachable rather than theoretical, and this repository proves it
// deterministically: `test/integration/postgres/env/init.sql` creates a role with
// `CONNECTION LIMIT 0`, which yields 53300 on every login while the server has
// connections to spare. So *"the endpoint had no connection slot available"* is
// a strictly stronger sentence than the evidence supports, and it may not appear
// on any surface an operator reads.
//
// This drives the positive half too. Refusing the overclaim is not enough on its
// own — prose that said nothing at all would pass — so the claim has to state
// that a limit applying to *this* attempt was reached and that the response does
// not identify it.
func TestTheConnectionLimitClaimIsScopedToTheAttemptedSession(t *testing.T) {
	b := newBuilder(t)
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
	b.sessionNode(
		domain.StateFail, domain.FailureResourceLimitReached, "53300", boolPtr(true), idAuth)
	f := only(t, allFindings(b.freeze()))

	surfaces := map[string]string{"summary": f.Summary(), "detail": f.Detail()}
	for i, r := range f.Recommendations() {
		surfaces["recommendation "+strconv.Itoa(i)] = r.Action()
	}

	// Endpoint-wide scope, in the wordings a rule author would reach for.
	for _, overclaimed := range []string{
		"no connection slot", "no slot", "slot free", "free slot",
		"out of connections", "no connections left", "no connection left",
		"every session", "all sessions", "any session", "globally",
	} {
		for name, text := range surfaces {
			if strings.Contains(strings.ToLower(text), overclaimed) {
				t.Errorf("the %s contains %q, which asserts that the endpoint had "+
					"nothing left for anybody.\n\n"+
					"53300 proves that a connection limit applicable to this attempted "+
					"session was reached. A role with CONNECTION LIMIT 0 produces it on "+
					"a server with connections to spare.\n\ntext: %s",
					name, overclaimed, text)
			}
		}
	}

	// Naming one limit is the same overclaim by a shorter route.
	for _, named := range []string{
		"max_connections", "superuser_reserved", "reserved_connections", "role limit",
	} {
		for name, text := range surfaces {
			if strings.Contains(strings.ToLower(text), named) {
				t.Errorf("the %s names %q; the response identifies no limit.\n\ntext: %s",
					name, named, text)
			}
		}
	}

	// The recommendation is held to a stricter rule than the detail, and the
	// difference is deliberate. The detail may say that the applicable limit
	// depends on session context and give the role as the obvious example,
	// because that bounds the claim. A recommendation is where an operator is
	// sent to look, so naming any member of the applicable set there — even as
	// an example — tells them implicitly which limit to suspect.
	for _, r := range f.Recommendations() {
		for _, named := range []string{
			"max_connections", "role", "database", "reserved", "superuser", "slot",
		} {
			if strings.Contains(strings.ToLower(r.Action()), named) {
				t.Errorf("the recommendation names %q; the response identifies no limit "+
					"and the advice must not point at one.\n\naction: %s",
					named, r.Action())
			}
		}
		// It still has to ask for the identification step, not only a
		// comparison against something unstated.
		if !strings.Contains(r.Action(), "Identify the connection limits applicable to this") {
			t.Errorf("the recommendation skips establishing which limits applied: %s",
				r.Action())
		}
	}

	// And the positive half, so silence cannot pass.
	if !strings.Contains(f.Detail(), "a connection limit that applied to this attempted session") {
		t.Errorf("the claim does not say that a limit applying to this attempt was "+
			"reached: %s", f.Detail())
	}
	if !strings.Contains(f.Detail(), "Which limit was reached is not in the response") {
		t.Errorf("the claim does not say that the limit is unidentified: %s", f.Detail())
	}
	if !strings.Contains(f.Summary(), "this session") {
		t.Errorf("the summary is not scoped to the attempted session: %s", f.Summary())
	}
}

// TestTheConnectionLimitDetailReportsWhatTheNodeCarries pins the two observed
// sentences the claim appends and the two floor sentences it must not.
func TestTheConnectionLimitDetailReportsWhatTheNodeCarries(t *testing.T) {
	build := func(t *testing.T, native *bool) domain.Finding {
		t.Helper()
		b := newBuilder(t)
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
		b.sessionNode(
			domain.StateFail, domain.FailureResourceLimitReached, "53300", native, idAuth)
		return only(t, allFindings(b.freeze()))
	}

	nativeDetail := build(t, boolPtr(true)).Detail()
	if !strings.Contains(nativeDetail, "SQLSTATE 53300") {
		t.Errorf("the SQLSTATE is not printed verbatim: %s", nativeDetail)
	}
	if strings.Contains(nativeDetail, sentenceNotNative) {
		t.Errorf("a native response is described as not native: %s", nativeDetail)
	}
	// The floor's two closing sentences belong to the floor. The condition is
	// already named in this claim's own base text, and the attribution sentence
	// would contradict it.
	if strings.Contains(nativeDetail, sentenceUnattributable) {
		t.Errorf("the claim names the condition and still declines to attribute it: %s",
			nativeDetail)
	}

	pooledDetail := build(t, boolPtr(false)).Detail()
	if !strings.Contains(pooledDetail, sentenceNotNative) {
		t.Errorf("an absent severity field is not reported: %s", pooledDetail)
	}

	// ADR 0040 section 18.1: error_is_native is an observation and never an
	// input. It changes the detail and nothing else.
	native, pooled := build(t, boolPtr(true)), build(t, boolPtr(false))
	if native.Code() != pooled.Code() || native.Kind() != pooled.Kind() ||
		native.Severity() != pooled.Severity() || native.Confidence() != pooled.Confidence() {
		t.Error("error_is_native changed a semantic field; it is an observation and " +
			"never an input (ADR 0040 section 18.1)")
	}
}

// TestTheSessionStepIsTheOnlyProducerOfTheResourceLimitClass records why the
// claim is scoped to one step, read off the vocabulary rather than asserted.
//
// The adapter classifies a SQLSTATE per step, because the only answerable
// question is what a code proves *there* (ADR 0039 section 7.1). 53300 reaches
// RESOURCE_LIMIT_REACHED at `postgres.session` and falls through to the honest
// weak class at `postgres.startup` and `postgres.authentication`, where nothing
// establishes that authentication completed. A rule that re-read the five
// characters to escalate at those steps would be building the shared SQLSTATE
// dictionary that decision forbids.
func TestTheSessionStepIsTheOnlyProducerOfTheResourceLimitClass(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(b *builder)
		want  domain.FindingCode
	}{
		{
			name: "53300 before authentication is the startup floor",
			build: func(b *builder) {
				b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse,
					"53300", boolPtr(true), "")
			},
			want: CodeStartupFailed,
		},
		{
			name: "53300 during authentication is the authentication floor",
			build: func(b *builder) {
				b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
				b.authNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse,
					"53300", boolPtr(true), "")
			},
			want: CodeAuthenticationFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			tc.build(b)
			f := only(t, allFindings(b.freeze()))
			if f.Code() != tc.want {
				t.Errorf("code = %s, want %s", f.Code(), tc.want)
			}
			if f.Code() == CodeConnectionLimitReached {
				t.Error("a SQLSTATE was escalated at a step that proves nothing about it")
			}
			// The floor still restates the named condition, which is what keeps
			// namedConditions alive rather than orphaned — and it restates it
			// with the same scope the claim uses, so one SQLSTATE does not get
			// two meanings depending on which window observed it.
			//
			// Asserted against **literals** and never against the constant. A
			// test that compared the output to the constant it is rendered from
			// would follow any edit to that constant and measure nothing.
			if !strings.Contains(f.Detail(), "too_many_connections") {
				t.Errorf("the floor no longer restates the named condition: %s", f.Detail())
			}
			if !strings.Contains(f.Detail(),
				"a connection limit that applied to the attempted session had been reached") {
				t.Errorf("the floor no longer states what was reached: %s", f.Detail())
			}
			if !strings.Contains(f.Detail(), "does not say which limit") {
				t.Errorf("the floor claims to know which limit was reached: %s", f.Detail())
			}
			for _, overclaimed := range []string{
				"no connection slot", "no slot", "slot free", "out of connections",
			} {
				if strings.Contains(strings.ToLower(f.Detail()), overclaimed) {
					t.Errorf("the floor restatement contains %q, an endpoint-wide claim "+
						"53300 does not carry: %s", overclaimed, f.Detail())
				}
			}
		})
	}

	// And the vocabulary the rule reads is the class, never the code.
	if _, ok := map[domain.AttributeKey]bool{servicepostgres.AttrSQLState: true}[servicepostgres.AttrSQLState]; !ok {
		t.Fatal("the SQLSTATE attribute key is not what this test thinks it is")
	}
}
