package diagnosis_test

import (
	"strings"
	"testing"

	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The PostgreSQL golden incident corpus, Phase 10.3.
//
// ADR 0083 section 2.5 fixes the shape: intent, evidence, expected, forbidden.
// The fourth is the one that matters, and every fixture here carries a
// non-empty one — TestThePostgresCorpusForbidsSomethingEverywhere fails
// otherwise.
//
// # Two scenarios in the phase brief are absent, and their absence is the result
//
// A run that observes two endpoints' recovery states, and a run where one
// address answers with a connection-limit refusal while a sibling accepts, are
// both **graphs svcdoctor cannot produce**. Exactly one path continues past the
// credential-free stages (ADR 0041), so a run holds at most one authentication
// node and at most one session node. Nothing suppresses those claims; there is
// no evidence from which to make them, which is why
// TestPGStructuralSingleSessionPerRun asserts the shape rather than the wording.
//
// The corpus covers what the product can reach: P01-P08 are the single-address
// journey, P09-P12 the multi-address admission shapes, P13 the withheld
// credential, P14 a hostile server, and P15 the two-primaries question answered
// structurally.

// pgIncident is one PostgreSQL corpus fixture.
type pgIncident struct {
	id     string
	name   string
	intent string

	build      func(t *testing.T) domain.Graph
	incomplete bool

	// expectCodes are the finding codes that must be present.
	expectCodes []domain.FindingCode

	// expectAbsentCodes are the codes that must not be, so silence is asserted
	// rather than merely unlisted.
	expectAbsentCodes []domain.FindingCode

	// expectStatus is the report's derived summary status.
	expectStatus domain.SummaryStatus

	// expectTerminal are substrings the operator-facing output must contain.
	expectTerminal []string

	// forbidden is what this scenario must never say, in any output surface.
	forbidden []forbiddenClaim
}

// yes and no are the pointer-to-bool spellings the stage constructors take.
func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

const pgAddrA = "10.0.0.11:5432"
const pgAddrB = "10.0.0.12:5432"

// pgCorpus is the whole set.
func pgCorpus() []pgIncident {
	return []pgIncident{
		{
			id:     "P01",
			name:   "the name does not resolve",
			intent: "reach a PostgreSQL endpoint by hostname over verified TLS",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StateFail, domain.FailureDNSNoAddress)
				return h.freeze()
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes:  []domain.FindingCode{"DNS_NAME_NOT_RESOLVED"},
			expectAbsentCodes: []domain.FindingCode{
				diagnosispostgres.CodeStartupFailed,
				diagnosispostgres.CodeConnectionLimitReached,
				diagnosispostgres.CodeAdmissionScope,
			},
			forbidden: []forbiddenClaim{
				{"postgresql endpoint refused", "no PostgreSQL byte was exchanged"},
				{"connection slot", "nothing reached a server to be refused a slot"},
				{"admission", "no admission decision can have been made"},
				{"in recovery", "no session parameter was received"},
				{"the connection failed", "the connection was never attempted"},
			},
		},
		{
			id:     "P02",
			name:   "TCP is refused at the only address",
			intent: "reach a PostgreSQL endpoint that resolves but refuses connections",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				h.path(pgAddrA,
					pgTCP(domain.StateFail, domain.FailureTCPConnectionRefused),
					pgSSLRequest(domain.StateSkipped, domain.FailureExecSkippedPrerequisiteFailed, nil),
				)
				return h.freeze()
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes:  []domain.FindingCode{"TCP_CONNECTION_NOT_ESTABLISHED"},
			expectAbsentCodes: []domain.FindingCode{
				diagnosispostgres.CodeConnectionLimitReached,
				diagnosispostgres.CodeAdmissionScope,
				diagnosispostgres.CodeConnectionNotPermitted,
			},
			forbidden: []forbiddenClaim{
				{"firewall", "no firewall was observed and none could be"},
				{"the host is down", "a refusal distinguishes neither a host nor a process"},
				{"connection slot", "a refusal at TCP is not a resource-limit statement"},
				{"53300", "no SQLSTATE was received"},
				{"admission", "the startup stage was never reached"},
			},
		},
		{
			id:     "P03",
			name:   "the in-band TLS handshake fails on an untrusted chain",
			intent: "reach a PostgreSQL endpoint over TLS verified against the system store",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				h.path(pgAddrA,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StateFail, domain.FailureTLSUnknownAuthority),
				)
				return h.freeze()
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes:  []domain.FindingCode{diagnosispostgres.CodeTLSChainNotTrusted},
			expectAbsentCodes: []domain.FindingCode{
				diagnosispostgres.CodeConnectionLimitReached,
				diagnosispostgres.CodeAdmissionScope,
				diagnosispostgres.CodeCredentialsRejected,
			},
			forbidden: []forbiddenClaim{
				{"bad password", "no credential was presented"},
				{"connection slot", "the session stage was never reached"},
				{"expired", "the chain was untrusted, which is a different observation"},
				{"disable", "svcdoctor never recommends weakening a control it verifies"},
			},
		},
		{
			id:     "P04",
			name:   "the endpoint rejects the credential",
			intent: "authenticate a role at a PostgreSQL endpoint over verified TLS",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				h.path(pgAddrA,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
					pgAuth(domain.StateFail, domain.FailureAuthCredentialsRejected, "28P01", yes()),
				)
				return h.freeze()
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes:  []domain.FindingCode{diagnosispostgres.CodeCredentialsRejected},
			expectAbsentCodes: []domain.FindingCode{
				diagnosispostgres.CodeConnectionNotPermitted,
				diagnosispostgres.CodeConnectionLimitReached,
			},
			forbidden: []forbiddenClaim{
				// The whole point of keeping these two apart: PostgreSQL issues
				// a mock salt for a role that does not exist, deliberately, so a
				// client cannot tell an unknown role from a wrong password.
				{"bad password", "28P01 does not distinguish an unknown role from a wrong password"},
				{"password is incorrect", "the same"},
				{"username", "the same"},
				{"does not exist", "the same"},
				{"pg_hba", "a credential rejection is not an admission decision"},
				{"host-based", "the same"},
			},
		},
		{
			id:     "P05",
			name:   "the endpoint refuses admission before any credential",
			intent: "authenticate a role at a PostgreSQL endpoint over verified TLS",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				h.path(pgAddrA,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", "", yes()),
				)
				return h.freeze()
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes:  []domain.FindingCode{diagnosispostgres.CodeConnectionNotPermitted},
			expectAbsentCodes: []domain.FindingCode{
				diagnosispostgres.CodeCredentialsRejected,
				// One address is not a scope.
				diagnosispostgres.CodeAdmissionScope,
			},
			forbidden: []forbiddenClaim{
				{"bad password", "no credential was presented, so none was judged"},
				{"credential is", "the same"},
				{"misconfigur", "a policy that refuses may be exactly what it was written to do"},
				{"pg_hba.conf is", "the same, and svcdoctor read no file"},
				{"add a", "widening an admission policy is a security-relevant change"},
			},
		},
		{
			id:     "P06",
			name:   "the endpoint refuses the session at its connection limit",
			intent: "establish a PostgreSQL session as an authenticated role",
			build: func(t *testing.T) domain.Graph {
				return pgSessionOutcome(t,
					domain.StateFail, domain.FailureResourceLimitReached, "53300", "")
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes: []domain.FindingCode{
				diagnosispostgres.CodeConnectionLimitReached,
				"DIAG_FAILURE_BOUNDARY",
			},
			expectAbsentCodes: []domain.FindingCode{
				// The generic boundary owns "where the failure begins"; this
				// phase adds server semantics beside it and never a second
				// PostgreSQL boundary code.
				diagnosispostgres.CodeSessionEstablishmentFailed,
				diagnosispostgres.CodeCredentialsRejected,
			},
			forbidden: []forbiddenClaim{
				{"connection leak", "no connection lifetime was observed"},
				{"max_connections", "svcdoctor read no setting and holds none"},
				{"too low", "the same, and it is a judgement about a value nobody saw"},
				{"increase", "raising a limit can worsen memory pressure and hide a leak"},
				{"pool", "a pooler's own limit arrives under a different code entirely"},
				{"spike", "nothing observed the arrival rate of connections"},
				{"memory", "nothing observed the endpoint's memory"},
				{"exhausted", "the endpoint said a limit applying to this session " +
					"was reached, at one instant, and named neither the limit nor " +
					"how much of it was in use"},
				// Scope, not cause. 53300 is raised against whichever applicable
				// limit was reached, and `CONNECTION LIMIT 0` on a role produces
				// it on a server with connections to spare — which is exactly
				// what the integration fixture does.
				{"no connection slot", "an endpoint-wide claim the code does not carry"},
				{"no slot", "the same, in any wording"},
				{"out of connections", "the same"},
			},
		},
		{
			id:     "P07",
			name:   "a session is established and the endpoint reports no recovery",
			intent: "establish a PostgreSQL session as an authenticated role",
			build: func(t *testing.T) domain.Graph {
				return pgSessionOutcome(t, domain.StatePass, domain.FailureNone, "", "off")
			},
			expectStatus: domain.SummaryStatusOK,
			// A healthy PostgreSQL path produces **zero** findings, and Phase
			// 10.3 did not change that. The role is an observation and reaches
			// the operator through the result block, not through a claim.
			expectCodes: nil,
			expectAbsentCodes: []domain.FindingCode{
				diagnosispostgres.CodeAdmissionScope,
				diagnosispostgres.CodeConnectionLimitReached,
				"DIAG_FAILURE_BOUNDARY",
			},
			expectTerminal: []string{"session established", "recovery", "not in recovery"},
			forbidden: []forbiddenClaim{
				{"primary", "in_hot_standby=off is not an endpoint identity"},
				{"healthy", "a pooler served a passing session with its backend stopped"},
				{"writable", "the parameter that answers that is session-local and needs SQL"},
				{"correct", "svcdoctor holds no expectation to compare this against"},
				{"ha ", "nothing about replication or high availability was observed"},
			},
		},
		{
			id:     "P08",
			name:   "a session is established and the endpoint reports recovery",
			intent: "establish a PostgreSQL session as an authenticated role",
			build: func(t *testing.T) domain.Graph {
				return pgSessionOutcome(t, domain.StatePass, domain.FailureNone, "", "on")
			},
			expectStatus: domain.SummaryStatusOK,
			// The measured Patroni result: during etcd quorum loss every node
			// reported in_hot_standby=on and svcdoctor produced no finding on
			// any of them. That is still right, and it is right for the stated
			// reason rather than by accident.
			expectCodes: nil,
			expectAbsentCodes: []domain.FindingCode{
				diagnosispostgres.CodeAdmissionScope,
				diagnosispostgres.CodeConnectionLimitReached,
				"DIAG_FAILURE_BOUNDARY",
			},
			expectTerminal: []string{
				"session established",
				"recovery",
				"in recovery",
				"neither a finding nor a fault",
			},
			forbidden: []forbiddenClaim{
				{"standby", "a pooler forwards a cached value; this is not an identity"},
				{"replica", "the same"},
				{"wrong server", "svcdoctor holds no expectation about which role this should have"},
				{"failover", "nothing about replication was observed"},
				{"promote", "svcdoctor recommends no disruptive action, ever"},
				{"split", "one session says nothing about any other endpoint"},
				{"read-only", "recovery and default_transaction_read_only are independent facts"},
			},
		},
		{
			id:     "P09",
			name:   "two addresses, one refused and one admitted",
			intent: "reach a dual-stack PostgreSQL target and authenticate a role",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				h.path(pgAddrA,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", "", yes()),
				)
				h.path(pgAddrB,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
					pgAuth(domain.StatePass, domain.FailureNone, "", nil),
					pgSession(domain.StatePass, domain.FailureNone, "", "off", nil),
				)
				return h.freeze()
			},
			// The refusal at one address is a real target-side ERROR, so the
			// status is PROBLEMS_FOUND even though the selected path succeeded.
			// The aggregate is what tells a reader the second half of that.
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes: []domain.FindingCode{
				diagnosispostgres.CodeConnectionNotPermitted,
				diagnosispostgres.CodeAdmissionScope,
			},
			expectTerminal: []string{"session established"},
			forbidden: []forbiddenClaim{
				{"misconfigur", "an admission policy that refuses one address may be intended"},
				{"pg_hba.conf is", "svcdoctor read no file"},
				{"add a", "widening admission is a security-relevant change"},
				{"bad password", "no credential reached the refusing address"},
				{"unreachable", "both addresses were reached; one refused"},
				{"every address", "one address completed the startup exchange"},
			},
		},
		{
			id:     "P10",
			name:   "two addresses, both refused, and the set is complete",
			intent: "reach a dual-stack PostgreSQL target and authenticate a role",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				for _, address := range []string{pgAddrA, pgAddrB} {
					h.path(address,
						pgTCP(domain.StatePass, domain.FailureNone),
						pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
						pgTLS(domain.StatePass, domain.FailureNone),
						pgStartup(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", "", yes()),
					)
				}
				return h.freeze()
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes: []domain.FindingCode{
				diagnosispostgres.CodeConnectionNotPermitted,
				diagnosispostgres.CodeAdmissionScope,
			},
			forbidden: []forbiddenClaim{
				{"misconfigur", "the policy may be exactly what it was written to do"},
				{"bad password", "no credential was presented at either address"},
				{"the server is down", "both addresses answered"},
				{"blocked", "nothing observed a mechanism"},
			},
		},
		{
			id:     "P11",
			name:   "two addresses refused and a third never determined",
			intent: "reach a PostgreSQL target with three addresses under a tight budget",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				for _, address := range []string{pgAddrA, pgAddrB} {
					h.path(address,
						pgTCP(domain.StatePass, domain.FailureNone),
						pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
						pgTLS(domain.StatePass, domain.FailureNone),
						pgStartup(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", "", yes()),
					)
				}
				h.path("10.0.0.13:5432",
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StateUnknown, domain.FailureExecLocalTimeout, "", "", nil),
				)
				return h.freeze()
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes: []domain.FindingCode{
				diagnosispostgres.CodeConnectionNotPermitted,
				diagnosispostgres.CodeAdmissionScope,
			},
			forbidden: []forbiddenClaim{
				// The completeness half, stated as forbidden phrasings.
				{"at all 3", "one address reached no decision, so 3 is not a total"},
				{"every address", "the same"},
				{"only", "an incomplete set supports no exclusive claim"},
				{"misconfigur", "the policy may be intended"},
			},
		},
		{
			id:     "P12",
			name:   "the run is cancelled before every address is measured",
			intent: "reach a PostgreSQL target with two addresses; the operator interrupts",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				h.path(pgAddrA,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", "", yes()),
				)
				h.path(pgAddrB,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", "", yes()),
				)
				return h.freeze()
			},
			// The counts are complete on their own terms and the run is not.
			// The incomplete sentence must win: svcdoctor's own execution is
			// what qualifies every conclusion (exit 4).
			incomplete:   true,
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes: []domain.FindingCode{
				diagnosispostgres.CodeConnectionNotPermitted,
				diagnosispostgres.CodeAdmissionScope,
			},
			forbidden: []forbiddenClaim{
				{"at all 2", "an interrupted run establishes no total"},
				{"account for the whole set", "the same"},
				{"every address", "the same"},
			},
		},
		{
			id:     "P13",
			name:   "the credential is withheld because the channel is unverified",
			intent: "authenticate over TLS whose verification was explicitly disabled",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				// The plaintext shape the adapter really records: no SSLRequest
				// was sent, the node states positively that none was and why,
				// and it is the node the authentication step points at when the
				// credential-transport policy refuses the channel (ADR 0030).
				h.path(pgAddrA,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StateSkipped, domain.FailureExecSkippedByPolicy, nil),
					pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
					pgAuthBlockedBy(servicepostgres.StepSSLRequest),
				)
				return h.freeze()
			},
			expectStatus: domain.SummaryStatusOK,
			expectCodes:  []domain.FindingCode{diagnosispostgres.CodeCredentialWithheld},
			expectAbsentCodes: []domain.FindingCode{
				// The whole point: a credential nobody sent was not rejected.
				diagnosispostgres.CodeCredentialsRejected,
				diagnosispostgres.CodeAuthenticationFailed,
				diagnosispostgres.CodeConnectionNotPermitted,
			},
			forbidden: []forbiddenClaim{
				{"rejected", "svcdoctor sent nothing to be rejected"},
				{"bad password", "no credential crossed the wire"},
				{"authentication failed", "authentication was never attempted"},
				{"disable", "svcdoctor never recommends weakening a control"},
			},
		},
		{
			id:     "P14",
			name:   "a hostile endpoint answers with crafted error fields",
			intent: "establish a PostgreSQL session against an endpoint that is not cooperating",
			build: func(t *testing.T) domain.Graph {
				return pgSessionOutcome(t,
					domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", "")
			},
			expectStatus: domain.SummaryStatusProblemsFound,
			expectCodes:  []domain.FindingCode{diagnosispostgres.CodeSessionEstablishmentFailed},
			expectAbsentCodes: []domain.FindingCode{
				// 08P01 is pgBouncer's default for everything and proves no
				// condition. It must not reach the connection-limit claim.
				diagnosispostgres.CodeConnectionLimitReached,
				diagnosispostgres.CodeDatabaseNotFound,
			},
			forbidden: []forbiddenClaim{
				{"connection slot", "08P01 names no condition"},
				{"too_many_connections", "the same"},
				{"pgbouncer", "svcdoctor never names a peer product"},
				{"proxy", "the absence of the severity field identifies nobody"},
			},
		},
		{
			id:   "P15",
			name: "two addresses both complete the startup exchange",
			intent: "reach a target whose two addresses might be two servers; " +
				"the operator wants to know what was measured",
			build: func(t *testing.T) domain.Graph {
				h := newPGHarness(t, "db.example:5432")
				h.lookup(domain.StatePass, domain.FailureNone)
				h.path(pgAddrA,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
				)
				h.path(pgAddrB,
					pgTCP(domain.StatePass, domain.FailureNone),
					pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
					pgTLS(domain.StatePass, domain.FailureNone),
					pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
					pgAuth(domain.StatePass, domain.FailureNone, "", nil),
					pgSession(domain.StatePass, domain.FailureNone, "", "off", nil),
				)
				return h.freeze()
			},
			// Nothing was refused, so the aggregate is silent too: it fires only
			// on a positively observed refusal.
			expectStatus: domain.SummaryStatusOK,
			expectCodes:  nil,
			expectAbsentCodes: []domain.FindingCode{
				diagnosispostgres.CodeAdmissionScope,
				"DIAG_FAILURE_BOUNDARY",
			},
			forbidden: []forbiddenClaim{
				{"split", "svcdoctor does not know these addresses share a database system"},
				{"two primaries", "one session was established; the other address was never authenticated"},
				{"dual", "the same"},
				{"fencing", "nothing about a replication topology was observed"},
				{"primary", "no endpoint identity was observed at either address"},
			},
		},
	}
}

// pgSessionOutcome is the common single-address journey through to a session.
func pgSessionOutcome(
	t *testing.T, state domain.State, class domain.FailureClass, sqlState, recovery string,
) domain.Graph {
	t.Helper()

	native := yes()
	if sqlState == "08P01" {
		native = no()
	}
	h := newPGHarness(t, "db.example:5432")
	h.lookup(domain.StatePass, domain.FailureNone)
	h.path(pgAddrA,
		pgTCP(domain.StatePass, domain.FailureNone),
		pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
		pgTLS(domain.StatePass, domain.FailureNone),
		pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
		pgAuth(domain.StatePass, domain.FailureNone, "", nil),
		pgSession(state, class, sqlState, recovery, native),
	)
	return h.freeze()
}

// TestThePostgresGoldenIncidentCorpus is the corpus, run.
func TestThePostgresGoldenIncidentCorpus(t *testing.T) {
	for _, fixture := range pgCorpus() {
		t.Run(fixture.id+" "+fixture.name, func(t *testing.T) {
			t.Logf("intent: %s", fixture.intent)

			r := diagnosePostgres(t, fixture.build(t), fixture.incomplete)

			for _, want := range fixture.expectCodes {
				if !hasCode(r, want) {
					t.Errorf("no %s finding; got %v", want, codesIn(r))
				}
			}
			for _, absent := range fixture.expectAbsentCodes {
				if hasCode(r, absent) {
					t.Errorf("%s must not be produced here; got %v", absent, codesIn(r))
				}
			}
			if fixture.expectCodes == nil && len(r.report.Findings()) != 0 {
				t.Errorf("this scenario must produce no finding; got %v", codesIn(r))
			}
			if got := r.report.Summary().Status(); got != fixture.expectStatus {
				t.Errorf("status = %s, want %s", got, fixture.expectStatus)
			}

			terminal := pgTerminal(t, r)
			for _, want := range fixture.expectTerminal {
				if !strings.Contains(terminal, want) {
					t.Errorf("the terminal output does not contain %q.\n\n%s", want, terminal)
				}
			}

			assertRefuses(t, r, fixture.forbidden)
		})
	}
}

// TestThePostgresCorpusForbidsSomethingEverywhere is ADR 0083 section 7's guard.
func TestThePostgresCorpusForbidsSomethingEverywhere(t *testing.T) {
	all := pgCorpus()
	if len(all) < 15 {
		t.Fatalf("the corpus holds %d fixtures, want at least 15", len(all))
	}
	seen := map[string]bool{}
	for _, fixture := range all {
		if seen[fixture.id] {
			t.Errorf("duplicate fixture id %s", fixture.id)
		}
		seen[fixture.id] = true
		if len(fixture.forbidden) == 0 {
			t.Errorf("the %s fixture forbids nothing, so it proves nothing about "+
				"overclaiming (ADR 0083 section 2.5)", fixture.id)
		}
		if fixture.intent == "" {
			t.Errorf("the %s fixture declares no intent", fixture.id)
		}
		for _, claim := range fixture.forbidden {
			if claim.why == "" {
				t.Errorf("the %s fixture forbids %q without saying why", fixture.id, claim.phrase)
			}
		}
	}
}

// TestThePostgresCorpusCarriesNoRealIdentity is ADR 0083 section 5.
func TestThePostgresCorpusCarriesNoRealIdentity(t *testing.T) {
	for _, fixture := range pgCorpus() {
		t.Run(fixture.id, func(t *testing.T) {
			g := fixture.build(t)
			if g.Len() == 0 {
				t.Fatal("the fixture built no evidence")
			}
			for _, node := range g.Nodes() {
				ref := node.Subject().Ref()
				host, _, found := strings.Cut(ref, ":")
				if !found {
					host = ref
				}
				switch {
				case strings.HasSuffix(host, ".example"), host == "example":
				case strings.HasPrefix(host, "10."), strings.HasPrefix(host, "192.168."),
					strings.HasPrefix(host, "127."):
				default:
					t.Errorf("subject %q is neither documentation-reserved nor private", ref)
				}
			}
		})
	}
}
