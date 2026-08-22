//go:build integration

package postgres

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// Phase 4.8a: the vertical slice, end to end, against a real server.
//
// Every graph here came out of the production stages. Nothing is hand-authored,
// no exchange is simulated, no finding is constructed by a test, and no SQL is
// executed. The Phase 4.6b tests over hand-built graphs remain and are still the
// authority on diagnosis *policy*; these are the authority on whether the policy
// meets the evidence a real server produces.

const (
	pgPlaintextPort = 55433
	pgTLSPort       = 55432

	rejectRole = "rejectuser"

	// The redaction canaries. Both reach the graph as identity attributes on the
	// startup node, and neither appears anywhere else in the repository.
	canaryRole     = "svcdcanaryrole"
	canaryDatabase = "svcdcanarydb"
	canaryPassword = "svcd-canary-pw-9Q7x"

	missingDatabase = "nosuchdb-svcd"
)

// healthy is the scenario every other one is a deviation from.
func healthy() scenario {
	return scenario{
		port: pgTLSPort, plan: postgres.TLSRequired, trustCA: true,
		role: scramRole, password: scramPassword, database: database,
	}
}

// --- A. healthy ---------------------------------------------------------------

// TestEndToEndHealthySession is the whole point of the phase.
//
// Real Docker PostgreSQL, real resolver, real socket, real SSLRequest, real TLS
// handshake, real StartupMessage, real SCRAM proof, real ReadyForQuery, real
// graph, real diagnosis, real report, real redaction.
func TestEndToEndHealthySession(t *testing.T) {
	o := run(t, healthy())

	// The real chain, by step and state.
	o.requireState(t, "dns.lookup", domain.StatePass, domain.FailureNone)
	o.requireState(t, "tcp.connect", domain.StatePass, domain.FailureNone)
	o.requireState(t, servicepostgres.StepSSLRequest, domain.StatePass, domain.FailureNone)
	o.requireState(t, "tls.handshake", domain.StatePass, domain.FailureNone)
	o.requireState(t, servicepostgres.StepStartup, domain.StatePass, domain.FailureNone)
	o.requireState(t, servicepostgres.StepAuthentication, domain.StatePass, domain.FailureNone)
	session := o.requireState(t, servicepostgres.StepSession, domain.StatePass, domain.FailureNone)

	// ReadyForQuery, and nothing stronger. The transaction status is the whole
	// payload of the frame that defines success.
	if got := stringAttr(t, session, "postgres.transaction_status"); got != "idle" {
		t.Errorf("transaction status = %q, want idle", got)
	}

	// The topology, walked structurally rather than by parsing identifiers.
	o.requireParentChain(t, []domain.Step{
		"dns.lookup", "tcp.connect", servicepostgres.StepSSLRequest, "tls.handshake",
		servicepostgres.StepStartup, servicepostgres.StepAuthentication,
		servicepostgres.StepSession,
	})

	// A healthy run says nothing, which is the correct amount to say. Notably it
	// does not claim a backend is healthy: a pooler serves a complete passing
	// session with its backend stopped, measured in Phase 4.5a.
	o.requireNoFindings(t)

	if got := o.report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("report status = %s, want OK", got)
	}
	if counts := o.report.Summary().FindingCountsBySeverity(); counts.Error+counts.Critical != 0 {
		t.Errorf("a healthy run reported %d ERROR and %d CRITICAL findings",
			counts.Error, counts.Critical)
	}

	requireRedactable(t, o.report)
}

// --- D. wrong password ---------------------------------------------------------

func TestEndToEndWrongPassword(t *testing.T) {
	s := healthy()
	s.password = scramPassword + "-wrong"
	o := run(t, s)

	auth := o.requireState(t, servicepostgres.StepAuthentication,
		domain.StateFail, domain.FailureAuthCredentialsRejected)
	if got := stringAttr(t, auth, servicepostgres.AttrSQLState); got != "28P01" {
		t.Errorf("sqlstate = %q, want 28P01", got)
	}

	// The session step must not have run: authentication failed, so there was
	// nothing to establish a session over.
	o.requireAbsent(t, servicepostgres.StepSession)

	f := o.requireOneFinding(t, diagnosispostgres.CodeCredentialsRejected)
	requireProseExcludes(t, f,
		"password is wrong", "password is incorrect", "invalid credential",
		"role does not exist", "account is disabled")

	requireProblemsFound(t, o)
	requireNoCredentialAnywhere(t, o, scramPassword+"-wrong")
	requireRedactable(t, o.report)
}

// --- unknown role --------------------------------------------------------------

// TestEndToEndUnknownRoleIsTheSameClaim confirms against a real server that an
// unknown role and a wrong password are one outcome.
//
// PostgreSQL issues a mock salt for a role that does not exist, deliberately, so
// a client cannot enumerate roles. The finding must therefore be the same narrow
// credential-material claim and must not say the role is unknown.
func TestEndToEndUnknownRoleIsTheSameClaim(t *testing.T) {
	s := healthy()
	s.role = "nosuchrole-svcd"
	s.password = "irrelevant-pw"
	o := run(t, s)

	auth := o.requireState(t, servicepostgres.StepAuthentication,
		domain.StateFail, domain.FailureAuthCredentialsRejected)
	if got := stringAttr(t, auth, servicepostgres.AttrSQLState); got != "28P01" {
		t.Errorf("sqlstate = %q, want 28P01", got)
	}

	f := o.requireOneFinding(t, diagnosispostgres.CodeCredentialsRejected)
	// The recommendation legitimately says that the endpoint's own log is the
	// only place a wrong secret and an unknown role are distinguished — that is
	// a refusal to distinguish, not a claim. What must be absent is any sentence
	// asserting which of the two happened.
	requireProseExcludes(t, f,
		"role does not exist", "no such role", "the role is unknown", "role was not found")
}

// --- B. missing database, 3D000 -------------------------------------------------

func TestEndToEndMissingDatabase(t *testing.T) {
	s := healthy()
	s.database = missingDatabase
	o := run(t, s)

	// Authentication passed and stays passed: a later answer does not revise an
	// earlier one.
	o.requireState(t, servicepostgres.StepAuthentication, domain.StatePass, domain.FailureNone)

	session := o.requireState(t, servicepostgres.StepSession,
		domain.StateFail, domain.FailureResourceNotFound)
	if got := stringAttr(t, session, servicepostgres.AttrSQLState); got != "3D000" {
		t.Errorf("sqlstate = %q, want 3D000", got)
	}

	f := o.requireOneFinding(t, diagnosispostgres.CodeDatabaseNotFound)
	requireProseExcludes(t, f,
		"does not exist", "never existed", "was dropped", "create database",
		"catalog is healthy", "filesystem")

	requireProblemsFound(t, o)
	requireRefsResolve(t, o, f)
	requireRedactable(t, o.report)
}

// --- C. CONNECT denied, 42501 ---------------------------------------------------

func TestEndToEndConnectDenied(t *testing.T) {
	s := healthy()
	s.role, s.password, s.database = norightsRole, norightsPassword, closedDatabase
	o := run(t, s)

	o.requireState(t, servicepostgres.StepAuthentication, domain.StatePass, domain.FailureNone)

	session := o.requireState(t, servicepostgres.StepSession,
		domain.StateFail, domain.FailureAuthzDenied)
	if got := stringAttr(t, session, servicepostgres.AttrSQLState); got != "42501" {
		t.Errorf("sqlstate = %q, want 42501", got)
	}

	f := o.requireOneFinding(t, diagnosispostgres.CodeDatabaseConnectDenied)
	requireProseExcludes(t, f,
		"table", "schema", "write access", "superuser", "role membership", "password", "grant ")

	requireProblemsFound(t, o)
	requireRefsResolve(t, o, f)
}

// --- E. TLS declined -------------------------------------------------------------

// TestEndToEndTLSDeclined runs against the plaintext-only listener.
//
// A real server really answers 'N' to a real SSLRequest. Simulating that byte
// would prove nothing about the negotiation, which is why the environment grows
// a second listener rather than the test growing a fake.
func TestEndToEndTLSDeclined(t *testing.T) {
	o := run(t, scenario{
		port: pgPlaintextPort, plan: postgres.TLSRequired, trustCA: true,
		role: scramRole, password: scramPassword, database: database,
	})

	ssl := o.requireState(t, servicepostgres.StepSSLRequest,
		domain.StateFail, domain.FailureProtocolUnsupportedCapability)

	offered, ok := ssl.Attribute(servicepostgres.AttrSSLOffered)
	if !ok {
		t.Fatal("no postgres.ssl.offered attribute; the answer was not recorded")
	}
	if v, _ := offered.Bool(); v {
		t.Error("postgres.ssl.offered = true on a declined negotiation")
	}

	// Nothing downstream may have succeeded.
	o.requireNoSuccessfulNodeAtOrBelow(t, servicepostgres.StepStartup)
	o.requireAbsent(t, servicepostgres.StepAuthentication)
	o.requireAbsent(t, servicepostgres.StepSession)

	f := o.requireOneFinding(t, diagnosispostgres.CodeTLSDeclined)
	requireProseExcludes(t, f, "does not support tls", "tls is disabled", "certificate")

	// And specifically: no generic TLS finding was manufactured.
	for _, got := range o.codes() {
		if got != diagnosispostgres.CodeTLSDeclined {
			t.Errorf("an extra finding %s fired on transport evidence", got)
		}
	}
	requireProblemsFound(t, o)
}

// --- G. host-based refusal, 28000 -------------------------------------------------

func TestEndToEndConnectionNotPermitted(t *testing.T) {
	s := healthy()
	s.role, s.password = rejectRole, "pw-rejectuser"
	o := run(t, s)

	startup := o.requireState(t, servicepostgres.StepStartup,
		domain.StateFail, domain.FailureAuthzNotPermitted)
	if got := stringAttr(t, startup, servicepostgres.AttrSQLState); got != "28000" {
		t.Errorf("sqlstate = %q, want 28000", got)
	}

	// The refusal arrived before authentication was requested, so no
	// authentication node exists and no credential was evaluated.
	o.requireAbsent(t, servicepostgres.StepAuthentication)
	o.requireAbsent(t, servicepostgres.StepSession)

	f := o.requireOneFinding(t, diagnosispostgres.CodeConnectionNotPermitted)
	if !f.VantageDependent() {
		t.Error("vantageDependent = false; host-based rules match the source address")
	}
	requireProseExcludes(t, f,
		"password", "credential is", "globally", "authenticated successfully")

	requireNoCredentialAnywhere(t, o, "pw-rejectuser")
}

// --- mechanism findings against real servers ---------------------------------------

// TestEndToEndDeclinedMechanisms covers the two INFO cases with real servers
// demanding methods svcdoctor does not perform.
func TestEndToEndDeclinedMechanisms(t *testing.T) {
	for _, tt := range []struct {
		name, role, password string
	}{
		{"md5", md5Role, "md5-pw"},
		{"cleartext", cleartextRole, "cleartext-pw"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := healthy()
			s.role, s.password = tt.role, tt.password
			o := run(t, s)

			o.requireState(t, servicepostgres.StepAuthentication,
				domain.StateUnknown, domain.FailureAuthMechanismUnsupported)
			o.requireAbsent(t, servicepostgres.StepSession)

			f := o.requireOneFinding(t, diagnosispostgres.CodeMechanismUnavailable)
			if f.Severity() != domain.SeverityInfo {
				t.Errorf("severity = %s, want INFO; a svcdoctor gap is not a target defect",
					f.Severity())
			}
			// An UNKNOWN node must not read as a refusal.
			requireProseExcludes(t, f, "credential is", "credential was rejected", "misconfigured")
			requireNoCredentialAnywhere(t, o, tt.password)
		})
	}
}

// TestEndToEndTrustPathRecordsNoAuthenticationNode confirms the shape every
// session rule must tolerate.
//
// A server demanding nothing produces no authentication node — svcdoctor
// presented nothing — so the session's parent is the startup node.
func TestEndToEndTrustPathRecordsNoAuthenticationNode(t *testing.T) {
	s := healthy()
	s.role, s.password = trustRole, ""
	o := run(t, s)

	startup := o.requireState(t, servicepostgres.StepStartup, domain.StatePass, domain.FailureNone)
	if got := stringAttr(t, startup, servicepostgres.AttrAuthMethod); got != "ok" {
		t.Fatalf("auth method = %q, want ok", got)
	}
	o.requireAbsent(t, servicepostgres.StepAuthentication)
	o.requireState(t, servicepostgres.StepSession, domain.StatePass, domain.FailureNone)
	o.requireNoFindings(t)
}

// TestEndToEndCredentialWithheldOverPlaintext exercises the fail-closed policy
// against a real server that really offers no TLS.
func TestEndToEndCredentialWithheldOverPlaintext(t *testing.T) {
	o := run(t, scenario{
		port: pgPlaintextPort, plan: postgres.TLSDisabled,
		role: scramRole, password: scramPassword, database: database,
	})

	o.requireState(t, servicepostgres.StepSSLRequest,
		domain.StateSkipped, domain.FailureExecSkippedByPolicy)
	o.requireState(t, servicepostgres.StepAuthentication,
		domain.StateSkipped, domain.FailureExecSkippedByPolicy)
	o.requireAbsent(t, servicepostgres.StepSession)

	f := o.requireOneFinding(t, diagnosispostgres.CodeCredentialWithheld)
	if f.Severity() != domain.SeverityWarn {
		t.Errorf("severity = %s, want WARN", f.Severity())
	}
	requireProseExcludes(t, f, "was rejected", "endpoint refused", "authentication failed")

	// Zero credential-derived bytes were sent, so the password cannot be
	// anywhere — and this is the path where a regression would be worst.
	requireNoCredentialAnywhere(t, o, scramPassword)
}

// --- redaction, from a real run -------------------------------------------------

// TestEndToEndRedactionRemovesEveryIdentityCanary is the security check for the
// composed path.
//
// The canaries reach the graph the ordinary way — as identity attributes the
// startup step records — so this proves the whole pipeline, not a constructor.
func TestEndToEndRedactionRemovesEveryIdentityCanary(t *testing.T) {
	// Both cases carry the role canary. The database canary differs on purpose:
	// the failing run names a database that does not exist, and that name is
	// identity too — redaction must remove a requested name whether or not the
	// endpoint has one to match it.
	for _, tt := range []struct {
		name     string
		database string
		wantCode domain.FindingCode
	}{
		{"healthy", canaryDatabase, ""},
		{"failing", missingDatabase, diagnosispostgres.CodeDatabaseNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := healthy()
			s.role, s.password, s.database = canaryRole, canaryPassword, tt.database
			o := run(t, s)

			if tt.wantCode != "" {
				o.requireOneFinding(t, tt.wantCode)
			} else {
				o.requireNoFindings(t)
			}

			local := encode(t, o.report)

			// The canaries must really be in the local report, or the test
			// proves nothing about their removal.
			for _, canary := range []string{canaryRole, tt.database} {
				if !strings.Contains(local, canary) {
					t.Fatalf("canary %q is absent from LOCAL_FULL; the test would prove nothing",
						canary)
				}
			}
			// The password must never have been there in the first place.
			if strings.Contains(local, canaryPassword) {
				t.Fatal("the credential reached the local report")
			}

			shareable, err := redaction.Redact(o.report)
			if err != nil {
				t.Fatalf("Redact: %v", err)
			}
			encoded := encode(t, shareable)

			for _, canary := range []string{canaryRole, tt.database, canaryPassword, pgHost} {
				if strings.Contains(encoded, canary) {
					t.Errorf("canary %q survived into the shareable report", canary)
				}
			}

			// Semantics survive.
			if shareable.Summary().Status() != o.report.Summary().Status() {
				t.Error("redaction changed the report status")
			}
			if shareable.Graph().Len() != o.graph.Len() {
				t.Errorf("redaction changed the graph size: %d -> %d",
					o.graph.Len(), shareable.Graph().Len())
			}
			before, after := o.report.Findings(), shareable.Findings()
			if len(before) != len(after) {
				t.Fatalf("finding count changed: %d -> %d", len(before), len(after))
			}
			for i := range before {
				a, b := before[i], after[i]
				if a.Code() != b.Code() || a.Kind() != b.Kind() ||
					a.Severity() != b.Severity() || a.Confidence() != b.Confidence() ||
					a.Layer() != b.Layer() || a.VantageDependent() != b.VantageDependent() {
					t.Errorf("%s: semantics changed under redaction", a.Code())
				}
				if a.Summary() != b.Summary() || a.Detail() != b.Detail() {
					t.Errorf("%s: prose changed under redaction", a.Code())
				}
				for _, ref := range b.EvidenceRefs() {
					if _, ok := shareable.Graph().Node(ref); !ok {
						t.Errorf("%s: reference %q does not resolve after redaction", a.Code(), ref)
					}
				}
			}

			// Idempotent.
			twice, err := redaction.Redact(shareable)
			if err != nil {
				t.Fatalf("Redact twice: %v", err)
			}
			if encode(t, twice) != encoded {
				t.Error("redaction is not idempotent over a real report")
			}
		})
	}
}

// --- helpers ---------------------------------------------------------------------

func encode(t *testing.T, report domain.Report) string {
	t.Helper()
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encoding the report: %v", err)
	}
	return string(out)
}

// requireRedactable proves a real report can always be shared.
func requireRedactable(t *testing.T, report domain.Report) {
	t.Helper()

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	once := encode(t, shareable)

	twice, err := redaction.Redact(shareable)
	if err != nil {
		t.Fatalf("Redact twice: %v", err)
	}
	if encode(t, twice) != once {
		t.Error("redaction is not idempotent")
	}
}

func requireProblemsFound(t *testing.T, o outcome) {
	t.Helper()
	if got := o.report.Summary().Status(); got != domain.SummaryStatusProblemsFound {
		t.Errorf("report status = %s, want PROBLEMS_FOUND", got)
	}
}

// requireRefsResolve pins that every reference names a node in the real graph.
func requireRefsResolve(t *testing.T, o outcome, f domain.Finding) {
	t.Helper()
	for _, ref := range f.EvidenceRefs() {
		if _, ok := o.graph.Node(ref); !ok {
			t.Errorf("%s references %q, which is not in the graph", f.Code(), ref)
		}
	}
}

// requireProseExcludes applies the wording contract to a real finding.
func requireProseExcludes(t *testing.T, f domain.Finding, phrases ...string) {
	t.Helper()

	text := strings.ToLower(f.Summary() + "\n" + f.Detail())
	for _, r := range f.Recommendations() {
		text += "\n" + strings.ToLower(r.Action())
	}
	for _, phrase := range phrases {
		if strings.Contains(text, strings.ToLower(phrase)) {
			t.Errorf("%s claims %q, which its evidence does not support", f.Code(), phrase)
		}
	}
}

// requireNoCredentialAnywhere sweeps the whole composed output for the secret.
//
// Lower-level tests remain authoritative for the SCRAM intermediates — the
// nonce, salt, proof and signature — which no field of the wire result holds.
// This one proves the composition path does not reintroduce the credential.
func requireNoCredentialAnywhere(t *testing.T, o outcome, password string) {
	t.Helper()

	local := encode(t, o.report)
	if strings.Contains(local, password) {
		t.Error("the credential reached the local report")
	}

	shareable, err := redaction.Redact(o.report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(encode(t, shareable), password) {
		t.Error("the credential reached the shareable report")
	}

	for _, f := range o.findings {
		text := f.Summary() + "\n" + f.Detail()
		for _, r := range f.Recommendations() {
			text += "\n" + r.Action()
		}
		if strings.Contains(text, password) {
			t.Errorf("%s carries the credential in prose", f.Code())
		}
	}
}
