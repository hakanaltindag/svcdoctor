//go:build integration

package postgres

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	renderjson "github.com/hakanaltindag/svcdoctor/internal/render/json"
	renderterminal "github.com/hakanaltindag/svcdoctor/internal/render/terminal"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// Phase 10.3 against a real PostgreSQL 18 server.
//
// Everything here goes through `app.DiagnosePostgres`: the real resolver, the
// real dialer, the real in-band TLS handshake, the real SCRAM exchange, the real
// server's own answers, the production rule set, a real canonical report, real
// redaction and both renderers. Nothing hand-authors evidence and nothing
// invokes a rule directly.
//
// The unit corpus proves what the rules say about a graph. This proves that the
// graphs a real server produces are the ones the rules were written for — which
// is the half a synthetic fixture cannot establish, and the half Phase 7.3A
// found svcdoctor getting wrong in the field.

// limitRole logs in successfully and is then refused at a connection limit.
//
// `CONNECTION LIMIT 0` makes 53300 a property of the fixture's configuration
// rather than of a race: every login for this role is refused at
// InitializeSessionUserId, after authentication has completed and before
// ReadyForQuery. No connection is held, nothing is exhausted, and an interrupted
// run leaves the server exactly as it found it.
//
// **It is also the counterexample the claim's wording is bounded by.** The
// server here has connections to spare and still answers 53300, so this fixture
// would falsify any sentence asserting that the endpoint had no connection slot
// available — which is why TestRealServerConnectionLimitInventsNoCause scans for
// scope overclaims beside cause overclaims.
const (
	limitRole     = "limituser"
	limitPassword = "pw-limituser"
)

// --- the connection-limit claim, from a real refusal ---------------------------

// TestRealServerConnectionLimitIsDiagnosed is the phase's headline for
// PostgreSQL: a real server names its own condition and svcdoctor repeats it and
// stops.
func TestRealServerConnectionLimitIsDiagnosed(t *testing.T) {
	report := runApp(t, runParams(t, limitRole, limitPassword, database)).Report()

	// The journey really happened: TLS, startup, SCRAM and a session attempt.
	// Without this the assertions below could pass on a run that failed earlier.
	for _, step := range []domain.Step{
		servicepostgres.StepSSLRequest,
		servicepostgres.StepStartup,
		servicepostgres.StepAuthentication,
		servicepostgres.StepSession,
	} {
		if len(nodesAt(report, step)) != 1 {
			t.Fatalf("%d %s nodes; the run did not reach the session window",
				len(nodesAt(report, step)), step)
		}
	}
	// Authentication passed. That is what makes the claim's first half true, and
	// it is the fact a synthetic fixture can only assert.
	if got := nodesAt(report, servicepostgres.StepAuthentication)[0].State(); got != domain.StatePass {
		t.Fatalf("authentication state = %s, want PASS: the server accepted the "+
			"credential and then refused the session", got)
	}

	session := nodesAt(report, servicepostgres.StepSession)[0]
	if got := session.State(); got != domain.StateFail {
		t.Fatalf("session state = %s, want FAIL", got)
	}
	if got := session.FailureClass(); got != domain.FailureResourceLimitReached {
		t.Fatalf("session class = %s, want RESOURCE_LIMIT_REACHED", got)
	}
	// The server's own five characters, read off the wire rather than assumed.
	code, ok := session.Attribute(servicepostgres.AttrSQLState)
	if !ok {
		t.Fatal("the session node carries no SQLSTATE")
	}
	if got, _ := code.Str(); got != "53300" {
		t.Errorf("SQLSTATE = %q, want 53300", got)
	}

	f := requireSingleFinding(t, report, diagnosispostgres.CodeConnectionLimitReached)
	if f.Kind() != domain.FindingKindConfirmed || f.Confidence() != domain.ConfidenceHigh {
		t.Errorf("%s at %s, want CONFIRMED at HIGH: the peer named the condition",
			f.Kind(), f.Confidence())
	}
	if f.Severity() != domain.SeverityError {
		t.Errorf("severity = %s, want ERROR", f.Severity())
	}
	if f.VantageDependent() {
		t.Error("the claim is marked vantage-dependent; the server named this " +
			"condition in its own protocol and svcdoctor did not infer it from the " +
			"address it dialled from")
	}
	if !strings.Contains(f.Detail(), "too_many_connections") ||
		!strings.Contains(f.Detail(), "SQLSTATE 53300") {
		t.Errorf("the claim does not restate what the server said:\n%s", f.Detail())
	}
	// And it restates it at the scope the server spoke at. This server refused
	// `limituser` at a limit attached to the role while having connections to
	// spare, so the claim has to be about this attempt and has to say that the
	// response identifies no limit.
	if !strings.Contains(f.Detail(), "a connection limit that applied to this attempted session") ||
		!strings.Contains(f.Detail(), "Which limit was reached is not in the response") {
		t.Errorf("the claim does not bound itself to the attempted session:\n%s", f.Detail())
	}

	// And the exit contract: an ERROR finding is a target-side problem.
	if got := report.Summary().Status(); got != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", got)
	}
}

// TestRealServerConnectionLimitInventsNoCause is the forbidden-claim gate, run
// over the output an operator and a CI job actually receive.
func TestRealServerConnectionLimitInventsNoCause(t *testing.T) {
	report := runApp(t, runParams(t, limitRole, limitPassword, database)).Report()

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	for name, prose := range map[string]string{
		"local report":     findingProse(report),
		"shareable report": findingProse(shareable),
		"terminal":         terminalOf(t, report),
	} {
		lowered := strings.ToLower(prose)
		// Causes, then scopes. The second list is the one this fixture is
		// uniquely placed to enforce: `limituser` is refused by a limit on the
		// role while the server has connections to spare, so any sentence
		// asserting an endpoint-wide shortage is falsified by the very run that
		// produced the report being scanned.
		for _, forbidden := range []string{
			"connection leak", "leak", "max_connections", "too low", "pool",
			"increase", "raise", "spike", "traffic", "memory", "misconfigur",
			"exhausted", "capacity", "restart", "postgresql server is",
			"no connection slot", "no slot", "slot free", "free slot",
			"out of connections", "no connections left", "no connection left",
		} {
			if strings.Contains(lowered, forbidden) {
				t.Errorf("the %s contains %q.\n\n"+
					"53300 proves that a connection limit applicable to this attempted "+
					"session was reached — here, one attached to the role. It does not "+
					"prove which limit, why, for how long, that the endpoint had "+
					"nothing left for another session, or what to change.\n\n%s",
					name, forbidden, prose)
			}
		}
	}
}

// --- the admission scope, from a real pg_hba refusal ---------------------------

// TestRealServerAdmissionScopeOverTwoAddresses drives the aggregate against a
// real server on both loopback families.
//
// `rejectuser` is refused by `pg_hba` before any credential is requested, on
// every address, so a `localhost` target reaching two addresses produces two
// real `28000` refusals and a **complete** set — which is the uniform branch of
// the admission scope, stated over evidence a real server produced.
//
// It skips rather than fails when the environment gives only one address: the
// dual-stack contract is a property of the host's resolver, and
// TestAppDualStackDiscoversEveryPathAndAuthenticatesOnce takes the same position
// for the same reason.
func TestRealServerAdmissionScopeOverTwoAddresses(t *testing.T) {
	params := runParams(t, rejectRole, "pw-rejectuser", database)
	// A name, not a literal, so the run really resolves more than one address.
	params.Host = "localhost"
	params.TLSOptions.ServerName = "localhost"
	endpoint, err := security.NewEndpoint("localhost", pgTLSPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(
		endpoint, rejectRole, security.NewSecret("pw-rejectuser"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	params.Credential = credential

	report := runApp(t, params).Report()

	startups := nodesAt(report, servicepostgres.StepStartup)
	if len(startups) < 2 {
		t.Skipf("localhost produced %d startup observation(s) in this environment; "+
			"the admission scope needs at least two addresses", len(startups))
	}

	// Every address really was refused, by a real server, before any credential.
	for _, node := range startups {
		if node.State() != domain.StateFail ||
			node.FailureClass() != domain.FailureAuthzNotPermitted {
			t.Fatalf("startup at %s is %s/%s, want FAIL/AUTHZ_NOT_PERMITTED",
				node.Subject().Ref(), node.State(), node.FailureClass())
		}
	}
	// And no credential crossed any of them, which is what "before evaluating
	// any credential" rests on.
	if got := len(nodesAt(report, servicepostgres.StepAuthentication)); got != 0 {
		t.Errorf("%d authentication nodes; pg_hba refused before authentication "+
			"was requested", got)
	}

	var scope []domain.Finding
	var perAddress []domain.Finding
	for _, f := range report.Findings() {
		switch f.Code() {
		case diagnosispostgres.CodeAdmissionScope:
			scope = append(scope, f)
		case diagnosispostgres.CodeConnectionNotPermitted:
			perAddress = append(perAddress, f)
		}
	}

	if len(scope) != 1 {
		t.Fatalf("%d admission-scope findings, want exactly 1: %v", len(scope), codesIn(report))
	}
	if len(perAddress) != len(startups) {
		t.Errorf("%d per-address refusal findings for %d refused addresses",
			len(perAddress), len(startups))
	}

	f := scope[0]
	if f.Severity() != domain.SeverityInfo {
		t.Errorf("severity = %s, want INFO; a count is never a verdict", f.Severity())
	}
	// The subject is the target the operator named, not one of the addresses.
	if f.Subject().Kind() != domain.SubjectKindTarget {
		t.Errorf("subject kind = %s, want TARGET", f.Subject().Kind())
	}
	for _, other := range perAddress {
		if other.Subject() == f.Subject() {
			t.Errorf("the set-level claim borrowed the address subject %s",
				other.Subject().Ref())
		}
	}
	// The complete, uniform sentence, over a set a real server closed.
	want := "at all " + itoa(len(startups)) + " addresses this target resolved to"
	if !strings.Contains(f.Summary(), want) {
		t.Errorf("summary does not state the complete set:\nwant substring %q\ngot %s",
			want, f.Summary())
	}
	if strings.Contains(f.Summary(), "no admission decision was observed") {
		t.Errorf("a complete set was reported as partial: %s", f.Summary())
	}

	t.Logf("addresses=%d scope=%q", len(startups), f.Summary())
}

// TestRealServerAdmissionScopeIsSilentOnOneAddress is the gate that keeps the
// aggregate out of ordinary runs.
//
// The overwhelming majority of PostgreSQL targets resolve to one address, and
// for those the aggregate would restate what the per-address finding already
// says. `pgHost` is a literal, so this is exactly that run.
func TestRealServerAdmissionScopeIsSilentOnOneAddress(t *testing.T) {
	report := runApp(t, runParams(t, rejectRole, "pw-rejectuser", database)).Report()

	if got := len(nodesAt(report, servicepostgres.StepStartup)); got != 1 {
		t.Fatalf("%d startup nodes against a literal target, want 1", got)
	}
	for _, f := range report.Findings() {
		if f.Code() == diagnosispostgres.CodeAdmissionScope {
			t.Errorf("a single-address run produced an admission scope: %s", f.Summary())
		}
	}
	requireSingleFinding(t, report, diagnosispostgres.CodeConnectionNotPermitted)
}

// --- the role observation, from a real ParameterStatus -------------------------

// TestRealServerReportsItsRecoveryStateAndSvcdoctorClaimsNothing is the role
// exemplar, end to end.
//
// The validation server is a primary, so `in_hot_standby` arrives as "off". What
// is asserted is not the value — that would be asserting the fixture — but the
// whole shape of the contract: the parameter is on the session node, **no
// finding is produced**, the report stays OK, and the operator is told what the
// server said in the result block rather than in a claim.
func TestRealServerReportsItsRecoveryStateAndSvcdoctorClaimsNothing(t *testing.T) {
	report := runApp(t, runParams(t, scramRole, scramPassword, database)).Report()

	sessions := nodesAt(report, servicepostgres.StepSession)
	if len(sessions) != 1 || sessions[0].State() != domain.StatePass {
		t.Fatalf("the run did not establish a session; there is no role to observe")
	}
	value, ok := sessions[0].Attribute(servicepostgres.AttrInHotStandby)
	if !ok {
		t.Fatal("the session node carries no in_hot_standby; PostgreSQL 14 and later " +
			"send it, and this fixture is 18")
	}
	recovery, _ := value.Str()
	if recovery != "on" && recovery != "off" {
		t.Fatalf("in_hot_standby = %q, want on or off", recovery)
	}

	// A passing PostgreSQL path produces zero findings, and Phase 10.3 did not
	// change that. The role is an observation.
	if len(report.Findings()) != 0 {
		t.Errorf("a healthy run produced %v; a reported role is not a claim",
			codesIn(report))
	}
	if got := report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", got)
	}

	terminal := terminalOf(t, report)
	want := "not in recovery"
	if recovery == "on" {
		want = "in recovery"
	}
	if !strings.Contains(terminal, "recovery") || !strings.Contains(terminal, want) {
		t.Errorf("the result block does not report the observed recovery state %q:\n\n%s",
			recovery, terminal)
	}

	// And it is never graded. "primary", "replica" and "standby" are endpoint
	// identities a pooler's cached value would falsify, and no expectation
	// exists to compare any of it against.
	lowered := strings.ToLower(terminal)
	for _, forbidden := range []string{
		"primary", "replica", "standby", "warning", "wrong", "expected",
		"failover", "promote", "split",
	} {
		if strings.Contains(lowered, forbidden) {
			t.Errorf("the terminal output contains %q beside a role observation:\n\n%s",
				forbidden, terminal)
		}
	}
}

// TestRealServerSessionParametersReachNoFinding is the standing gate, restated
// against a real server.
//
// ADR 0040 section 20 and ADR 0085 section 4: `in_hot_standby`,
// `default_transaction_read_only`, `is_superuser` and `server_version` are
// recorded, are in the report, and no rule reads any of them. Changing that is a
// decision and not a rule quietly starting to assert.
func TestRealServerSessionParametersReachNoFinding(t *testing.T) {
	report := runApp(t, runParams(t, scramRole, scramPassword, database)).Report()

	session := nodesAt(report, servicepostgres.StepSession)[0]
	present := 0
	for _, key := range []domain.AttributeKey{
		servicepostgres.AttrInHotStandby,
		servicepostgres.AttrServerVersion,
		"postgres.default_transaction_read_only",
		"postgres.is_superuser",
	} {
		if _, ok := session.Attribute(key); ok {
			present++
		}
	}
	if present < 3 {
		t.Fatalf("only %d session parameters are recorded; this guard would pass "+
			"for want of anything to read", present)
	}
	if len(report.Findings()) != 0 {
		t.Errorf("session parameters produced %v", codesIn(report))
	}

	// The version really is the server's own unbounded string, and it reaches
	// the report's evidence. It deliberately reaches no operator-facing
	// observation line: ParameterStatus values are unbounded at the wire
	// boundary, and Phase 10.3 declined to widen that surface.
	version, ok := session.Attribute(servicepostgres.AttrServerVersion)
	if !ok {
		t.Fatal("the session node carries no server_version")
	}
	text, _ := version.Str()
	if text == "" {
		t.Fatal("server_version is empty")
	}
	if strings.Contains(terminalOf(t, report), text) {
		t.Errorf("the raw server_version %q reached the terminal", text)
	}
}

// --- the failure boundary and the server semantics beside it -------------------

// TestRealServerBoundaryAndServerSemanticsAreTwoFindings is section 17 of the
// phase brief, measured.
//
// The generic boundary says *where* observation stopped succeeding. The
// PostgreSQL claim says *what the server reported there*. They are two findings
// with two codes over one run, and Phase 10.3 added no second PostgreSQL
// boundary code.
func TestRealServerBoundaryAndServerSemanticsAreTwoFindings(t *testing.T) {
	report := runApp(t, runParams(t, limitRole, limitPassword, database)).Report()

	var boundary, server int
	for _, f := range report.Findings() {
		switch f.Code() {
		case "DIAG_FAILURE_BOUNDARY":
			boundary++
			if f.Severity() != domain.SeverityInfo {
				t.Errorf("the boundary is %s, want INFO", f.Severity())
			}
		case diagnosispostgres.CodeConnectionLimitReached:
			server++
		default:
			t.Errorf("unexpected finding %s", f.Code())
		}
	}
	if boundary != 1 || server != 1 {
		t.Errorf("%d boundary and %d server findings, want 1 and 1: %v",
			boundary, server, codesIn(report))
	}

	// And the boundary is filed where the failure was evidenced, which for a
	// session refusal is the auth layer — not at the transport stages, every one
	// of which passed.
	for _, f := range report.Findings() {
		if f.Code() != "DIAG_FAILURE_BOUNDARY" {
			continue
		}
		if f.Layer() != domain.LayerAuth {
			t.Errorf("the boundary is at %s, want auth", f.Layer())
		}
	}
}

// TestRealServerJSONIsConsumableByCI proves the new codes survive the canonical
// projection a CI job reads.
func TestRealServerJSONIsConsumableByCI(t *testing.T) {
	report := runApp(t, runParams(t, limitRole, limitPassword, database)).Report()

	var out bytes.Buffer
	if err := renderjson.Write(&out, report); err != nil {
		t.Fatalf("json.Write: %v", err)
	}
	body := out.String()

	if !strings.Contains(body, string(diagnosispostgres.CodeConnectionLimitReached)) {
		t.Errorf("the canonical JSON does not carry the finding code:\n%s", body)
	}
	if !strings.Contains(body, `"schemaVersion": 1`) &&
		!strings.Contains(body, `"schemaVersion":1`) {
		t.Errorf("the report is not schema version 1:\n%s", body)
	}

	// The shareable projection keeps the code and loses the identity.
	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	var redacted bytes.Buffer
	if err := renderjson.Write(&redacted, shareable); err != nil {
		t.Fatalf("json.Write: %v", err)
	}
	if !strings.Contains(redacted.String(), string(diagnosispostgres.CodeConnectionLimitReached)) {
		t.Error("the shareable projection dropped the finding code")
	}
	if strings.Contains(redacted.String(), limitRole) {
		t.Error("the role name survived redaction")
	}
}

// --- helpers -------------------------------------------------------------------

// findingProse is everything a report *claims*, which is the surface the
// false-positive policy governs.
func findingProse(report domain.Report) string {
	var b strings.Builder
	for _, f := range report.Findings() {
		b.WriteString(f.Summary())
		b.WriteString("\n")
		b.WriteString(f.Detail())
		b.WriteString("\n")
		b.WriteString(f.Discriminator())
		b.WriteString("\n")
		for _, r := range f.Recommendations() {
			b.WriteString(r.Action())
			b.WriteString("\n")
			// The rationale is report-visible prose since Phase 10.4B, so it
			// is scanned like every other prose field. A forbidden cause
			// smuggled into a rationale is the same overclaim wearing the
			// newest field.
			b.WriteString(r.Rationale())
			b.WriteString("\n")
		}
	}
	return b.String()
}

// terminalOf renders the report the way an operator sees it.
func terminalOf(t *testing.T, report domain.Report) string {
	t.Helper()

	var out bytes.Buffer
	if err := renderterminal.Write(&out, render.Input{Report: report}); err != nil {
		t.Fatalf("terminal.Write: %v", err)
	}
	return out.String()
}

// itoa avoids importing strconv for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// Compile-time proof that these tests drive the production entry point.
var _ = app.DiagnosePostgres
