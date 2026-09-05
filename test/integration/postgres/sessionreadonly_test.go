//go:build integration

package postgres

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// Phase 10.7B against a real PostgreSQL 18 server whose sessions default to
// read-only transactions.
//
// # Why this container exists
//
// `default_transaction_read_only` has been recorded on every passing session
// since Phase 4.5 and **no fixture had ever produced it as "on"**. ADR 0089
// selected the observation as a Class 1 activation — the fact was already on the
// wire — and made this measurement the condition of landing it, for the reason
// ADR 0069 section 8 gives about `VHOST_DOWN`: membership requires having watched
// a real endpoint produce it.
//
// The `svcd-pg-readonly` container is started with
// `-c default_transaction_read_only=on`. **No statement sets it.** The value
// therefore arrives in the `ParameterStatus` stream ahead of `ReadyForQuery`
// exactly as a real deployment's would, which is the only thing that makes this
// a protocol measurement rather than a fixture assertion.

// pgReadOnlyPort is the plaintext listener whose sessions default to read only.
const pgReadOnlyPort = 55434

// The role and database this container has, which are the ones it is born with.
//
// It runs no init script — see the compose comment — so the only role is the
// bootstrap superuser and the only database is `postgres`. `trust` authentication
// means a complete session is reachable with nothing to present, which keeps the
// credential-transport policy out of the measurement entirely: this test is about
// one parameter, not about authentication.
const (
	readOnlyRole     = "postgres"
	readOnlyDatabase = "postgres"
)

// readOnlyParams targets that listener, credential-free and without TLS.
func readOnlyParams(t *testing.T) app.PostgresParams {
	t.Helper()

	// runParams leaves Credential zero when the password is empty, which is what
	// a `trust` role needs and what keeps this run credential-free.
	params := runParams(t, readOnlyRole, "", readOnlyDatabase)
	params.Port = pgReadOnlyPort
	params.TLS = postgres.TLSDisabled
	params.TLSOptions = postgres.TLSOptions{}
	return params
}

// TestRealServerReportsAReadOnlyDefaultAndSvcdoctorClaimsNothing is the
// exemplar, end to end.
//
// It asserts the whole contract rather than the value alone: the parameter is on
// the session node with the value the server was started with, **no finding is
// produced**, the report stays OK, the operator is told what the server said in
// the result block, and none of svcdoctor's own words turn it into a claim about
// the server, the database or the application's writes.
func TestRealServerReportsAReadOnlyDefaultAndSvcdoctorClaimsNothing(t *testing.T) {
	report := runApp(t, readOnlyParams(t)).Report()

	sessions := nodesAt(report, servicepostgres.StepSession)
	if len(sessions) != 1 || sessions[0].State() != domain.StatePass {
		t.Fatalf("the run did not establish a session; there is no parameter to observe")
	}

	// 1. The server emitted it, and 2. svcdoctor normalized it.
	value, ok := sessions[0].Attribute(servicepostgres.AttrDefaultTransactionReadOnly)
	if !ok {
		t.Fatal("the session node carries no default_transaction_read_only; the " +
			"container is started with -c default_transaction_read_only=on and every " +
			"supported PostgreSQL reports it")
	}
	mode, _ := value.Str()
	if mode != "on" {
		t.Fatalf("default_transaction_read_only = %q, want on; the fixture sets it at "+
			"startup, so anything else means the value did not survive the wire", mode)
	}

	// 3. It is in canonical evidence, and the recovery sibling is unaffected.
	recovery, ok := sessions[0].Attribute(servicepostgres.AttrInHotStandby)
	if !ok {
		t.Fatal("the session node carries no in_hot_standby")
	}
	if got, _ := recovery.Str(); got != "off" {
		t.Errorf("in_hot_standby = %q, want off; this server is a primary, and a "+
			"read-only default is not recovery", got)
	}

	// 5. and 6. No finding, no recommendation, no status movement.
	if len(report.Findings()) != 0 {
		t.Errorf("a read-only default produced %v; it is an observation, and none of "+
			"these facts is a problem without an expectation (ADR 0040 section 20)",
			codesIn(report))
	}
	if got := report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", got)
	}

	// 4. The operator sees it, in the result block.
	terminal := terminalOf(t, report)
	// Collapsed past the tabwriter padding: the wording is the assertion, the
	// column arithmetic is not.
	collapsed := strings.Join(strings.Fields(terminal), " ")
	for _, want := range []string{
		"default transaction read-only on",
		"not in recovery",
		"This session reported that its transactions default to read-only",
	} {
		if !strings.Contains(collapsed, want) {
			t.Errorf("the result block does not report %q:\n\n%s", want, terminal)
		}
	}

	// And svcdoctor never strengthens it. Each of these is a sentence a
	// reasonable person would write from "read only", and none of them is
	// supported: the parameter that settles a given transaction is the
	// session-local `transaction_read_only`, which needs SQL.
	lowered := strings.ToLower(terminal)
	for _, forbidden := range []string{
		"server is read", "database is read", "backend is read",
		"read-only server", "read-only database",
		"writes will", "cannot write", "unable to write", "writable",
		"replica", "standby", "misconfigur", "warning", "expected", "should be",
		// Phase 10.7B's revision. `off` is never "read write", and `on` is
		// never a positive statement about what the session can do — so neither
		// concept may appear anywhere in the document.
		"read write", "read-write",
	} {
		if strings.Contains(lowered, forbidden) {
			t.Errorf("the observation was strengthened into %q:\n\n%s", forbidden, terminal)
		}
	}
}
