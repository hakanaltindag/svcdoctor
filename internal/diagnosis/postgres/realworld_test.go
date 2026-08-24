package postgres

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// Real-world claim discipline, pinned from Phase 7.3A.
//
// These assertions exist because a released binary was run against real
// PostgreSQL 18 and a real 3-node Patroni cluster on Hetzner, not because
// someone imagined a failure mode. Each one records a claim the product either
// made correctly and must keep making, or made too weakly and must not return
// to.
//
// The scenarios were injected, so they prove semantics rather than prevalence.
// What they establish is that the wording survives contact with a real server.

// TestSQLState53300NamesTheConditionAndInventsNoCause is the Phase 7.3B
// correction.
//
// Measured against PostgreSQL 18.6 with max_connections exhausted: the endpoint
// authenticated the connection, refused the session before ReadyForQuery, and
// reported SQLSTATE 53300. svcdoctor printed that code *and* "could not
// attribute this outcome to a specific cause" in the same finding — a
// contradiction, and an understatement of evidence the product held.
//
// ADR 0040 section 8.1 already made the attribution sentence conditional on the
// same principle: understating the evidence is a different error from
// overstating it and is still an error. This extends that gate to a code the
// peer names for itself.
func TestSQLState53300NamesTheConditionAndInventsNoCause(t *testing.T) {
	f := only(t, allFindings(sessionSQLState(t, "53300")))
	detail := f.Detail()

	if !strings.Contains(detail, "too_many_connections") {
		t.Errorf("53300 does not name the endpoint's own condition.\n\ndetail: %s", detail)
	}
	if !strings.Contains(detail, "no connection slot was available") {
		t.Errorf("53300 does not state what the endpoint refused for.\n\ndetail: %s", detail)
	}
	// The correction is the removal of a false sentence, not the addition of a
	// true one. Both halves matter: leaving it in beside the new sentence would
	// keep the contradiction.
	if strings.Contains(detail, sentenceUnattributable) {
		t.Errorf("53300 still says svcdoctor could not attribute the outcome, "+
			"while restating the condition the endpoint named.\n\ndetail: %s", detail)
	}
	// The SQLSTATE stays printed verbatim. It is the machine-readable fact and
	// the new sentence is a restatement, not a replacement.
	if !strings.Contains(detail, "SQLSTATE 53300") {
		t.Errorf("the SQLSTATE is no longer reported verbatim.\n\ndetail: %s", detail)
	}

	// Every one of these is a *cause*, and 53300 separates none of them. A
	// second run a moment later may connect.
	for _, invented := range []string{
		"max_connections", "too low", "leak", "leaking", "pool", "pooler",
		"spike", "overload", "exhausted", "capacity", "increase", "raise",
	} {
		if strings.Contains(strings.ToLower(detail), invented) {
			t.Errorf("53300 detail contains %q, which is a cause the code does not carry.\n\n"+
				"53300 proves the endpoint had no slot at that instant. It does not "+
				"prove why, for how long, or what to change.\n\ndetail: %s", invented, detail)
		}
	}

	// And it stays the session floor. A named condition is a wording change, not
	// a new code or a new class.
	if got := f.Code(); got != CodeSessionEstablishmentFailed {
		t.Errorf("53300 produced code %q; the correction adds no code", got)
	}
}

// TestAnUnnamedSQLStateStillDeclinesToAttribute is the other side of the gate.
//
// 08P01 is pgBouncer's default for everything, so restating it would invent
// specificity the code does not carry. The unattributable sentence is correct
// there and must survive.
func TestAnUnnamedSQLStateStillDeclinesToAttribute(t *testing.T) {
	f := only(t, allFindings(sessionSQLState(t, "08P01")))
	if !strings.Contains(f.Detail(), sentenceUnattributable) {
		t.Errorf("an unnamed SQLSTATE no longer declines to attribute a cause.\n\n"+
			"Suppressing that sentence for every code would trade one "+
			"understatement for a much worse overstatement.\n\ndetail: %s", f.Detail())
	}
}

// TestNamedConditionsStayMeasured keeps the table honest.
//
// Every entry has to have been watched arriving from a real endpoint. Reading a
// condition name out of the PostgreSQL source and adding it here would produce a
// sentence svcdoctor has never verified it can reach.
func TestNamedConditionsStayMeasured(t *testing.T) {
	measured := map[string]bool{"53300": true}
	for code := range namedConditions {
		if !measured[code] {
			t.Errorf("SQLSTATE %s restates a condition but was never measured arriving "+
				"from a real endpoint.\n\n"+
				"Add it to the measured set only with a validation record behind it.", code)
		}
	}
}

// TestSessionFactsStayEvidenceAndNeverBecomeFindings is the Phase 7.3B hard
// gate, and the reason it exists is the most interesting thing Phase 7.3A found.
//
// The session node already carries in_hot_standby, default_transaction_read_only,
// is_superuser and server_version. Against a real Patroni cluster those tracked
// pg_is_in_recovery() exactly, through a failover and a rejoin. During etcd
// quorum loss every node reported in_hot_standby=on — the cluster had no primary
// at all — and svcdoctor correctly reported OK with no findings on each one.
//
// That is right, and it must stay right *for the stated reason*: none of these
// facts is a problem without an expectation, and svcdoctor has no expected-state
// model. A replica is not a fault. A read-only server may be deliberate. A
// superuser diagnostic role may be policy. An old version may be supported.
//
// Turning any of them into a finding here would be inventing the operator's
// intent. When an expected-state contract exists, this gate is reopened
// deliberately — not by a rule that quietly starts asserting.
func TestSessionFactsStayEvidenceAndNeverBecomeFindings(t *testing.T) {
	b := newBuilder(t)
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
	id := b.sessionNode(domain.StatePass, domain.FailureNone, "", nil, idAuth)
	_ = id

	g := b.freeze()
	// Confirm the facts are actually present, so this cannot pass by their
	// absence.
	var sess domain.Evidence
	for _, n := range g.Nodes() {
		if n.Step() == servicepostgres.StepSession {
			sess = n
		}
	}
	for _, key := range []domain.AttributeKey{
		"postgres.in_hot_standby",
		"postgres.default_transaction_read_only",
		"postgres.server_version",
	} {
		if _, ok := sess.Attribute(key); !ok {
			t.Fatalf("fixture does not carry %s, so this guard would pass vacuously", key)
		}
	}

	if findings := allFindings(g); len(findings) != 0 {
		t.Errorf("a passing session produced %d finding(s): %v\n\n"+
			"in_hot_standby, default_transaction_read_only, is_superuser and "+
			"server_version are observations. None of them is a problem without an "+
			"expectation, and this product has no expected-state model.",
			len(findings), codesOf(findings))
	}
}

// TestNoPostgresFindingAssertsAnExpectation is section 14's gate, read off the
// finding vocabulary rather than off any single rule.
//
// PostgreSQL BASIC diagnoses one endpoint's journey. A code naming a role, a
// cluster, replication or HA would be asserting something about an estate this
// package cannot see, from evidence one connection cannot carry.
func TestNoPostgresFindingAssertsAnExpectation(t *testing.T) {
	for _, code := range allCodes() {
		s := string(code)
		if !strings.HasPrefix(s, "POSTGRES_") {
			continue
		}
		for _, forbidden := range []string{
			"PRIMARY", "REPLICA", "STANDBY", "CLUSTER", "REPLICATION",
			"PATRONI", "FAILOVER", "QUORUM", "LEADER", "WRITABLE", "READ_ONLY",
			"SUPERUSER", "VERSION_UNSUPPORTED", "EOL",
		} {
			if strings.Contains(s, forbidden) {
				t.Errorf("finding code %s names %q.\n\n"+
					"That is an assurance claim: it depends on what the operator "+
					"expected, and PostgreSQL BASIC has no expected-state model. "+
					"Reopen the freeze deliberately instead.", code, forbidden)
			}
		}
	}
}

// sessionSQLState builds the smallest graph that reaches the session floor with
// a given SQLSTATE. Deliberately not a replica of the Hetzner lab: the lab
// proved the product's behaviour, and these fixtures pin the semantics it
// showed.
func sessionSQLState(t *testing.T, code string) domain.Graph {
	t.Helper()
	b := newBuilder(t)
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
	b.sessionNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, code, boolPtr(true), idAuth)
	return b.freeze()
}
