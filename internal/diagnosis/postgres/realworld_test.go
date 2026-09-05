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
// correction, re-anchored by Phase 10.3 and made strictly harder.
//
// Measured against PostgreSQL 18.6 with max_connections exhausted — which is
// how that measurement was *produced* and not what the code proves; a role with
// CONNECTION LIMIT 0 reaches the same five characters on a server with
// connections to spare — the endpoint authenticated the connection, refused the
// session before ReadyForQuery, and reported SQLSTATE 53300. Phase 7.3A found svcdoctor printing that code *and*
// "could not attribute this outcome to a specific cause" in the same finding —
// a contradiction, and an understatement of evidence the product held — and
// Phase 7.3B fixed it by restating the condition in the floor's detail.
//
// **Phase 10.3 moved the claim out of the floor and into a code of its own**
// (ADR 0085 section 3), so the old assertion "the correction adds no code" no
// longer describes the product. It was re-anchored rather than deleted, and
// every epistemic ban it carried is not only kept but widened twice: the
// forbidden substrings are now checked across the summary, the detail **and**
// the recommendations, which the original checked in the detail alone, and a
// second list bans *scope* overclaims beside the *cause* overclaims — 53300
// proves that a limit applying to this session was reached, and not that the
// endpoint had no connection left for anybody.
func TestSQLState53300NamesTheConditionAndInventsNoCause(t *testing.T) {
	f := only(t, allFindings(sessionSQLState(t, "53300")))

	if got := f.Code(); got != CodeConnectionLimitReached {
		t.Errorf("53300 produced code %q, want %s", got, CodeConnectionLimitReached)
	}

	detail := f.Detail()
	if !strings.Contains(detail, "too_many_connections") {
		t.Errorf("53300 does not name the endpoint's own condition.\n\ndetail: %s", detail)
	}
	if !strings.Contains(detail, "a connection limit that applied to this attempted session") {
		t.Errorf("53300 does not state what the endpoint refused for.\n\ndetail: %s", detail)
	}
	// The 7.3B correction was the removal of a false sentence, not the addition
	// of a true one, and the removal has to survive the move.
	if strings.Contains(detail, sentenceUnattributable) {
		t.Errorf("53300 still says svcdoctor could not attribute the outcome, "+
			"while restating the condition the endpoint named.\n\ndetail: %s", detail)
	}
	// The SQLSTATE stays printed verbatim. It is the machine-readable fact and
	// the sentence beside it is a restatement, not a replacement.
	if !strings.Contains(detail, "SQLSTATE 53300") {
		t.Errorf("the SQLSTATE is no longer reported verbatim.\n\ndetail: %s", detail)
	}
	// It is HIGH on direct authority — the peer named the condition in a field
	// its own protocol defines — and CONFIRMED, because svcdoctor is repeating
	// what it was told rather than inferring it.
	if f.Kind() != domain.FindingKindConfirmed || f.Confidence() != domain.ConfidenceHigh {
		t.Errorf("53300 is %s at %s, want CONFIRMED at HIGH", f.Kind(), f.Confidence())
	}

	// Every one of these is a *cause*, and 53300 separates none of them. A
	// second run a moment later may connect. The scan now covers everything a
	// reader sees, because a cause smuggled into a recommendation is the same
	// overclaim wearing a different field.
	surfaces := []string{f.Summary(), detail}
	for _, r := range f.Recommendations() {
		// Both prose fields. The rationale reaches the report since Phase
		// 10.4B, so a cause or a scope overclaim hidden there is as public as
		// one in the summary.
		surfaces = append(surfaces, r.Action(), r.Rationale())
	}
	for _, invented := range []string{
		"max_connections", "too low", "leak", "leaking", "pool", "pooler",
		"spike", "overload", "exhausted", "capacity", "increase", "raise",
	} {
		for _, surface := range surfaces {
			if strings.Contains(strings.ToLower(surface), invented) {
				t.Errorf("the 53300 finding contains %q, which is a cause the code does "+
					"not carry.\n\n"+
					"53300 proves a limit applying to this session was reached. It does "+
					"not prove why, for how long, or what to change.\n\ntext: %s",
					invented, surface)
			}
		}
	}

	// And these are *scope* overclaims, which are a different error from a cause
	// and were the one the first cut of Phase 10.3 made.
	//
	// 53300 is raised when a limit applicable to the session being admitted has
	// been reached, and PostgreSQL has several. The integration fixture proves
	// the gap is reachable rather than theoretical: `CONNECTION LIMIT 0` on a
	// role yields 53300 on a server with connections to spare. So none of these
	// sentences may appear, and — because a denial that names the thing puts the
	// words in the report — the prose states its scope positively instead.
	for _, overclaimed := range []string{
		"no connection slot", "no slot", "slot free", "free slot",
		"out of connections", "no connections left", "no connection left",
		"every session", "all sessions", "any session", "globally",
	} {
		for _, surface := range surfaces {
			if strings.Contains(strings.ToLower(surface), overclaimed) {
				t.Errorf("the 53300 finding contains %q, which asserts an endpoint-wide "+
					"property.\n\n"+
					"53300 proves that a connection limit applicable to *this* attempted "+
					"session was reached. It does not prove which limit, and it does not "+
					"prove that another session would be refused.\n\ntext: %s",
					overclaimed, surface)
			}
		}
	}

	// It carries the observation that would separate those causes, and it says
	// svcdoctor cannot take it: PostgreSQL BASIC executes no SQL.
	if len(f.Recommendations()) != 1 {
		t.Fatalf("53300 carries %d recommendations, want exactly 1", len(f.Recommendations()))
	}
}

// TestTheStartupFloorStillRestatesANamedCondition keeps the Phase 7.3B mechanism
// alive where it is still reachable.
//
// 53300 arrives at the session step as RESOURCE_LIMIT_REACHED, which Phase 10.3
// escalates. It can also arrive **before** authentication — the postmaster
// refuses a connection slot without reading a startup packet — where the adapter
// classifies it PROTOCOL_UNEXPECTED_RESPONSE, deliberately, because that step
// proves nothing about authentication having completed. There the floor and its
// namedConditions table are still what states the condition, and moving the
// session claim must not have quietly orphaned them.
func TestTheStartupFloorStillRestatesANamedCondition(t *testing.T) {
	b := newBuilder(t)
	b.startupNode(
		domain.StateFail, domain.FailureProtocolUnexpectedResponse, "53300", boolPtr(true), "")

	f := only(t, allFindings(b.freeze()))
	if f.Code() != CodeStartupFailed {
		t.Fatalf("code = %s, want %s", f.Code(), CodeStartupFailed)
	}
	if !strings.Contains(f.Detail(), "too_many_connections") ||
		!strings.Contains(f.Detail(), "a connection limit that applied to the attempted session") {
		t.Errorf("the startup floor no longer restates the named condition.\n\ndetail: %s",
			f.Detail())
	}
	if strings.Contains(f.Detail(), sentenceUnattributable) {
		t.Errorf("the startup floor names the condition and still declines to attribute "+
			"it.\n\ndetail: %s", f.Detail())
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
// The class mirrors what `sessionSQLStateFailure` actually returns for the code,
// so that this helper cannot describe a node production can no longer emit.
// Phase 8.1 moved 53300 to RESOURCE_LIMIT_REACHED (ADR 0069); the finding, the
// detail and the suppression of the unattributable sentence are unchanged, which
// is what the tests above assert.
func sessionSQLState(t *testing.T, code string) domain.Graph {
	t.Helper()
	class := domain.FailureProtocolUnexpectedResponse
	if code == "53300" {
		class = domain.FailureResourceLimitReached
	}
	b := newBuilder(t)
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
	b.sessionNode(domain.StateFail, class, code, boolPtr(true), idAuth)
	return b.freeze()
}
