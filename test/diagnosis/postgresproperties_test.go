package diagnosis_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The Phase 10.3 property suite, PG-P01 through PG-P20.
//
// Level L2 of ADR 0083 section 2.4's pyramid: the invariants, over the pipeline
// rather than over a rule. Each one is a sentence svcdoctor must never be able to
// say, or a shape whose output must not vary, and each is checked through the
// production rule set, a real report, real redaction and both renderers.
//
// Several are *structural*: they hold because the graph a run produces cannot
// carry the premise, not because a rule declines to draw the conclusion. Those
// say so, because a structural property is a much stronger claim than a
// suppressed one and the difference should not have to be rediscovered.

// PG-P01 -----------------------------------------------------------------

// TestPGP01TransportFailureProducesNoServerSideDiagnosis is the first claim
// discipline gate.
//
// A DNS or TCP failure means nothing PostgreSQL-shaped was exchanged. No
// SQLSTATE arrived, no admission decision was made, no session parameter was
// received — so no PostgreSQL finding may exist at all.
func TestPGP01TransportFailureProducesNoServerSideDiagnosis(t *testing.T) {
	for _, name := range []string{"P01", "P02"} {
		fixture := pgFixture(t, name)
		r := diagnosePostgres(t, fixture.build(t), fixture.incomplete)
		for _, f := range r.report.Findings() {
			if strings.HasPrefix(string(f.Code()), "POSTGRES_") {
				t.Errorf("%s produced %s from transport evidence alone", name, f.Code())
			}
		}
	}
}

// PG-P02 -----------------------------------------------------------------

// TestPGP02NoOtherSQLStateBecomesAConnectionLimit sweeps the SQLSTATE space.
//
// The connection-limit claim is reachable from exactly one failure class, and
// that class is reachable from exactly one SQLSTATE at exactly one step. Every
// other code in the session window falls to the floor with the five characters
// recorded beside it, uninterpreted.
func TestPGP02NoOtherSQLStateBecomesAConnectionLimit(t *testing.T) {
	// A spread across PostgreSQL's classes, including the neighbours of 53300
	// and pgBouncer's catch-all.
	for _, sqlState := range []string{
		"08P01", "08006", "08004", "08000", "0A000", "22023", "28000", "28P01",
		"3D000", "42501", "53000", "53100", "53200", "53400", "57P01", "57P03",
		"58P01", "XX000", "", "53300 ", " 53300", "53301", "5330",
	} {
		g := pgSessionOutcome(t,
			domain.StateFail, domain.FailureProtocolUnexpectedResponse, sqlState, "")
		r := diagnosePostgres(t, g, false)
		if hasCode(r, diagnosispostgres.CodeConnectionLimitReached) {
			t.Errorf("SQLSTATE %q reached the connection-limit claim through a class "+
				"that does not carry it", sqlState)
		}
	}
}

// PG-P03 -----------------------------------------------------------------

// TestPGP03TheResourceLimitClassConfirmsTheRefusal is the positive half.
//
// Without it, PG-P02 and PG-P04 would both pass on a product that says nothing
// at all.
func TestPGP03TheResourceLimitClassConfirmsTheRefusal(t *testing.T) {
	fixture := pgFixture(t, "P06")
	r := diagnosePostgres(t, fixture.build(t), false)

	f := findingWithCode(t, r, diagnosispostgres.CodeConnectionLimitReached)
	if f.Kind() != domain.FindingKindConfirmed {
		t.Errorf("kind = %s, want CONFIRMED", f.Kind())
	}
	if f.Confidence() != domain.ConfidenceHigh {
		t.Errorf("confidence = %s, want HIGH; the peer named the condition in a field "+
			"its own protocol defines", f.Confidence())
	}
	if !strings.Contains(f.Detail(), "too_many_connections") {
		t.Errorf("the claim does not restate the endpoint's own condition: %s", f.Detail())
	}
}

// PG-P04 -----------------------------------------------------------------

// TestPGP04TheResourceLimitConfirmsNoCause is the refusal ADR 0083 section 2.2
// lists by name.
//
// Every candidate cause is indistinguishable from the others with what
// svcdoctor can see, so it emits none of them — and it emits no remediation
// either, because the remedy differs for every one.
func TestPGP04TheResourceLimitConfirmsNoCause(t *testing.T) {
	fixture := pgFixture(t, "P06")
	r := diagnosePostgres(t, fixture.build(t), false)
	f := findingWithCode(t, r, diagnosispostgres.CodeConnectionLimitReached)

	assertRefuses(t, r, []forbiddenClaim{
		{"connection leak", "no connection lifetime was observed"},
		{"leak", "the same"},
		{"max_connections", "svcdoctor read no setting"},
		{"increase", "raising a limit can worsen memory pressure and hide a leak"},
		{"pool", "a pooler's own limit arrives under a different code"},
		{"misconfigur", "nothing observed how the endpoint is configured"},
		{"traffic", "nothing observed the arrival rate of connections"},
		{"memory", "nothing observed the endpoint's memory"},
		{"no connection slot", "a scope overclaim rather than a cause: 53300 names " +
			"whichever applicable limit was reached and never the endpoint's total"},
	})

	// It carries next-evidence and never remediation, which the safety class
	// gate enforces at construction and this restates as an output property.
	for _, r := range f.Recommendations() {
		if err := diagnosis.ValidateActionText(r.Action()); err != nil {
			t.Errorf("recommendation %q is not safe advice: %v", r.Action(), err)
		}
	}
}

// PG-P05 -----------------------------------------------------------------

// TestPGP05AdmissionRefusalIsNeverACredentialClaim keeps the two epistemically
// distinct, in both directions.
//
// A missing matching host-based rule prevents credential verification entirely,
// so an admission refusal says nothing about the credential. And a credential
// rejection is not an admission decision: the endpoint evaluated what it was
// sent.
func TestPGP05AdmissionRefusalIsNeverACredentialClaim(t *testing.T) {
	admission := diagnosePostgres(t, pgFixture(t, "P05").build(t), false)
	assertRefuses(t, admission, []forbiddenClaim{
		{"bad password", "no credential was presented"},
		{"password", "the same"},
		{"credential is", "the same"},
		{"rejected the credential", "the same"},
	})
	if hasCode(admission, diagnosispostgres.CodeCredentialsRejected) {
		t.Error("an admission refusal produced a credential-rejection finding")
	}

	credential := diagnosePostgres(t, pgFixture(t, "P04").build(t), false)
	assertRefuses(t, credential, []forbiddenClaim{
		{"pg_hba", "a credential rejection is not an admission decision"},
		{"host-based", "the same"},
		{"before evaluating any credential", "a credential was evaluated"},
	})
	if hasCode(credential, diagnosispostgres.CodeConnectionNotPermitted) {
		t.Error("a credential rejection produced an admission finding")
	}

	// And the protocol ordering is preserved: the refused-admission path has no
	// authentication node at all, because the endpoint never asked.
	for _, node := range admission.graph.Nodes() {
		if node.Step() == servicepostgres.StepAuthentication {
			t.Error("the admission-refusal fixture carries an authentication node; " +
				"blocked downstream evidence is not failed downstream evidence")
		}
	}
}

// PG-P06 and PG-P07 --------------------------------------------------------

// TestPGP06AndP07RoleObservationIsNeitherIncidentNorAssurance is the pair of
// role properties, and they are one test because they are one decision.
//
// A reported recovery state produces no finding in either direction: not a
// problem when it is "on", and not a clean bill of health when it is "off". The
// operator sees the fact in the result block, which is where an endpoint-reported
// observation belongs (ADR 0085 section 4).
func TestPGP06AndP07RoleObservationIsNeitherIncidentNorAssurance(t *testing.T) {
	for _, tc := range []struct {
		id       string
		recovery string
		want     string
	}{
		{"P08", "on", "in recovery"},
		{"P07", "off", "not in recovery"},
	} {
		t.Run(tc.recovery, func(t *testing.T) {
			r := diagnosePostgres(t, pgFixture(t, tc.id).build(t), false)

			if len(r.report.Findings()) != 0 {
				t.Errorf("a passing session produced %v; a role is an observation and "+
					"none of these facts is a problem without an expectation",
					codesIn(r))
			}
			if got := r.report.Summary().Status(); got != domain.SummaryStatusOK {
				t.Errorf("status = %s, want OK", got)
			}
			terminal := pgTerminal(t, r)
			if !strings.Contains(terminal, tc.want) {
				t.Errorf("the result block does not report %q.\n\n%s", tc.want, terminal)
			}
			// And the presentation never grades it.
			for _, verdict := range []string{
				"WARNING", "Warning:", "problem", "incorrect", "unexpected",
				"should be", "expected ",
			} {
				if strings.Contains(terminal, verdict) {
					t.Errorf("the role line is graded by %q; svcdoctor holds no "+
						"expectation to grade it against.\n\n%s", verdict, terminal)
				}
			}
		})
	}
}

// PG-P08 -----------------------------------------------------------------

// TestPGP08SplitBrainIsStructurallyUnreachable is the strongest property in the
// suite, and it is deliberately not a forbidden-substring check.
//
// "Two endpoints both reported themselves out of recovery" requires two session
// nodes in one run. A PostgreSQL run measures every address through the
// credential-free stages and then continues **exactly one** (ADR 0041), so the
// premise of a split-brain claim is a graph with no producer.
//
// This asserts that, over the whole corpus and over the composition root itself,
// rather than asserting that a rule declines a conclusion it could otherwise
// draw.
func TestPGP08SplitBrainIsStructurallyUnreachable(t *testing.T) {
	for _, fixture := range pgCorpus() {
		g := fixture.build(t)
		sessions, auths := 0, 0
		for _, node := range g.Nodes() {
			switch node.Step() {
			case servicepostgres.StepSession:
				sessions++
			case servicepostgres.StepAuthentication:
				auths++
			}
		}
		if sessions > 1 || auths > 1 {
			t.Errorf("the %s fixture carries %d session and %d authentication nodes; "+
				"a PostgreSQL run continues exactly one path, so this fixture is not a "+
				"shape the product can produce", fixture.id, sessions, auths)
		}
	}

	// And the corpus's own two-address fixture, which is the closest the product
	// gets to the scenario, says nothing about a topology.
	r := diagnosePostgres(t, pgFixture(t, "P15").build(t), false)
	assertRefuses(t, r, []forbiddenClaim{
		{"split", "svcdoctor does not know these addresses share a database system"},
		{"brain", "the same"},
		{"dual", "the same"},
		{"fencing", "the same"},
		{"two primaries", "the same"},
		{"failover", "nothing about replication was observed"},
	})
}

// PG-P09 and PG-P10 --------------------------------------------------------

// TestPGP09AndP10AnAbsentRoleIsNotAReportedRole is the absence rule.
//
// `in_hot_standby` arrived in PostgreSQL 14, and a pooler may not forward it. An
// endpoint that sent no such parameter reported no recovery state, which is a
// third value and never "off" — and a session that never completed reported
// nothing at all.
func TestPGP09AndP10AnAbsentRoleIsNotAReportedRole(t *testing.T) {
	t.Run("the parameter was never sent", func(t *testing.T) {
		g := pgSessionOutcome(t, domain.StatePass, domain.FailureNone, "", "")
		r := diagnosePostgres(t, g, false)
		terminal := pgTerminal(t, r)

		if strings.Contains(terminal, "recovery") {
			t.Errorf("an absent parameter produced a recovery line.\n\n%s", terminal)
		}
		if len(r.report.Findings()) != 0 {
			t.Errorf("an absent parameter produced %v", codesIn(r))
		}
	})

	t.Run("the endpoint sent a value nothing recognizes", func(t *testing.T) {
		// The render function is a closed two-value map and everything else
		// drops the line, so a peer cannot put a value of its own on a terminal.
		for _, hostile := range []string{"ON", "true", "1", "yes", "maybe", "off "} {
			g := pgSessionOutcome(t, domain.StatePass, domain.FailureNone, "", hostile)
			terminal := pgTerminal(t, diagnosePostgres(t, g, false))
			if strings.Contains(terminal, "recovery") {
				t.Errorf("the value %q reached the result block.\n\n%s", hostile, terminal)
			}
		}
	})

	t.Run("the session never completed", func(t *testing.T) {
		g := pgSessionOutcome(t,
			domain.StateUnknown, domain.FailureExecLocalTimeout, "", "on")
		r := diagnosePostgres(t, g, true)
		terminal := pgTerminal(t, r)
		// An UNKNOWN session is svcdoctor's own budget expiring. Nothing was
		// learned about the endpoint, and the recovery line must not imply
		// otherwise by appearing beside a session that did not complete.
		if strings.Contains(terminal, "session established") {
			t.Errorf("an unknown session rendered as established.\n\n%s", terminal)
		}
		for _, f := range r.report.Findings() {
			if strings.HasPrefix(string(f.Code()), "POSTGRES_") {
				t.Errorf("an unknown session produced %s; nothing was learned about "+
					"the endpoint", f.Code())
			}
		}
	})
}

// PG-P11 -----------------------------------------------------------------

// TestPGP11AnIncompleteSetSupportsNoExclusiveClaim is the RAB18 lesson in this
// phase's vocabulary.
//
// "Every address", "all N addresses" and "only" are claims about a total, and a
// total requires that every address reached a decision **and** that svcdoctor's
// own budget did not stop the run. Both halves are required and neither implies
// the other.
func TestPGP11AnIncompleteSetSupportsNoExclusiveClaim(t *testing.T) {
	for _, id := range []string{"P11", "P12"} {
		fixture := pgFixture(t, id)
		r := diagnosePostgres(t, fixture.build(t), fixture.incomplete)
		f := findingWithCode(t, r, diagnosispostgres.CodeAdmissionScope)

		for _, exclusive := range []string{"at all ", "every address", "only", "account for the whole set"} {
			for _, surface := range []string{f.Summary(), f.Detail()} {
				if strings.Contains(strings.ToLower(surface), exclusive) {
					t.Errorf("%s claims %q over an incomplete set.\n\ntext: %s",
						id, exclusive, surface)
				}
			}
		}
		if !strings.Contains(f.Detail(), "no count here is a total") {
			t.Errorf("%s does not say its counts are partial.\n\ndetail: %s", id, f.Detail())
		}
	}

	// The complete case must be able to say it, or the property above is
	// satisfied by a product that never says anything.
	complete := diagnosePostgres(t, pgFixture(t, "P10").build(t), false)
	uniform := findingWithCode(t, complete, diagnosispostgres.CodeAdmissionScope)
	if !strings.Contains(uniform.Summary(), "at all 2 addresses") {
		t.Errorf("a complete uniform set does not state its total.\n\nsummary: %s",
			uniform.Summary())
	}
}

// PG-P12 -----------------------------------------------------------------

// TestPGP12WithheldCredentialsAreNeverARejection is the credential-binding gate.
//
// svcdoctor sent zero bytes, so nothing was rejected. The four states must stay
// distinguishable: not attempted, blocked, unavailable, and refused by the peer.
func TestPGP12WithheldCredentialsAreNeverARejection(t *testing.T) {
	r := diagnosePostgres(t, pgFixture(t, "P13").build(t), false)

	if !hasCode(r, diagnosispostgres.CodeCredentialWithheld) {
		t.Fatalf("no withheld-credential finding; got %v", codesIn(r))
	}
	for _, forbidden := range []domain.FindingCode{
		diagnosispostgres.CodeCredentialsRejected,
		diagnosispostgres.CodeAuthenticationFailed,
		diagnosispostgres.CodePeerVerificationFailed,
		diagnosispostgres.CodeConnectionNotPermitted,
	} {
		if hasCode(r, forbidden) {
			t.Errorf("a withheld credential produced %s", forbidden)
		}
	}
	assertRefuses(t, r, []forbiddenClaim{
		{"rejected", "svcdoctor sent nothing to be rejected"},
		{"authentication failed", "authentication was never attempted"},
		{"invalid", "nothing was judged"},
	})

	// The authentication node is SKIPPED and not FAIL, which is what makes the
	// distinction structural rather than a matter of wording.
	for _, node := range r.graph.Nodes() {
		if node.Step() != servicepostgres.StepAuthentication {
			continue
		}
		if node.State() != domain.StateSkipped {
			t.Errorf("the withheld authentication node is %s, want SKIPPED", node.State())
		}
	}
}

// PG-P13 -----------------------------------------------------------------

// TestPGP13ServerControlledTextNeverReachesTrustedProse is ADR 0081 section 2.7,
// driven by a hostile endpoint.
//
// # Where the hostile bytes can actually come from
//
// Not from the SQLSTATE or the severity: `wire.validSQLState` accepts exactly
// five alphanumeric ASCII characters and `wire.validSeverity` a closed set of
// eight words, so an endpoint cannot put arbitrary text in either and a fixture
// that did would be testing a graph with no producer.
//
// The unbounded surface is **ParameterStatus**. `wire.SessionParameters`
// allowlists four keys and retains each one's value as the server's own string,
// with no length or character bound — so `in_hot_standby` and `server_version`
// are where a hostile endpoint's bytes really arrive. This drives them, and
// requires that they change no claim and reach no trusted prose.
func TestPGP13ServerControlledTextNeverReachesTrustedProse(t *testing.T) {
	const marker = "SVCDOCTOR-HOSTILE-MARKER"
	hostile := []string{
		marker,
		"on" + marker,
		"\x1b[31m" + marker + "\x1b[0m",
		"# " + marker + "\n\n**bold**",
		"password=hunter2 " + marker,
		strings.Repeat(marker, 200),
		"\r\n" + marker,
	}

	for i, value := range hostile {
		t.Run(pgCaseName(i), func(t *testing.T) {
			h := newPGHarness(t, "db.example:5432")
			h.lookup(domain.StatePass, domain.FailureNone)
			session := pgSession(
				domain.StateFail, domain.FailureResourceLimitReached, "53300", "", yes())
			// Every unbounded field a hostile endpoint can populate.
			session.attrs[servicepostgres.AttrInHotStandby] = domain.StringAttr(value)
			session.attrs[servicepostgres.AttrServerVersion] = domain.StringAttr(value)
			session.attrs["postgres.default_transaction_read_only"] = domain.StringAttr(value)
			h.path(pgAddrA,
				pgTCP(domain.StatePass, domain.FailureNone),
				pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
				pgTLS(domain.StatePass, domain.FailureNone),
				pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
				pgAuth(domain.StatePass, domain.FailureNone, "", nil),
				session,
			)
			r := diagnosePostgres(t, h.freeze(), false)

			// The claim is unchanged: the failure class decides it, and no rule
			// reads a session parameter at all.
			if !hasCode(r, diagnosispostgres.CodeConnectionLimitReached) {
				t.Fatalf("a hostile session parameter changed which claim was made: %v",
					codesIn(r))
			}

			for _, report := range []domain.Report{r.report, r.shareable} {
				for _, f := range report.Findings() {
					surfaces := []string{f.Summary(), f.Detail(), f.Discriminator()}
					for _, rec := range f.Recommendations() {
						surfaces = append(surfaces, rec.Action())
					}
					for _, surface := range surfaces {
						if strings.Contains(surface, marker) {
							t.Errorf("%s copied peer-controlled text into trusted "+
								"prose:\n%s", f.Code(), surface)
						}
					}
				}
			}

			// And it reaches no operator-facing line either. The recovery
			// observation is a closed two-value map, so anything else drops the
			// line rather than printing it.
			if strings.Contains(pgTerminal(t, r), marker) {
				t.Errorf("peer-controlled text reached the terminal:\n%s", pgTerminal(t, r))
			}
		})
	}
}

// pgCaseName names a hostile case without putting its bytes in a subtest name.
func pgCaseName(i int) string {
	return "hostile-parameter-" + strconv.Itoa(i)
}

// TestPGP13bTheSQLStateDetailIsTheOneVerbatimField records the one exception and
// bounds it.
//
// A floor finding and the connection-limit claim both print the SQLSTATE
// verbatim, deliberately: five characters carry no identity, they are already a
// structured attribute a consumer should read instead, and repeating them helps
// a human without inventing a meaning. That is a *detail* field and never a
// summary, a discriminator or a recommendation, and the producer bounds what can
// arrive there.
func TestPGP13bTheSQLStateDetailIsTheOneVerbatimField(t *testing.T) {
	g := pgSessionOutcome(t, domain.StateFail, domain.FailureResourceLimitReached, "53300", "")
	r := diagnosePostgres(t, g, false)
	f := findingWithCode(t, r, diagnosispostgres.CodeConnectionLimitReached)

	if !strings.Contains(f.Detail(), "SQLSTATE 53300") {
		t.Errorf("the SQLSTATE is not printed verbatim: %s", f.Detail())
	}
	if strings.Contains(f.Summary(), "53300") {
		t.Error("the SQLSTATE reached the summary; the summary is one stable sentence")
	}
	for _, rec := range f.Recommendations() {
		if strings.Contains(rec.Action(), "53300") {
			t.Error("the SQLSTATE reached a recommendation")
		}
	}
}

// PG-P14 -----------------------------------------------------------------

// TestPGP14RemovingEvidenceNeverStrengthensAClaim is the monotonicity property,
// and it is the one the whole phase is judged by.
//
// Less evidence must produce the same claim or a weaker one — never a stronger
// one, and never a new one.
func TestPGP14RemovingEvidenceNeverStrengthensAClaim(t *testing.T) {
	for _, tc := range []struct {
		name    string
		full    func(t *testing.T) domain.Graph
		reduced func(t *testing.T) domain.Graph
		// gone is the code the reduced graph must no longer produce.
		gone domain.FindingCode
	}{
		{
			name: "the resource-limit class becomes an unnormalizable refusal",
			full: func(t *testing.T) domain.Graph {
				return pgSessionOutcome(t,
					domain.StateFail, domain.FailureResourceLimitReached, "53300", "")
			},
			reduced: func(t *testing.T) domain.Graph {
				return pgSessionOutcome(t,
					domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", "")
			},
			gone: diagnosispostgres.CodeConnectionLimitReached,
		},
		{
			name: "the session becomes undetermined",
			full: func(t *testing.T) domain.Graph {
				return pgSessionOutcome(t,
					domain.StateFail, domain.FailureResourceLimitReached, "53300", "")
			},
			reduced: func(t *testing.T) domain.Graph {
				return pgSessionOutcome(t,
					domain.StateUnknown, domain.FailureExecLocalTimeout, "", "")
			},
			gone: diagnosispostgres.CodeConnectionLimitReached,
		},
		{
			name:    "the second address's decision is lost",
			full:    func(t *testing.T) domain.Graph { return pgFixture(t, "P10").build(t) },
			reduced: func(t *testing.T) domain.Graph { return pgFixture(t, "P05").build(t) },
			gone:    diagnosispostgres.CodeAdmissionScope,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full := diagnosePostgres(t, tc.full(t), false)
			if !hasCode(full, tc.gone) {
				t.Fatalf("the full graph does not produce %s; the comparison is vacuous",
					tc.gone)
			}
			reduced := diagnosePostgres(t, tc.reduced(t), false)
			if hasCode(reduced, tc.gone) {
				t.Errorf("removing evidence kept %s alive", tc.gone)
			}
			// And confidence never rose.
			for _, f := range reduced.report.Findings() {
				if f.Confidence() == domain.ConfidenceHigh && f.Kind() == domain.FindingKindHypothesis {
					t.Errorf("%s is a HIGH hypothesis on reduced evidence; the ladder "+
						"admits that only on direct peer authority", f.Code())
				}
			}
		})
	}
}

// PG-P15 -----------------------------------------------------------------

// TestPGP15NoIntentMeansNoMismatchClaimExists is the declared-intent property,
// answered structurally.
//
// The brief's property is "removing intent cannot preserve role mismatch". There
// is no intent to remove: ADR 0083 section 2.6 keeps declared expectation out of
// Phase 10 entirely, so **no role-mismatch claim exists to preserve**, and the
// factual role observation is present either way.
//
// This asserts the stronger form: no PostgreSQL finding code, and no prose any
// PostgreSQL rule can produce, expresses an expectation at all. When an
// `expect:` block arrives it will arrive against a record, and this test is what
// will have to be changed deliberately.
func TestPGP15NoIntentMeansNoMismatchClaimExists(t *testing.T) {
	for _, fixture := range pgCorpus() {
		r := diagnosePostgres(t, fixture.build(t), fixture.incomplete)
		// The phrases are the ones that would assert an *expectation about this
		// run's target*. They are deliberately narrow: existing correct prose
		// says "spelled as intended" about a hostname and "a wrong secret"
		// about what 28P01 does not distinguish, and neither is a claim that
		// something is not what the operator wanted.
		assertRefuses(t, r, []forbiddenClaim{
			{"the expected", "svcdoctor holds no declared expectation to compare against"},
			{"should be", "the same"},
			{"role mismatch", "the same"},
			{"wrong role", "the same"},
			{"wrong server", "the same"},
			{"wrong endpoint", "the same"},
			{"required role", "the same"},
			{"not the primary", "the same"},
			{"expected role", "the same"},
		})
	}

	// The observation survives the absence of intent, which is the half that
	// must not be lost.
	terminal := pgTerminal(t, diagnosePostgres(t, pgFixture(t, "P08").build(t), false))
	if !strings.Contains(terminal, "in recovery") {
		t.Errorf("the factual role observation disappeared with the intent that "+
			"never existed.\n\n%s", terminal)
	}
}

// PG-P16 and PG-P17 --------------------------------------------------------

// TestPGP16AndP17NeitherWiringOrderNorRuleNamesReachTheOutput is ADR 0081
// sections 2.6 and 2.6a for this service's rules.
//
// Wiring order is a property of the composition root and rule identity is
// svcdoctor's internal name for a piece of code. Neither is a fact about the
// target, so neither may reach a byte of a report.
func TestPGP16AndP17NeitherWiringOrderNorRuleNamesReachTheOutput(t *testing.T) {
	for _, fixture := range pgCorpus() {
		t.Run(fixture.id, func(t *testing.T) {
			g := fixture.build(t)
			want := pgEncode(t, g, fixture.incomplete, pgRuleNaming{})

			// Every rule under one identity is refused by NewRuleSet at
			// construction (ADR 0080 section 2.4), so the closest legal
			// analogues are a reversed wiring order and namings whose
			// alphabetical order is the exact reverse of production's.
			for _, naming := range []pgRuleNaming{
				{reverse: true},
				{prefix: "zzz/"},
				{prefix: "aaa/"},
				{reverse: true, prefix: "m/"},
			} {
				if got := pgEncode(t, g, fixture.incomplete, naming); got != want {
					t.Errorf("naming %+v changed the report", naming)
				}
			}
		})
	}
}

// pgRuleNaming describes one alternative wiring of the same rule set.
type pgRuleNaming struct {
	reverse bool
	prefix  string
}

// pgEncode diagnoses one graph under one naming and returns the canonical JSON
// of its findings.
func pgEncode(t *testing.T, g domain.Graph, incomplete bool, naming pgRuleNaming) string {
	t.Helper()

	rules := append([]namedRule{{"diag/failure-boundary", diagnosis.FailureBoundary}},
		postgresProductionRules()...)
	if naming.reverse {
		for i, j := 0, len(rules)-1; i < j; i, j = i+1, j-1 {
			rules[i], rules[j] = rules[j], rules[i]
		}
	}

	set := diagnosis.NewRuleSet()
	for i, r := range rules {
		id := r.id
		if naming.prefix != "" {
			// A distinct identity per rule whose alphabetical order is the exact
			// reverse of the production one. A RuleID is "<owner>/<name>" with
			// exactly one separator, so the renaming replaces both halves rather
			// than prefixing them.
			id = strings.TrimSuffix(naming.prefix, "/") + "/r" + strconv.Itoa(len(rules)-i-1)
		}
		set.Add(id, r.rule)
	}
	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("freezing: %v", err)
	}
	vantage, err := domain.NewLocalVantage("test-host")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	findings := diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{
		Graph: g, Vantage: vantage, Incomplete: incomplete,
	}).Findings()
	return encode(t, findings)
}

// PG-P18 -----------------------------------------------------------------

// TestPGP18DifferentSubjectsNeverConverge is the identity half of ADR 0081.
//
// Semantic identity is (Code, Subject). Two addresses are two subjects, so two
// findings about them are two claims however alike their prose — and the
// set-level claim carries a TARGET subject, so it shares an identity with
// nothing.
func TestPGP18DifferentSubjectsNeverConverge(t *testing.T) {
	r := diagnosePostgres(t, pgFixture(t, "P10").build(t), false)

	refused := map[string]int{}
	for _, f := range r.report.Findings() {
		if f.Code() != diagnosispostgres.CodeConnectionNotPermitted {
			continue
		}
		refused[f.Subject().Ref()]++
	}
	if len(refused) != 2 {
		t.Errorf("two refused addresses produced %d distinct subjects: %v", len(refused), refused)
	}
	for ref, count := range refused {
		if count != 1 {
			t.Errorf("subject %s carries %d copies of one code", ref, count)
		}
	}

	scope := findingWithCode(t, r, diagnosispostgres.CodeAdmissionScope)
	for ref := range refused {
		if scope.Subject().Ref() == ref {
			t.Errorf("the set-level claim borrowed the address subject %s", ref)
		}
	}
}

// PG-P19 -----------------------------------------------------------------

// TestPGP19TheOneIntentionalConvergenceSharesItsConstants is ADR 0081 section
// 2.2b's merge precondition, checked on the one PostgreSQL code two rules can
// reach.
//
// POSTGRES_CONNECTION_NOT_PERMITTED is produced by postgres/startup at L4 and
// postgres/authentication at L5. Layer is a merge precondition, so the two never
// converge — and the prose is shared through one constant, so if they ever did,
// they would merge byte for byte rather than one overwriting the other.
func TestPGP19TheOneIntentionalConvergenceSharesItsConstants(t *testing.T) {
	atStartup := diagnosePostgres(t, pgFixture(t, "P05").build(t), false)
	startup := findingWithCode(t, atStartup, diagnosispostgres.CodeConnectionNotPermitted)

	h := newPGHarness(t, "db.example:5432")
	h.lookup(domain.StatePass, domain.FailureNone)
	h.path(pgAddrA,
		pgTCP(domain.StatePass, domain.FailureNone),
		pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
		pgTLS(domain.StatePass, domain.FailureNone),
		pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
		pgAuth(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", yes()),
	)
	atAuth := diagnosePostgres(t, h.freeze(), false)
	auth := findingWithCode(t, atAuth, diagnosispostgres.CodeConnectionNotPermitted)

	if startup.Summary() != auth.Summary() {
		t.Errorf("the two routes to one code write two summaries:\n%q\n%q",
			startup.Summary(), auth.Summary())
	}
	if startup.Detail() != auth.Detail() {
		t.Errorf("the two routes to one code write two details:\n%q\n%q",
			startup.Detail(), auth.Detail())
	}
	if startup.Layer() == auth.Layer() {
		t.Errorf("both routes file the claim at %s; the layers are the reason the two "+
			"do not converge", startup.Layer())
	}
}

// PG-P20 -----------------------------------------------------------------

// TestPGP20TheGenericCoreStaysPostgreSQLUnaware is ADR 0080 section 2.3's
// vocabulary boundary, checked over the source.
//
// The generic engine and the generic rules may know endpoint, subject, layer,
// step, state, failure class, sibling set and boundary. They may not know
// SQLSTATE values, `pg_is_in_recovery()`, `in_hot_standby`, `pg_hba` or any
// PostgreSQL finding code.
func TestPGP20TheGenericCoreStaysPostgreSQLUnaware(t *testing.T) {
	forbidden := []string{
		"POSTGRES_", "sqlstate", "53300", "28000", "28P01", "3D000", "42501",
		"pg_hba", "pg_is_in_recovery", "in_hot_standby", "postgres.",
		"ReadyForQuery", "SSLRequest",
	}

	root := pgRepoRoot(t)
	for _, dir := range []string{"internal/diagnosis", "internal/diagnosis/transport"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
				strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(root, dir, name)
			source, err := os.ReadFile(path) //nolint:gosec // a fixed repository path
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			// The AST, not the bytes: these files discuss PostgreSQL at length
			// in their comments, and a comment is documentation rather than
			// behaviour. What must be clean is the code.
			file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				for _, word := range forbidden {
					if strings.Contains(strings.ToLower(lit.Value), strings.ToLower(word)) {
						t.Errorf("%s/%s contains the string literal %s, which names "+
							"PostgreSQL vocabulary the generic core must not hold",
							dir, name, lit.Value)
					}
				}
				return true
			})
		}
	}
}

// pgRepoRoot walks up to the module root.
func pgRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

// pgFixture returns one corpus fixture by identifier.
func pgFixture(t *testing.T, id string) pgIncident {
	t.Helper()

	for _, fixture := range pgCorpus() {
		if fixture.id == id {
			return fixture
		}
	}
	t.Fatalf("no corpus fixture %s", id)
	return pgIncident{}
}

// TestPGStructuralSingleSessionPerRun records the fact the corpus rests on, read
// off the composition root rather than off a fixture.
//
// `internal/app/postgres.go` calls `selectPath` once and continues one
// candidate. A change that continued two would make several claims in this suite
// reachable that are currently unreachable, and it should fail here rather than
// in a report.
func TestPGStructuralSingleSessionPerRun(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(pgRepoRoot(t), "internal/app/postgres.go"))
	if err != nil {
		t.Fatalf("reading the composition root: %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "postgres.go", source, 0)
	if err != nil {
		t.Fatalf("parsing the composition root: %v", err)
	}

	calls := map[string]int{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok {
			calls[ident.Name]++
		}
		return true
	})
	for name, want := range map[string]int{"selectPath": 1, "continuePath": 1} {
		if calls[name] != want {
			t.Errorf("the composition root calls %s %d times, want %d.\n\n"+
				"Exactly one path continues past the credential-free stages "+
				"(ADR 0041). A run with two sessions would make a two-role "+
				"observation reachable, and the whole role contract assumes it "+
				"is not.", name, calls[name], want)
		}
	}
}

// PG-P21 -------------------------------------------------------------------

// TestPGP21TheTwoSessionObservationsAreIndependent is Phase 10.7B's property,
// driven through the whole pipeline rather than through the renderer alone.
//
// `default_transaction_read_only` has been recorded on every passing session
// since Phase 4.5 and was read by nothing until ADR 0089 activated it as a
// presentation-layer observation. Activating it must not have made it a claim:
// the four combinations all reach the result block, none of them reaches a
// finding, and the pair a naive reader would call contradictory —
// `in_hot_standby=off` beside a read-only default — is the ordinary shape of
// `ALTER ROLE … SET default_transaction_read_only = on`.
func TestPGP21TheTwoSessionObservationsAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		recovery, mode         string
		wantRecovery, wantMode string
	}{
		{"off", "on", "not in recovery", "default transaction read-only"},
		{"on", "off", "in recovery", "default transaction read-only"},
		{"on", "on", "in recovery", "default transaction read-only"},
		{"off", "off", "not in recovery", "default transaction read-only"},
	} {
		t.Run(tc.recovery+"/"+tc.mode, func(t *testing.T) {
			g := pgSessionOutcomeWithMode(t, tc.recovery, tc.mode)
			r := diagnosePostgres(t, g, false)

			if len(r.report.Findings()) != 0 {
				t.Errorf("the session observations produced %v; both are facts and "+
					"neither is a problem without an expectation (ADR 0040 section 20)",
					codesIn(r))
			}
			if got := r.report.Summary().Status(); got != domain.SummaryStatusOK {
				t.Errorf("status = %s, want OK", got)
			}

			terminal := pgTerminal(t, r)
			// Collapsed, because the Result block is tabwriter-aligned and the
			// padding depends on how many observation lines a case happens to
			// have. The wording is the assertion; the column arithmetic is not.
			collapsed := strings.Join(strings.Fields(terminal), " ")
			for _, want := range []string{
				tc.wantRecovery,
				tc.wantMode + " " + tc.mode,
			} {
				if !strings.Contains(collapsed, want) {
					t.Errorf("the result block does not report %q.\n\n%s", want, terminal)
				}
			}
			// And it never reconciles them into one mode, one identity, or one
			// verdict about writing.
			for _, forbidden := range []string{
				"contradict", "inconsistent", "misconfigur", "writable",
				"writes will", "cannot write", "read-only server", "is a replica",
				// `off` is not "read write". Phase 10.7B's revision: the
				// parameter says one default is not set, and every positive
				// rendering of that is a claim about what the session can do.
				"read write", "read-write",
			} {
				if strings.Contains(strings.ToLower(terminal), forbidden) {
					t.Errorf("the observations were reconciled into %q.\n\n%s",
						forbidden, terminal)
				}
			}
		})
	}
}

// pgSessionOutcomeWithMode is pgSessionOutcome with the transaction-mode
// parameter set explicitly.
//
// pgSessionOutcome hard-codes "off" through pgSession, which is right for every
// fixture that predates Phase 10.7B and useless for proving the pair.
func pgSessionOutcomeWithMode(t *testing.T, recovery, mode string) domain.Graph {
	t.Helper()

	session := pgSession(domain.StatePass, domain.FailureNone, "", recovery, yes())
	session.attrs[servicepostgres.AttrDefaultTransactionReadOnly] = domain.StringAttr(mode)

	h := newPGHarness(t, "db.example:5432")
	h.lookup(domain.StatePass, domain.FailureNone)
	h.path(pgAddrA,
		pgTCP(domain.StatePass, domain.FailureNone),
		pgSSLRequest(domain.StatePass, domain.FailureNone, yes()),
		pgTLS(domain.StatePass, domain.FailureNone),
		pgStartup(domain.StatePass, domain.FailureNone, "", "sasl", nil),
		pgAuth(domain.StatePass, domain.FailureNone, "", nil),
		session,
	)
	return h.freeze()
}
