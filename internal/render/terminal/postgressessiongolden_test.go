package terminal

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The PostgreSQL session-observation goldens, added in Phase 10.7B.
//
// # What they are for
//
// `postgres.default_transaction_read_only` has been recorded on every passing
// session since Phase 4.5 and was read by nothing until ADR 0089 selected it as
// a Class 1 activation. It is presented, never diagnosed: the value reaches the
// Result block as an endpoint-reported observation and reaches no rule, no
// finding, no severity and no recommendation.
//
// Each case asserts what the output must say **and** what it must never say, for
// the reason the Redis goldens give: every claim svcdoctor is forbidden from
// making here is a claim a reasonable person would write. `on` invites *"writes
// will fail"*, and any positive rendering of `off` — *"read write"*, *"writable"*
// — invites *"writes will work"*. The observation supports neither. The parameter
// that settles a given transaction is the session-local `transaction_read_only`,
// which is not sent as a `ParameterStatus` and would need SQL (ADR 0040 §20).
//
// **`off` therefore renders `off`.** The label carries the meaning; the value
// stays the endpoint's own token.
//
// The graphs are built here rather than captured, so the cases are reproducible
// without Docker. `test/integration/postgres` proves the same shapes arise from
// a real PostgreSQL 18 server.

// pgSessionGraph builds one PostgreSQL report reaching a session node.
type pgSessionGraph struct {
	t       *testing.T
	builder *domain.GraphBuilder
}

func newPGSessionGraph(t *testing.T) *pgSessionGraph {
	t.Helper()
	return &pgSessionGraph{t: t, builder: domain.NewGraphBuilder()}
}

func (g *pgSessionGraph) add(
	id string,
	step domain.Step,
	layer domain.Layer,
	attrs map[domain.AttributeKey]domain.AttrValue,
	parent string,
) {
	g.t.Helper()

	subject, err := domain.NewEndpointSubject("198.51.100.20:5432")
	if err != nil {
		g.t.Fatalf("NewEndpointSubject: %v", err)
	}
	if step == vocabulary.StepTargetRequested {
		subject, err = domain.NewTargetSubject("db.internal:5432")
		if err != nil {
			g.t.Fatalf("NewTargetSubject: %v", err)
		}
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:         domain.EvidenceID(id),
		Subject:    subject,
		Layer:      layer,
		Step:       step,
		State:      domain.StatePass,
		Attributes: attrs,
		StartedAt:  time.Unix(1700000000, 0).UTC(),
		Elapsed:    domain.Measured(2 * time.Millisecond),
	})
	if err != nil {
		g.t.Fatalf("NewEvidence(%s): %v", id, err)
	}
	if err := g.builder.AddEvidence(evidence); err != nil {
		g.t.Fatalf("AddEvidence(%s): %v", id, err)
	}
	if parent != "" {
		if err := g.builder.AddParent(evidence.ID(), domain.EvidenceID(parent)); err != nil {
			g.t.Fatalf("AddParent(%s): %v", id, err)
		}
	}
}

// session lays down the whole passing journey and hangs the given session
// parameters off the terminal node.
func (g *pgSessionGraph) session(attrs map[domain.AttributeKey]domain.AttrValue) {
	g.t.Helper()
	g.add("target.requested/db", vocabulary.StepTargetRequested, domain.LayerInput, nil, "")
	g.add("tcp.connect/db", vocabulary.StepTCPConnect, domain.LayerTCP, nil,
		"target.requested/db")
	g.add("postgres.ssl_request/db", servicepostgres.StepSSLRequest, domain.LayerProtocol, nil,
		"tcp.connect/db")
	g.add("tls.handshake/db", vocabulary.StepTLSHandshake, domain.LayerTLS, nil,
		"postgres.ssl_request/db")
	g.add("postgres.startup/db", servicepostgres.StepStartup, domain.LayerProtocol, nil,
		"tls.handshake/db")
	g.add("postgres.authentication/db", servicepostgres.StepAuthentication, domain.LayerAuth, nil,
		"postgres.startup/db")
	g.add("postgres.session/db", servicepostgres.StepSession, domain.LayerAuth, attrs,
		"postgres.authentication/db")
}

// render produces the terminal document.
func (g *pgSessionGraph) render() string {
	g.t.Helper()

	graph, err := g.builder.Freeze()
	if err != nil {
		g.t.Fatalf("Freeze: %v", err)
	}
	service, err := domain.NewServiceID("postgres")
	if err != nil {
		g.t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("test", time.Unix(1700000000, 0).UTC(),
		12*time.Millisecond, service)
	if err != nil {
		g.t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("db.internal:5432")
	if err != nil {
		g.t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("host.test")
	if err != nil {
		g.t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		g.t.Fatalf("NewReportSecurity: %v", err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Security: security,
	})
	if err != nil {
		g.t.Fatalf("NewReport: %v", err)
	}

	var out bytes.Buffer
	if err := Write(&out, render.Input{Report: report}); err != nil {
		g.t.Fatalf("Write: %v", err)
	}
	return out.String()
}

// sessionParams is the two-key attribute map, with "" meaning absent.
func sessionParams(recovery, readOnly string) map[domain.AttributeKey]domain.AttrValue {
	attrs := map[domain.AttributeKey]domain.AttrValue{}
	if recovery != "" {
		attrs[servicepostgres.AttrInHotStandby] = domain.StringAttr(recovery)
	}
	if readOnly != "" {
		attrs[servicepostgres.AttrDefaultTransactionReadOnly] = domain.StringAttr(readOnly)
	}
	return attrs
}

// forbiddenWritabilityClaims is the sentence set this observation may never
// produce, in either direction.
//
// Scoped to the words that would only appear because of this line: a report
// legitimately contains "session" and "read" elsewhere, and asserting on those
// would be brittle rather than strict.
var forbiddenWritabilityClaims = []string{
	"server is read only", "server is read-only",
	"database is read only", "database is read-only",
	"backend is read only", "backend is read-only",
	"read-only server", "read-only database", "read-only backend",
	"writes will fail", "writes will work", "writes are disabled",
	"cannot write", "can write", "unable to write",
	"writable", "write-ready", "write ready", "writes enabled", "writes available",
	"is a replica", "is the primary", "misconfigur",
	// The revision this file exists to pin. "off" is not "read write": the
	// parameter says one default is not set, and every positive rendering of
	// that is a claim about what the session can do (ADR 0089 section 7.1).
	"read write", "read-write",
}

// TestPSROOnRendersABoundedSessionObservation is Case A.
func TestPSROOnRendersABoundedSessionObservation(t *testing.T) {
	g := newPGSessionGraph(t)
	g.session(sessionParams("off", "on"))
	text := g.render()

	assertWording(t, "read-only session", text,
		[]string{
			"default transaction read-only on",
			// The note, which is what stops the silence beside the line from
			// being read as a verdict — and which says "this session", not
			// "this endpoint".
			"this session reported that its transactions default to read-only",
			"neither a finding nor a fault",
		},
		forbiddenWritabilityClaims)

	// It is an observation and produces nothing else.
	for _, graded := range []string{"WARNING", "Warning:", "problem", "should be", "expected "} {
		if strings.Contains(text, graded) {
			t.Errorf("the observation is graded by %q; svcdoctor holds no expectation "+
				"to grade it against.\n\n%s", graded, text)
		}
	}
}

// TestPSROOffIsNotReassurance is Case B, and it is the sharper half.
//
// `off` is as much an observation as `on`. The failure mode on this side is not
// alarm but comfort: an operator told "read write" beside no finding must not be
// told, or allowed to infer from svcdoctor's own words, that writes will work.
func TestPSROOffIsNotReassurance(t *testing.T) {
	g := newPGSessionGraph(t)
	g.session(sessionParams("off", "off"))
	text := g.render()

	assertWording(t, "read-only off session", text,
		[]string{"default transaction read-only off"},
		append([]string{
			// No note fires on this side at all, deliberately.
			"this session reported that its transactions default to read-only",
		}, forbiddenWritabilityClaims...))
}

// TestPSROAbsentParameterRendersNothing is Case C.
//
// A pre-14 server, a pooler that forwards neither parameter, or a session that
// reported only one: the missing fact produces silence, never a default.
func TestPSROAbsentParameterRendersNothing(t *testing.T) {
	for _, tc := range []struct {
		name             string
		recovery, mode   string
		wantAbsentPhrase string
	}{
		{"both absent", "", "", "default transaction read-only"},
		{"only recovery reported", "off", "", "default transaction read-only"},
		{"only the parameter reported", "", "on", "recovery"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newPGSessionGraph(t)
			g.session(sessionParams(tc.recovery, tc.mode))
			text := g.render()

			if strings.Contains(text, tc.wantAbsentPhrase) {
				t.Errorf("an absent parameter produced a %q line.\n\n%s",
					tc.wantAbsentPhrase, text)
			}
			for _, defaulted := range []string{
				"default transaction read-only off", "default transaction read-only on",
			} {
				if tc.mode == "" && strings.Contains(collapseSpaces(text), defaulted) {
					t.Errorf("an absent parameter was defaulted to %q.\n\n%s",
						defaulted, text)
				}
			}
		})
	}
}

// TestPSROTheTwoObservationsAreIndependent is Case D, and it is the property the
// whole phase turns on.
//
// A primary that defaults its transactions to read only is an ordinary, correct
// configuration — `ALTER ROLE … SET default_transaction_read_only = on` produces
// exactly this pair. It is not a contradiction and svcdoctor must not present it
// as one, nor collapse the two facts into a single mode.
func TestPSROTheTwoObservationsAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name           string
		recovery, mode string
		wantRecovery   string
		wantMode       string
	}{
		{"not in recovery, read-only on", "off", "on", "not in recovery",
			"default transaction read-only on"},
		{"in recovery, read-only off", "on", "off", "in recovery",
			"default transaction read-only off"},
		{"in recovery, read-only on", "on", "on", "in recovery",
			"default transaction read-only on"},
		{"not in recovery, read-only off", "off", "off", "not in recovery",
			"default transaction read-only off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newPGSessionGraph(t)
			g.session(sessionParams(tc.recovery, tc.mode))
			text := g.render()

			assertWording(t, tc.name, text,
				[]string{"recovery", tc.wantRecovery, tc.wantMode},
				append([]string{
					"contradict", "inconsistent", "misconfigur", "unexpected",
				}, forbiddenWritabilityClaims...))
		})
	}
}

// TestPSROTheRecoveryValueNeverDrivesTheModeLine is the merge guard.
//
// The two lines read two attributes and nothing derives one from the other. The
// repository measured a real standby reporting `in_hot_standby=on` while
// `default_transaction_read_only=off`, so a reader that collapsed them would
// publish a mode nobody reported.
func TestPSROTheRecoveryValueNeverDrivesTheModeLine(t *testing.T) {
	g := newPGSessionGraph(t)
	g.session(sessionParams("on", "off"))
	text := g.render()

	if strings.Contains(collapseSpaces(text), "default transaction read-only on") {
		t.Errorf("recovery=on produced default_transaction_read_only=on; the two facts "+
			"are independent and this session reported the parameter as off.\n\n%s", text)
	}
	if !strings.Contains(collapseSpaces(text), "default transaction read-only off") {
		t.Errorf("the reported parameter is missing.\n\n%s", text)
	}
}

// TestPSROAnUnrecognizedValueDropsTheLine is Case E.
//
// The render map is closed. A value the endpoint chose — including one that
// merely begins with a recognized token — yields the empty string, which drops
// the line rather than printing peer bytes.
func TestPSROAnUnrecognizedValueDropsTheLine(t *testing.T) {
	const marker = "SVCDOCTOR-HOSTILE-MARKER"
	for _, value := range []string{
		marker, "on" + marker, "ON", "true", "1", "\x1b[31m" + marker, " on",
	} {
		g := newPGSessionGraph(t)
		g.session(sessionParams("off", value))
		text := g.render()

		if strings.Contains(text, marker) {
			t.Errorf("peer-controlled text reached the terminal for %q.\n\n%s", value, text)
		}
		if strings.Contains(text, "default transaction read-only") {
			t.Errorf("an unrecognized value %q produced a line.\n\n%s", value, text)
		}
	}
}

// TestPSROTheModeAttributeIsDeclaredByTheServiceView proves the specific
// consumption contract ADR 0089 selected.
//
// It is deliberately **not** a generic "every attribute must have a consumer"
// invariant: unused attributes are legitimately retained, and Phase 10.7A counted
// twenty-four of them. This pins one key to one renderer, so deleting the
// observation fails a test that says why.
func TestPSROTheModeAttributeIsDeclaredByTheServiceView(t *testing.T) {
	view, ok := services["postgres"]
	if !ok {
		t.Fatal("the renderer has no PostgreSQL service view")
	}
	for _, observation := range view.observations {
		if observation.key != servicepostgres.AttrDefaultTransactionReadOnly {
			continue
		}
		if observation.step != servicepostgres.StepSession {
			t.Errorf("the read-only observation reads %s; it is a session parameter",
				observation.step)
		}
		if observation.render == nil {
			t.Error("the read-only observation has no render function, so an arbitrary " +
				"peer value would reach the terminal verbatim")
		}
		// The closed map returns this package's own tokens, never the peer's.
		for value, want := range map[string]string{"on": "on", "off": "off", "ON": "", "x": ""} {
			if got := observation.render(domain.StringAttr(value)); got != want {
				t.Errorf("render(%q) = %q, want %q", value, got, want)
			}
		}
		return
	}
	t.Fatalf("no PostgreSQL observation reads %s (ADR 0089 section 7.1)",
		servicepostgres.AttrDefaultTransactionReadOnly)
}
