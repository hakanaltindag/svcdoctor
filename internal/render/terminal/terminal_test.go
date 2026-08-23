package terminal

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// These tests build domain values directly, and that is a boundary rather than a
// shortcut: depguard denies this package internal/app, in test files too, so a
// renderer test cannot reach for the application even by accident. Golden output
// from real runs lives in test/render, which may.
//
// What is checked here is presentation logic in isolation — the absence rules,
// the state vocabulary, the duration formatter, the session derivation and the
// determinism of the whole document.

// builder assembles a graph one node at a time.
type builder struct {
	t     *testing.T
	graph *domain.GraphBuilder
	last  map[domain.Step]domain.EvidenceID

	// service names the run, so the same builder can produce a Kafka report.
	// Empty means PostgreSQL, which is what every pre-Kafka test assumed.
	service string

	// shareable makes report() build the SHAREABLE_REDACTED projection, which
	// is what the header line reads to announce itself.
	shareable bool

	// requested overrides the report's target. Empty keeps the per-service
	// default, which is what every fixture predating IP literals expects.
	requested string

	// tlsVerificationDisabled is the run-level security fact the header reads.
	// It is deliberately separate from any node's tls.verified attribute: the
	// header and the rows are read from different places so that a fixture can
	// make them disagree, which is how the guard against a renderer inventing
	// either from the other is written.
	tlsVerificationDisabled bool

	// inputs and edges are held until report(), so a fixture can describe a
	// graph in whatever order reads best and the builder still adds every node
	// before any parent edge that names it.
	inputs []domain.EvidenceInput
	edges  [][2]domain.EvidenceID
}

func newBuilder(t *testing.T) *builder {
	t.Helper()
	return &builder{t: t, graph: domain.NewGraphBuilder(), last: map[domain.Step]domain.EvidenceID{}}
}

// addUnder records one node beneath an explicit parent identifier.
//
// The `add` helpers above thread parentage through the *last node of a step*,
// which is enough for a single-path PostgreSQL graph and wrong for a Kafka one:
// two bootstrap paths hold two `tcp.connect` nodes, and a `tls.handshake` must
// attach to its own. So Kafka fixtures name the parent.
func (b *builder) addUnder(
	id string, step domain.Step, layer domain.Layer, subject string,
	state domain.State, failure domain.FailureClass, elapsed domain.Elapsed,
	parent domain.EvidenceID,
) domain.EvidenceID {
	b.t.Helper()
	return b.addUnderWith(id, step, layer, subject, state, failure, elapsed, parent, nil)
}

// addUnderWith is addUnder with the node's attributes.
//
// Most fixtures need none: a terminal row is built from state, step, class and
// duration. The exception is a TLS handshake, whose row also depends on
// tls.verified — which is exactly the fact Phase 6.8A made the renderer read.
func (b *builder) addUnderWith(
	id string, step domain.Step, layer domain.Layer, subject string,
	state domain.State, failure domain.FailureClass, elapsed domain.Elapsed,
	parent domain.EvidenceID, attrs map[domain.AttributeKey]domain.AttrValue,
) domain.EvidenceID {
	b.t.Helper()

	subj, err := domain.NewEndpointSubject(subject)
	if err != nil {
		b.t.Fatalf("NewEndpointSubject(%q): %v", subject, err)
	}
	b.record(domain.EvidenceInput{
		ID: domain.EvidenceID(id), Subject: subj, Layer: layer, Step: step,
		State: state, FailureClass: failure, Attributes: attrs,
		StartedAt: time.Unix(0, 0).UTC(), Elapsed: elapsed,
	}, parent)
	return domain.EvidenceID(id)
}

// addAdvertisement records one discovered endpoint, carrying the identity a
// reader correlates by.
func (b *builder) addAdvertisement(
	id, subject string, state domain.State, failure domain.FailureClass,
	nodeID int64, parent domain.EvidenceID,
) domain.EvidenceID {
	b.t.Helper()

	subj, err := domain.NewEndpointSubject(subject)
	if err != nil {
		b.t.Fatalf("NewEndpointSubject(%q): %v", subject, err)
	}
	b.record(domain.EvidenceInput{
		ID: domain.EvidenceID(id), Subject: subj,
		Layer: domain.LayerTopology, Step: servicekafka.StepBrokerAdvertised,
		State: state, FailureClass: failure,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekafka.AttrBrokerNodeID: domain.IntAttr(nodeID),
		},
		StartedAt: time.Unix(0, 0).UTC(),
		// An advertisement is a fact read out of a response, not a timed
		// operation, which is what the production producer records too.
		Elapsed: domain.Unmeasured(),
	}, parent)
	return domain.EvidenceID(id)
}

// record defers construction until report(), so replace can amend a node.
func (b *builder) record(in domain.EvidenceInput, parent domain.EvidenceID) {
	b.inputs = append(b.inputs, in)
	if parent != "" {
		b.edges = append(b.edges, [2]domain.EvidenceID{in.ID, parent})
	}
}

// add records one measured node, optionally beneath a parent step.
//
// It wraps d in domain.Measured, because a node built by this helper stands for
// a step that ran. addElapsed is the way to build one that timed nothing.
func (b *builder) add(
	id string, step domain.Step, layer domain.Layer, subject string,
	state domain.State, failure domain.FailureClass, d time.Duration, parent domain.Step,
) domain.EvidenceID {
	b.t.Helper()
	return b.addElapsed(id, step, layer, subject, state, failure, domain.Measured(d), parent)
}

// addElapsed records one node whose measurement — or lack of one — is given
// exactly.
func (b *builder) addElapsed(
	id string, step domain.Step, layer domain.Layer, subject string,
	state domain.State, failure domain.FailureClass, e domain.Elapsed, parent domain.Step,
) domain.EvidenceID {
	b.t.Helper()

	subj, err := domain.NewEndpointSubject(subject)
	if err != nil {
		b.t.Fatalf("NewEndpointSubject: %v", err)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: domain.EvidenceID(id), Subject: subj, Layer: layer, Step: step,
		State: state, FailureClass: failure,
		StartedAt: time.Unix(0, 0).UTC(), Elapsed: e,
	})
	if err != nil {
		b.t.Fatalf("NewEvidence(%s): %v", id, err)
	}
	if err := b.graph.AddEvidence(evidence); err != nil {
		b.t.Fatalf("AddEvidence(%s): %v", id, err)
	}
	if parent != "" {
		if parentID, ok := b.last[parent]; ok {
			if err := b.graph.AddParent(evidence.ID(), parentID); err != nil {
				b.t.Fatalf("AddParent(%s): %v", id, err)
			}
		}
	}
	b.last[step] = evidence.ID()
	return evidence.ID()
}

// report freezes the graph into a report.
func (b *builder) report(findings ...domain.Finding) domain.Report {
	b.t.Helper()

	for _, in := range b.inputs {
		evidence, err := domain.NewEvidence(in)
		if err != nil {
			b.t.Fatalf("NewEvidence(%s): %v", in.ID, err)
		}
		if err := b.graph.AddEvidence(evidence); err != nil {
			b.t.Fatalf("AddEvidence(%s): %v", in.ID, err)
		}
	}
	for _, edge := range b.edges {
		if err := b.graph.AddParent(edge[0], edge[1]); err != nil {
			b.t.Fatalf("AddParent(%s -> %s): %v", edge[0], edge[1], err)
		}
	}

	graph, err := b.graph.Freeze()
	if err != nil {
		b.t.Fatalf("Freeze: %v", err)
	}
	name := b.service
	if name == "" {
		name = "postgres"
	}
	service, err := domain.NewServiceID(name)
	if err != nil {
		b.t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("0.0.0-test", time.Unix(0, 0).UTC(), 12*time.Millisecond, service)
	if err != nil {
		b.t.Fatalf("NewRunMetadata: %v", err)
	}
	requested := "db.internal:5432"
	if b.service == "kafka" {
		requested = kafkaTarget
	}
	if b.requested != "" {
		requested = b.requested
	}
	target, err := domain.NewTarget(requested, requested)
	if err != nil {
		b.t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("svcdoctor-test")
	if err != nil {
		b.t.Fatalf("NewLocalVantage: %v", err)
	}
	// Only a real redaction may produce SHAREABLE_REDACTED, and the ordinary
	// constructor refuses the mode outright — which is the invariant, not an
	// inconvenience. A fixture that wants the shareable projection derives it
	// the way redaction does, from a LOCAL_FULL value.
	security, err := domain.NewReportSecurity(
		domain.OutputModeLocalFull, b.tlsVerificationDisabled, false)
	if err != nil {
		b.t.Fatalf("NewReportSecurity: %v", err)
	}
	if b.shareable {
		security, err = domain.NewShareableReportSecurity(security, domain.RedactionCounts{
			Hostname: 2, IPAddress: 2,
		})
		if err != nil {
			b.t.Fatalf("NewShareableReportSecurity: %v", err)
		}
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: security,
	})
	if err != nil {
		b.t.Fatalf("NewReport: %v", err)
	}
	return report
}

// healthyGraph is one path that reaches a session, with authentication.
func healthyGraph(t *testing.T) *builder {
	t.Helper()
	b := newBuilder(t)
	b.add("dns", vocabulary.StepDNSLookup, domain.LayerDNS, "db.internal:5432",
		domain.StatePass, domain.FailureNone, 2*time.Millisecond, "")
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepDNSLookup)
	b.add("ssl", servicepostgres.StepSSLRequest, domain.LayerTLS, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 800*time.Microsecond, vocabulary.StepTCPConnect)
	b.add("tls", vocabulary.StepTLSHandshake, domain.LayerTLS, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 3*time.Millisecond, servicepostgres.StepSSLRequest)
	b.add("startup", servicepostgres.StepStartup, domain.LayerProtocol, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 700*time.Microsecond, vocabulary.StepTLSHandshake)
	b.add("auth", servicepostgres.StepAuthentication, domain.LayerAuth, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 1500*time.Microsecond, servicepostgres.StepStartup)
	b.add("session", servicepostgres.StepSession, domain.LayerAuth, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 200*time.Microsecond, servicepostgres.StepAuthentication)
	return b
}

func rendered(t *testing.T, in render.Input) string {
	t.Helper()
	var out bytes.Buffer
	if err := Write(&out, in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return out.String()
}

// --- the independent axes -----------------------------------------------------

// TestTheResultSectionAlwaysSaysStatusOutcomeAndExecution is the product
// invariant.
//
// The label is `outcome` rather than `session` (ADR 0052 section 2). PostgreSQL's
// *value* is unchanged — "session established" — because the record generalized
// the label and preserved the wording: a `session` label carrying a Kafka
// metadata value is worse than either word alone.
func TestTheResultSectionAlwaysSaysStatusOutcomeAndExecution(t *testing.T) {
	text := rendered(t, render.Input{Report: healthyGraph(t).report()})

	for _, want := range []string{"status", "outcome", "execution", "duration"} {
		if !strings.Contains(text, want) {
			t.Errorf("the Result section omits %q", want)
		}
	}
	if !containsRow(text, "outcome", "session established") {
		t.Errorf("a passing session is not reported as established:\n%s", text)
	}
	if strings.Contains(text, "\n  session") {
		t.Errorf("the Result section still labels the outcome `session`:\n%s", text)
	}
	// A PostgreSQL run discovers no topology, so there is nothing to count and
	// no line. `0 of 0` would suggest discovery ran and found nothing.
	if strings.Contains(text, "topology") {
		t.Errorf("a PostgreSQL run rendered a topology line:\n%s", text)
	}
}

// containsRow reports whether one Result row carries a label and a value,
// whatever column padding tabwriter chose for that document.
//
// Padding is collapsed on both sides, because a column's width is set by the
// widest cell in its block and a test that pinned it would fail whenever an
// unrelated row grew. The words, their order and the row they are on are the
// contract; the spacing between them is not.
func containsRow(text, label, value string) bool {
	want := strings.Join(strings.Fields(label+" "+value), " ")
	for _, line := range strings.Split(text, "\n") {
		if strings.Join(strings.Fields(line), " ") == want {
			return true
		}
	}
	return false
}

// TestOKNeverStandsAlone pins the wording that stops a reader misreading it.
func TestOKNeverStandsAlone(t *testing.T) {
	text := rendered(t, render.Input{Report: healthyGraph(t).report()})

	if !strings.Contains(text, "no target-side error was proven") {
		t.Error("status OK is printed without its gloss; a reader will take it for success")
	}
}

// TestStatusOKDoesNotImplyASession is the ADR 0046 shape.
//
// The endpoint demanded authentication, the run had none, the status is OK and
// **no session exists**. The output must say so in as many words.
func TestStatusOKDoesNotImplyASession(t *testing.T) {
	b := newBuilder(t)
	b.add("dns", vocabulary.StepDNSLookup, domain.LayerDNS, "db.internal:5432",
		domain.StatePass, domain.FailureNone, 2*time.Millisecond, "")
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepDNSLookup)
	b.add("startup", servicepostgres.StepStartup, domain.LayerProtocol, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 700*time.Microsecond, vocabulary.StepTCPConnect)
	b.add("auth", servicepostgres.StepAuthentication, domain.LayerAuth, "10.0.0.10:5432",
		domain.StateSkipped, domain.FailureExecRequiredInputMissing, 0, servicepostgres.StepStartup)

	warn := finding(t, "POSTGRES_CREDENTIAL_NOT_CONFIGURED", domain.SeverityWarn, "10.0.0.10:5432")
	text := rendered(t, render.Input{Report: b.report(warn)})

	if !strings.Contains(text, "NOT established") {
		t.Errorf("a run with no session does not say so:\n%s", text)
	}
	if !strings.Contains(text, "POSTGRES_CREDENTIAL_NOT_CONFIGURED") {
		t.Error("the WARN finding is not rendered on an OK report")
	}
	if !strings.Contains(text, "⚠ WARN") {
		t.Error("the warning is not marked as one")
	}
	// The SKIPPED node keeps its recorded class, and no prose invents a cause.
	if !strings.Contains(text, "EXEC_REQUIRED_INPUT_MISSING") {
		t.Error("the skipped authentication does not show its recorded class")
	}
}

// TestSessionIsNotInferredFromAnythingElse covers the three wrong sources.
func TestSessionIsNotInferredFromAnythingElse(t *testing.T) {
	// Startup and authentication both pass; no session node exists. AuthenticationOk
	// is not success (ADR 0039), so this must not read as established.
	b := newBuilder(t)
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, "")
	b.add("startup", servicepostgres.StepStartup, domain.LayerProtocol, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepTCPConnect)
	b.add("auth", servicepostgres.StepAuthentication, domain.LayerAuth, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, servicepostgres.StepStartup)

	text := rendered(t, render.Input{Report: b.report()})
	if !strings.Contains(text, "NOT established") {
		t.Errorf("a passing authentication was read as a session:\n%s", text)
	}

	// A failing session node is also not established.
	b2 := newBuilder(t)
	b2.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, "")
	b2.add("session", servicepostgres.StepSession, domain.LayerAuth, "10.0.0.10:5432",
		domain.StateFail, domain.FailureResourceNotFound, time.Millisecond, vocabulary.StepTCPConnect)
	if text := rendered(t, render.Input{Report: b2.report()}); !strings.Contains(text, "NOT established") {
		t.Errorf("a failing session was read as established:\n%s", text)
	}
}

// TestIncompleteComesFromTheInput proves the renderer does not re-derive it.
//
// The graph below carries no UNKNOWN node at all. If the renderer scanned the
// graph instead of reading Input.Incomplete, it would report a complete run —
// and disagree with the exit code the same result produced.
func TestIncompleteComesFromTheInput(t *testing.T) {
	report := healthyGraph(t).report()

	complete := rendered(t, render.Input{Report: report, Incomplete: false})
	if !strings.Contains(complete, "execution   complete") &&
		!strings.Contains(complete, "execution  complete") {
		t.Errorf("a complete run does not say so:\n%s", complete)
	}

	incomplete := rendered(t, render.Input{Report: report, Incomplete: true})
	if !strings.Contains(incomplete, "INCOMPLETE") {
		t.Errorf("an incomplete run does not say so:\n%s", incomplete)
	}
	if !strings.Contains(incomplete, "svcdoctor did not finish the intended measurement") {
		t.Error("the incompleteness is not explained as svcdoctor's own limit")
	}
	// And never as the target's fault.
	for _, blame := range []string{"endpoint timed out", "target timed out", "slow", "unresponsive"} {
		if strings.Contains(incomplete, blame) {
			t.Errorf("the output blames the target with %q", blame)
		}
	}
}

// --- states, absence and skipping ---------------------------------------------

func TestStateVocabulary(t *testing.T) {
	tests := []struct {
		state domain.State
		want  string
	}{
		{domain.StatePass, "✓ PASS"},
		{domain.StateFail, "✗ FAIL"},
		{domain.StateUnknown, "? UNKNOWN"},
		{domain.StateSkipped, "· SKIPPED"},
	}
	for _, tt := range tests {
		if got := stateGlyph(tt.state); got != tt.want {
			t.Errorf("stateGlyph(%s) = %q, want %q", tt.state, got, tt.want)
		}
		// Every state carries its word, so the meaning survives a terminal that
		// cannot draw the glyph.
		if !strings.Contains(stateGlyph(tt.state), tt.state.String()) {
			t.Errorf("stateGlyph(%s) does not contain the state name", tt.state)
		}
	}

	// UNKNOWN is never rendered as a failure.
	if strings.Contains(stateGlyph(domain.StateUnknown), "✗") {
		t.Error("UNKNOWN carries the failure glyph")
	}
	if strings.Contains(stateGlyph(domain.StateSkipped), "PASS") {
		t.Error("SKIPPED reads as a pass")
	}
}

// TestAbsenceIsNotSkipped is the ADR 0041 distinction.
func TestAbsenceIsNotSkipped(t *testing.T) {
	t.Run("a trust path has no authentication node", func(t *testing.T) {
		b := newBuilder(t)
		b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
			domain.StatePass, domain.FailureNone, time.Millisecond, "")
		b.add("startup", servicepostgres.StepStartup, domain.LayerProtocol, "10.0.0.10:5432",
			domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepTCPConnect)
		b.add("session", servicepostgres.StepSession, domain.LayerAuth, "10.0.0.10:5432",
			domain.StatePass, domain.FailureNone, time.Millisecond, servicepostgres.StepStartup)

		text := rendered(t, render.Input{Report: b.report()})
		if !strings.Contains(text, "Authentication") {
			t.Fatal("the absent stage is not shown at all")
		}
		if strings.Contains(text, "SKIPPED  Authentication") {
			t.Error("an absent authentication is rendered as a SKIPPED node")
		}
		// And never as a missing credential: that claim belongs to a finding.
		for _, invented := range []string{"credential", "password", "missing input"} {
			if strings.Contains(strings.ToLower(text), invented) {
				t.Errorf("the renderer invented %q for an absent authentication", invented)
			}
		}
	})

	t.Run("an unselected path stops after discovery", func(t *testing.T) {
		b := newBuilder(t)
		b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.11:5432",
			domain.StatePass, domain.FailureNone, time.Millisecond, "")
		b.add("startup", servicepostgres.StepStartup, domain.LayerProtocol, "10.0.0.11:5432",
			domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepTCPConnect)

		text := rendered(t, render.Input{Report: b.report()})
		if !strings.Contains(text, "not attempted on this path") {
			t.Errorf("an unselected path is not described as such:\n%s", text)
		}
	})

	t.Run("a failed stage leaves the rest not reached", func(t *testing.T) {
		b := newBuilder(t)
		b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
			domain.StatePass, domain.FailureNone, time.Millisecond, "")
		b.add("ssl", servicepostgres.StepSSLRequest, domain.LayerTLS, "10.0.0.10:5432",
			domain.StateFail, domain.FailureProtocolUnexpectedResponse, time.Millisecond,
			vocabulary.StepTCPConnect)

		text := rendered(t, render.Input{Report: b.report()})
		if !strings.Contains(text, "not reached") {
			t.Errorf("stages after a failure are not described as unreached:\n%s", text)
		}
		if !strings.Contains(text, "PROTOCOL_UNEXPECTED_RESPONSE") {
			t.Error("the failed stage does not show its recorded class")
		}
	})
}

// TestAnUnknownStepStillRenders proves nothing is silently dropped.
func TestAnUnknownStepStillRenders(t *testing.T) {
	b := newBuilder(t)
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, "")
	b.add("future", domain.Step("postgres.future_stage"), domain.LayerProtocol, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepTCPConnect)

	text := rendered(t, render.Input{Report: b.report()})
	if !strings.Contains(text, "postgres.future_stage") {
		t.Errorf("a step the label table does not know vanished from the output:\n%s", text)
	}
}

// --- continuation -------------------------------------------------------------

// TestContinuedNeedsPositiveEvidence pins §16 of the phase brief.
func TestContinuedNeedsPositiveEvidence(t *testing.T) {
	// Two paths; neither continued. Nothing may be marked.
	b := newBuilder(t)
	b.add("tcp-a", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, "")
	b.add("tcp-b", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.11:5432",
		domain.StateFail, domain.FailureTCPConnectionRefused, time.Millisecond, "")

	if text := rendered(t, render.Input{Report: b.report()}); strings.Contains(text, "continued") {
		t.Errorf("a path was marked continued with no authentication or session node:\n%s", text)
	}

	// One path with a session node is marked; the other is not.
	b2 := newBuilder(t)
	b2.add("tcp-a", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, "")
	b2.add("session", servicepostgres.StepSession, domain.LayerAuth, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepTCPConnect)
	b2.add("tcp-b", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.11:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, "")

	text := rendered(t, render.Input{Report: b2.report()})
	if strings.Count(text, "· continued") != 1 {
		t.Errorf("expected exactly one continued marker:\n%s", text)
	}
	if !strings.Contains(text, "Path 10.0.0.10:5432 · continued") {
		t.Error("the path with a session node is not marked continued")
	}
}

// --- durations ----------------------------------------------------------------

func TestDurationFormatter(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		// A measured zero prints. It is what a monotonic clock returns for an
		// operation that starts and ends inside one tick, and it is a result
		// rather than an absence. formatElapsed owns the absence case.
		{0, "0s"},
		// Unreachable rather than meaningful: NewEvidence rejects a negative
		// measured duration and run metadata comes from a monotonic clock. It is
		// pinned so the branch has a defined answer rather than an accidental one.
		{-time.Second, "0s"},
		{time.Nanosecond, "<1µs"},
		{500 * time.Nanosecond, "<1µs"},
		{198 * time.Microsecond, "198µs"},
		{3200 * time.Microsecond, "3.2ms"},
		{42700 * time.Microsecond, "42.7ms"},
		{10 * time.Second, "10.0s"},
		{90 * time.Second, "90.0s"},
	}
	for _, tt := range tests {
		if got := formatDuration(tt.in); got != tt.want {
			t.Errorf("formatDuration(%s) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestElapsedFormatterSeparatesMeasurementFromAbsence is the duration contract.
//
// Three classes, three renderings, and no two of them collide:
//
//	measured positive   a number
//	measured zero       "0s"
//	not measured        nothing at all
//
// Before domain.Elapsed the second and third were the same blank cell, which is
// what made TestGoldenTerminalOutput fail about one run in three: the golden
// fixtures measure a real clock around an in-memory resolver, that measurement
// lands on zero when it completes inside one monotonic tick, and the DNS row
// then rendered exactly like a step that had never run.
func TestElapsedFormatterSeparatesMeasurementFromAbsence(t *testing.T) {
	tests := []struct {
		name string
		in   domain.Elapsed
		want string
	}{
		{"measured milliseconds", domain.Measured(3200 * time.Microsecond), "3.2ms"},
		{"measured sub-microsecond", domain.Measured(41 * time.Nanosecond), "<1µs"},
		{"measured one nanosecond", domain.Measured(time.Nanosecond), "<1µs"},
		{"measured zero", domain.Measured(0), "0s"},
		{"not measured", domain.Unmeasured(), ""},
		{"the zero Elapsed", domain.Elapsed{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatElapsed(tt.in); got != tt.want {
				t.Errorf("formatElapsed = %q, want %q", got, tt.want)
			}
		})
	}

	// The two collapses this contract forbids, stated as the assertions a
	// mutation has to survive rather than left implicit in the table.
	if formatElapsed(domain.Unmeasured()) == formatElapsed(domain.Measured(0)) {
		t.Error("an unmeasured step renders identically to one that measured zero")
	}
	if formatElapsed(domain.Measured(0)) == "" {
		t.Error("a measured zero renders as an absent measurement")
	}
}

// TestSubTickMeasurementsRenderIdenticallyAcrossTheWholeRange is the flake, put
// under test at the layer that produced it.
//
// Every value here is a plausible reading from a monotonic clock whose tick is
// about 41.67ns measured around an in-memory resolver — the exact shape the
// golden fixtures produce. What matters is not which token appears but that all
// of them are non-empty, because an empty one is indistinguishable from a step
// that never ran and that is what shifted the golden output.
func TestSubTickMeasurementsRenderIdenticallyAcrossTheWholeRange(t *testing.T) {
	for _, ns := range []int64{0, 41, 42, 83, 84, 125, 208, 416, 834, 999} {
		got := formatElapsed(domain.Measured(time.Duration(ns)))
		if got == "" {
			t.Errorf("a measurement of %dns renders as no measurement at all", ns)
		}
	}
}

// TestAStepThatNeverRanShowsNoDuration walks the whole document rather than the
// formatter, so a renderer that reached around formatElapsed is still caught.
func TestAStepThatNeverRanShowsNoDuration(t *testing.T) {
	b := newBuilder(t)
	b.add("dns", vocabulary.StepDNSLookup, domain.LayerDNS, "db.internal:5432",
		domain.StatePass, domain.FailureNone, 2*time.Millisecond, "")
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepDNSLookup)
	// SKIPPED by policy: svcdoctor decided not to run it, so it timed nothing.
	b.addElapsed("ssl", servicepostgres.StepSSLRequest, domain.LayerTLS, "10.0.0.10:5432",
		domain.StateSkipped, domain.FailureExecSkippedByPolicy, domain.Unmeasured(),
		vocabulary.StepTCPConnect)

	text := rendered(t, render.Input{Report: b.report()})
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "SSLRequest") {
			continue
		}
		if strings.Contains(line, "0s") {
			t.Errorf("a step that never ran claims a measurement:\n%s", line)
		}
		if !strings.Contains(line, "EXEC_SKIPPED_BY_POLICY") {
			t.Errorf("the skipped row lost its class:\n%s", line)
		}
	}
}

// TestAMeasuredZeroStepKeepsItsMeasurement is the mirror of the test above.
func TestAMeasuredZeroStepKeepsItsMeasurement(t *testing.T) {
	b := newBuilder(t)
	b.addElapsed("dns", vocabulary.StepDNSLookup, domain.LayerDNS, "db.internal:5432",
		domain.StatePass, domain.FailureNone, domain.Measured(0), "")
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, time.Millisecond, vocabulary.StepDNSLookup)

	text := rendered(t, render.Input{Report: b.report()})
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "DNS") && !strings.Contains(line, "0s") {
			t.Errorf("a step that measured zero lost its measurement:\n%s", line)
		}
	}
}

// TestAnUnknownLocalTimeoutKeepsItsMeasurement pins the case ADR 0047 turns on.
//
// svcdoctor's own budget ending is not a claim about the endpoint, and the wait
// it did measure is the one fact that says how long it gave the target. The row
// stays UNKNOWN, keeps the class, and keeps the number.
func TestAnUnknownLocalTimeoutKeepsItsMeasurement(t *testing.T) {
	b := newBuilder(t)
	b.add("dns", vocabulary.StepDNSLookup, domain.LayerDNS, "db.internal:5432",
		domain.StatePass, domain.FailureNone, 2*time.Millisecond, "")
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StateUnknown, domain.FailureExecLocalTimeout, 80*time.Millisecond,
		vocabulary.StepDNSLookup)

	text := rendered(t, render.Input{Report: b.report(), Incomplete: true})
	if !strings.Contains(text, "? UNKNOWN") {
		t.Error("a local timeout is not rendered as UNKNOWN")
	}
	if !strings.Contains(text, "EXEC_LOCAL_TIMEOUT") {
		t.Error("a local timeout lost its class")
	}
	if !strings.Contains(text, "80.0ms") {
		t.Error("a local timeout lost the wait it measured")
	}
}

// TestRenderingIsByteIdenticalAcrossRepeats runs the whole document repeatedly.
//
// Every fixture below holds a fixed report, so any difference between runs is
// the renderer reading something outside it — a clock, a map iteration, an
// environment. The duration column is the one that historically did.
func TestRenderingIsByteIdenticalAcrossRepeats(t *testing.T) {
	b := newBuilder(t)
	b.addElapsed("dns", vocabulary.StepDNSLookup, domain.LayerDNS, "db.internal:5432",
		domain.StatePass, domain.FailureNone, domain.Measured(0), "")
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 41*time.Nanosecond, vocabulary.StepDNSLookup)
	b.addElapsed("ssl", servicepostgres.StepSSLRequest, domain.LayerTLS, "10.0.0.10:5432",
		domain.StateSkipped, domain.FailureExecSkippedByPolicy, domain.Unmeasured(),
		vocabulary.StepTCPConnect)
	report := b.report()

	in := render.Input{Report: report}
	first := rendered(t, in)
	for range 200 {
		if got := rendered(t, in); got != first {
			t.Fatal("re-rendering the same report produced different bytes")
		}
	}
}

// TestNoPerformanceInterpretation pins the frozen boundary.
func TestNoPerformanceInterpretation(t *testing.T) {
	b := newBuilder(t)
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StateUnknown, domain.FailureExecLocalTimeout, 10*time.Second, "")

	text := strings.ToLower(rendered(t, render.Input{Report: b.report(), Incomplete: true}))
	for _, word := range []string{"slow", "fast", "degraded", "latency", "threshold", "sluggish"} {
		if strings.Contains(text, word) {
			t.Errorf("the output interprets a duration with %q", word)
		}
	}
	// The measured wait is still shown, and the class says whose limit it was.
	if !strings.Contains(text, "10.0s") {
		t.Error("the interrupted stage lost its measured duration")
	}
	if !strings.Contains(text, strings.ToLower(domain.FailureExecLocalTimeout.String())) {
		t.Error("the local-timeout class is not shown")
	}
}

// TestTotalDurationComesFromRunMetadata is the Phase 4.11c-R2 closure invariant.
//
// The stage durations below sum to 6ms; the run's own metadata says 12ms. The
// output must show the metadata, because orchestration gaps sit between stages
// and a sum is not the elapsed time.
func TestTotalDurationComesFromRunMetadata(t *testing.T) {
	b := newBuilder(t)
	b.add("tcp", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 2*time.Millisecond, "")
	b.add("ssl", servicepostgres.StepSSLRequest, domain.LayerTLS, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 4*time.Millisecond, vocabulary.StepTCPConnect)

	text := rendered(t, render.Input{Report: b.report()})
	if !strings.Contains(text, "duration") || !strings.Contains(text, "12.0ms") {
		t.Errorf("the total is not the run metadata's 12ms:\n%s", text)
	}
	if strings.Contains(text, "6.0ms") {
		t.Error("the total is the sum of the stage durations")
	}
}

// TestMultiPathTimingsStaySeparate proves nothing is aggregated.
func TestMultiPathTimingsStaySeparate(t *testing.T) {
	b := newBuilder(t)
	b.add("tcp-a", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.10:5432",
		domain.StatePass, domain.FailureNone, 2100*time.Microsecond, "")
	b.add("tcp-b", vocabulary.StepTCPConnect, domain.LayerTCP, "10.0.0.11:5432",
		domain.StateUnknown, domain.FailureExecLocalTimeout, 10*time.Second, "")

	text := rendered(t, render.Input{Report: b.report()})
	if !strings.Contains(text, "2.1ms") || !strings.Contains(text, "10.0s") {
		t.Errorf("per-path timings were not both shown:\n%s", text)
	}
	// An average of 2.1ms and 10s would be about 5s. Nothing computes one.
	for _, aggregate := range []string{"5.0s", "average", "mean", "fastest", "slowest"} {
		if strings.Contains(strings.ToLower(text), aggregate) {
			t.Errorf("the output aggregates path timings with %q", aggregate)
		}
	}
}

// --- findings -----------------------------------------------------------------

func finding(t *testing.T, code string, severity domain.Severity, subject string) domain.Finding {
	t.Helper()

	subj, err := domain.NewEndpointSubject(subject)
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	recommendation, err := domain.NewRecommendation("Check the thing the finding names")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	f, err := domain.NewFinding(domain.FindingInput{
		Code: domain.FindingCode(code), Kind: domain.FindingKindConfirmed,
		Severity: severity, Confidence: domain.ConfidenceHigh, Layer: domain.LayerAuth,
		Subject: subj, Summary: "A one-line summary", Detail: "A detail line.\nA second line.",
		EvidenceRefs: []domain.EvidenceID{"tcp"}, Recommendations: []domain.Recommendation{recommendation},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

// TestFindingsAreNeverSuppressed covers the case that matters most.
func TestFindingsAreNeverSuppressed(t *testing.T) {
	b := healthyGraph(t)
	// A session was established *and* a warning exists elsewhere. Neither
	// suppresses the other.
	warn := finding(t, "POSTGRES_TLS_DECLINED", domain.SeverityWarn, "10.0.0.11:5432")
	text := rendered(t, render.Input{Report: b.report(warn)})

	if !strings.Contains(text, "POSTGRES_TLS_DECLINED") {
		t.Error("a finding was hidden because another path established a session")
	}
	if !strings.Contains(text, "A one-line summary") {
		t.Error("the finding summary is missing")
	}
	if !strings.Contains(text, "A second line.") {
		t.Error("the finding detail was truncated")
	}
	if !strings.Contains(text, "→ Check the thing the finding names") {
		t.Error("the recommendation is missing")
	}
	if !strings.Contains(text, "10.0.0.11:5432") {
		t.Error("the finding subject is missing")
	}
}

func TestNoFindingsSaysNone(t *testing.T) {
	if text := rendered(t, render.Input{Report: healthyGraph(t).report()}); !strings.Contains(text, "none") {
		t.Errorf("a clean run does not say it had no findings:\n%s", text)
	}
}

// TestEvidenceIdentifiersAreNotDumped keeps machine detail out of the prose.
func TestEvidenceIdentifiersAreNotDumped(t *testing.T) {
	warn := finding(t, "POSTGRES_TLS_DECLINED", domain.SeverityWarn, "10.0.0.11:5432")
	text := rendered(t, render.Input{Report: healthyGraph(t).report(warn)})

	if !strings.Contains(text, "evidence: 1") {
		t.Error("the evidence reference count is missing")
	}
	// Node identifiers belong to the JSON.
	if strings.Contains(text, "evidence: [") || strings.Contains(text, "\"tcp\"") {
		t.Error("evidence identifiers were dumped into the terminal output")
	}
}

// --- the document as a whole ---------------------------------------------------

func TestOutputIsDeterministic(t *testing.T) {
	warn := finding(t, "POSTGRES_TLS_DECLINED", domain.SeverityWarn, "10.0.0.11:5432")
	report := healthyGraph(t).report(warn)

	first := rendered(t, render.Input{Report: report})
	for range 8 {
		if got := rendered(t, render.Input{Report: report}); got != first {
			t.Fatal("rendering the same report twice produced different bytes")
		}
	}
}

func TestOutputCarriesNoANSI(t *testing.T) {
	warn := finding(t, "POSTGRES_TLS_DECLINED", domain.SeverityWarn, "10.0.0.11:5432")
	text := rendered(t, render.Input{Report: healthyGraph(t).report(warn), Incomplete: true})

	if strings.Contains(text, "\x1b") {
		t.Error("the output contains an escape sequence")
	}
	for _, line := range strings.Split(text, "\n") {
		if line != strings.TrimRight(line, " \t") {
			t.Errorf("line %q has trailing whitespace", line)
		}
	}
}

// TestShareableIsReadFromTheReport pins that the header is metadata-driven.
func TestShareableIsReadFromTheReport(t *testing.T) {
	local := rendered(t, render.Input{Report: healthyGraph(t).report()})
	if strings.Contains(local, "Shareable report") {
		t.Error("a LOCAL_FULL report claims to be shareable")
	}
}

func TestWriteReportsAWriteFailure(t *testing.T) {
	if err := Write(failingWriter{}, render.Input{Report: healthyGraph(t).report()}); err == nil {
		t.Error("a failed write was reported as success")
	}
	if err := Write(nil, render.Input{Report: healthyGraph(t).report()}); err == nil {
		t.Error("a nil writer was accepted")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed pipe") }

// TestPathOrderIsCanonicalNotByAddressFamily closes a gap a mutation pass found.
//
// The obvious multi-path fixture uses two IPv4 addresses, where a hardcoded
// "IPv4 first" rule is indistinguishable from canonical order and a mutation
// introducing one goes unnoticed.
//
// These two are chosen so the orders genuinely differ. Canonical order is the
// graph's, by evidence identifier, and `2001:db8::1` sorts before `9.9.9.9`
// because '2' precedes '9'. A family rule would put the IPv4 path first, which
// is exactly the invisible preference ADR 0024 removed from the transport chain
// and which must not reappear in presentation.
func TestPathOrderIsCanonicalNotByAddressFamily(t *testing.T) {
	b := newBuilder(t)
	b.add("tcp.connect/db/2001:db8::1", vocabulary.StepTCPConnect, domain.LayerTCP,
		"[2001:db8::1]:5432", domain.StatePass, domain.FailureNone, time.Millisecond, "")
	b.add("tcp.connect/db/9.9.9.9", vocabulary.StepTCPConnect, domain.LayerTCP,
		"9.9.9.9:5432", domain.StatePass, domain.FailureNone, time.Millisecond, "")

	text := rendered(t, render.Input{Report: b.report()})
	six := strings.Index(text, "[2001:db8::1]:5432")
	four := strings.Index(text, "9.9.9.9:5432")

	if six < 0 || four < 0 {
		t.Fatalf("both paths were not rendered:\n%s", text)
	}
	if six > four {
		t.Errorf("paths are ordered by address family rather than canonically; "+
			"the graph lists 2001:db8::1 first:\n%s", text)
	}
}

// TestPathOrderIgnoresOutcomeAndDuration pins the other two tempting rankings.
func TestPathOrderIgnoresOutcomeAndDuration(t *testing.T) {
	b := newBuilder(t)
	// The first path in canonical order is the slow failure; the second is the
	// fast success. Neither fact may reorder them.
	b.add("tcp.connect/db/10.0.0.1", vocabulary.StepTCPConnect, domain.LayerTCP,
		"10.0.0.1:5432", domain.StateFail, domain.FailureTCPConnectionRefused,
		9*time.Second, "")
	b.add("tcp.connect/db/10.0.0.2", vocabulary.StepTCPConnect, domain.LayerTCP,
		"10.0.0.2:5432", domain.StatePass, domain.FailureNone, time.Microsecond, "")

	text := rendered(t, render.Input{Report: b.report()})
	if strings.Index(text, "10.0.0.1:5432") > strings.Index(text, "10.0.0.2:5432") {
		t.Errorf("paths were reordered by outcome or duration:\n%s", text)
	}
}
