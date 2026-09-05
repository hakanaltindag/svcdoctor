package diagnosis_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	renderterminal "github.com/hakanaltindag/svcdoctor/internal/render/terminal"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The PostgreSQL end-to-end harness for Phase 10.3.
//
// It builds graphs in the shape `internal/app/postgres.go` really produces — one
// requested-target anchor, one DNS lookup, and a full credential-free journey per
// resolved address, with **exactly one** address continuing to authentication and
// a session — and drives them through the production rule set, a real
// domain.Report, real redaction and both renderers.
//
// # The structural fact the whole corpus rests on
//
// A PostgreSQL run measures every resolved address through DNS, TCP, SSLRequest,
// TLS and Startup, and then **exactly one path continues** (ADR 0041 sections 5
// through 9). So a run has at most one authentication node and at most one
// session node, whatever the target resolved to.
//
// That is why several scenarios a reader might expect are not in the corpus
// below: two endpoints reporting different recovery states, one address
// answering with a connection-limit refusal while a sibling accepts, a session
// established at two addresses at once. **None of them is a graph svcdoctor can
// produce.** They are not forbidden claims that a test suppresses; they are
// shapes with no producer, which is a stronger property and is asserted by name
// in TestPGStructuralSingleSessionPerRun.

// pgHarness accumulates one PostgreSQL scenario.
type pgHarness struct {
	t      *testing.T
	b      *domain.GraphBuilder
	anchor domain.EvidenceID
	dns    domain.EvidenceID
	target string
}

// newPGHarness records the anchor and the lookup every scenario shares.
func newPGHarness(t *testing.T, target string) *pgHarness {
	t.Helper()

	h := &pgHarness{t: t, b: domain.NewGraphBuilder(), target: target}
	h.anchor = h.targetNode()
	return h
}

// targetNode records the requested-target anchor, with a TARGET subject.
func (h *pgHarness) targetNode() domain.EvidenceID {
	h.t.Helper()

	subject, err := domain.NewTargetSubject(h.target)
	if err != nil {
		h.t.Fatalf("NewTargetSubject(%q): %v", h.target, err)
	}
	return h.record(domain.EvidenceInput{
		ID:           domain.EvidenceID("pg-target/" + h.target),
		Subject:      subject,
		Layer:        domain.LayerInput,
		Step:         vocabulary.StepTargetRequested,
		State:        domain.StatePass,
		FailureClass: domain.FailureNone,
		Elapsed:      domain.Unmeasured(),
	}, "")
}

// lookup records the DNS node beneath the anchor.
func (h *pgHarness) lookup(state domain.State, class domain.FailureClass) domain.EvidenceID {
	h.t.Helper()

	h.dns = h.endpointNode(domain.EvidenceInput{
		ID:           domain.EvidenceID("pg-dns/" + h.target),
		Layer:        domain.LayerDNS,
		Step:         vocabulary.StepDNSLookup,
		State:        state,
		FailureClass: class,
	}, h.target, string(h.anchor))
	return h.dns
}

// pgStage is one step on one address's journey.
type pgStage struct {
	step  domain.Step
	layer domain.Layer
	state domain.State
	class domain.FailureClass
	attrs map[domain.AttributeKey]domain.AttrValue

	// blockedBy names an earlier step on the same path as this one's blocker.
	//
	// It is explicit rather than "whatever the parent is", because the two are
	// genuinely different and the difference is load-bearing. A step skipped
	// because the layer above it failed is blocked by that layer; a step skipped
	// because a *policy* refused — the credential-transport policy on an
	// unverified channel — is blocked by the node that established the channel,
	// which may be several stages back. Collapsing them would make the withheld
	// credential point at the wrong fact.
	blockedBy domain.Step
}

// path records one address's journey beneath the DNS node, stage by stage.
//
// Each stage is parented to the one before it, which is the chain the adapter
// really builds. The address is the subject of every node on the path.
func (h *pgHarness) path(address string, stages ...pgStage) []domain.EvidenceID {
	h.t.Helper()

	parent := string(h.dns)
	if parent == "" {
		parent = string(h.anchor)
	}

	byStep := map[domain.Step]string{}
	out := make([]domain.EvidenceID, 0, len(stages))
	for i, stage := range stages {
		id := fmt.Sprintf("pg-%s-%s-%d", stage.step, address, i)
		blocker := ""
		switch {
		case stage.blockedBy != "":
			blocker = byStep[stage.blockedBy]
			if blocker == "" {
				h.t.Fatalf("stage %s is blocked by %s, which is not earlier on this path",
					stage.step, stage.blockedBy)
			}
		case stage.state == domain.StateSkipped &&
			stage.class == domain.FailureExecSkippedPrerequisiteFailed:
			blocker = parent
		}
		node := h.endpointNodeBlocked(domain.EvidenceInput{
			ID:           domain.EvidenceID(id),
			Layer:        stage.layer,
			Step:         stage.step,
			State:        stage.state,
			FailureClass: stage.class,
			Attributes:   stage.attrs,
		}, address, parent, blocker)
		out = append(out, node)
		byStep[stage.step] = string(node)
		parent = string(node)
	}
	return out
}

func (h *pgHarness) endpointNode(in domain.EvidenceInput, ref, parent string) domain.EvidenceID {
	return h.endpointNodeBlocked(in, ref, parent, "")
}

func (h *pgHarness) endpointNodeBlocked(
	in domain.EvidenceInput, ref, parent, blocker string,
) domain.EvidenceID {
	h.t.Helper()

	subject, err := domain.NewEndpointSubject(ref)
	if err != nil {
		h.t.Fatalf("NewEndpointSubject(%q): %v", ref, err)
	}
	in.Subject = subject
	// A step that was skipped or never determined has no duration to report,
	// which is the distinction domain.Elapsed exists to keep: a zero a reader
	// cannot tell from an instantaneous measurement is the shape it replaced.
	in.Elapsed = domain.Measured(time.Millisecond)
	if in.State == domain.StateSkipped || in.State == domain.StateUnknown {
		in.Elapsed = domain.Unmeasured()
	}
	id := h.record(in, parent)
	if blocker != "" {
		if err := h.b.AddBlockedBy(id, domain.EvidenceID(blocker)); err != nil {
			h.t.Fatalf("AddBlockedBy(%q): %v", in.ID, err)
		}
	}
	return id
}

func (h *pgHarness) record(in domain.EvidenceInput, parent string) domain.EvidenceID {
	h.t.Helper()

	in.StartedAt = fixedStart
	evidence, err := domain.NewEvidence(in)
	if err != nil {
		h.t.Fatalf("NewEvidence(%q): %v", in.ID, err)
	}
	if err := h.b.AddEvidence(evidence); err != nil {
		h.t.Fatalf("AddEvidence(%q): %v", in.ID, err)
	}
	if parent != "" {
		if err := h.b.AddParent(evidence.ID(), domain.EvidenceID(parent)); err != nil {
			h.t.Fatalf("AddParent(%q): %v", in.ID, err)
		}
	}
	return evidence.ID()
}

func (h *pgHarness) freeze() domain.Graph {
	h.t.Helper()
	g, err := h.b.Freeze()
	if err != nil {
		h.t.Fatalf("Freeze: %v", err)
	}
	return g
}

// The stage constructors, so a scenario reads as a journey rather than as a
// struct literal.

func pgTCP(state domain.State, class domain.FailureClass) pgStage {
	return pgStage{
		step: vocabulary.StepTCPConnect, layer: domain.LayerTCP, state: state, class: class,
	}
}

func pgSSLRequest(state domain.State, class domain.FailureClass, offered *bool) pgStage {
	attrs := map[domain.AttributeKey]domain.AttrValue{}
	if offered != nil {
		attrs[servicepostgres.AttrSSLOffered] = domain.BoolAttr(*offered)
	}
	return pgStage{
		step: servicepostgres.StepSSLRequest, layer: domain.LayerTLS,
		state: state, class: class, attrs: attrs,
	}
}

func pgTLS(state domain.State, class domain.FailureClass) pgStage {
	return pgStage{
		step: vocabulary.StepTLSHandshake, layer: domain.LayerTLS, state: state, class: class,
	}
}

// pgStartup records a startup node with the identity attributes the adapter
// always sets, plus whatever a rejection produced.
func pgStartup(
	state domain.State, class domain.FailureClass, sqlState, authMethod string, native *bool,
) pgStage {
	attrs := map[domain.AttributeKey]domain.AttrValue{
		"postgres.protocol_version": domain.StringAttr("3.0"),
		"postgres.role":             domain.IdentityAttr("appuser"),
		"postgres.database":         domain.IdentityAttr("appdb"),
	}
	if sqlState != "" {
		attrs[servicepostgres.AttrSQLState] = domain.StringAttr(sqlState)
	}
	if authMethod != "" {
		attrs[servicepostgres.AttrAuthMethod] = domain.StringAttr(authMethod)
	}
	if native != nil {
		attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(*native)
	}
	return pgStage{
		step: servicepostgres.StepStartup, layer: domain.LayerProtocol,
		state: state, class: class, attrs: attrs,
	}
}

func pgAuth(state domain.State, class domain.FailureClass, sqlState string, native *bool) pgStage {
	attrs := map[domain.AttributeKey]domain.AttrValue{
		"postgres.sasl_mechanism": domain.StringAttr("SCRAM-SHA-256"),
	}
	if sqlState != "" {
		attrs[servicepostgres.AttrSQLState] = domain.StringAttr(sqlState)
	}
	if native != nil {
		attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(*native)
	}
	return pgStage{
		step: servicepostgres.StepAuthentication, layer: domain.LayerAuth,
		state: state, class: class, attrs: attrs,
	}
}

// pgAuthBlockedBy records the authentication node the credential-transport
// policy refused to run, pointing at the node that established the channel.
//
// It is SKIPPED and never FAIL, which is the distinction the whole credential
// model rests on: svcdoctor sent zero bytes, so nothing was rejected.
func pgAuthBlockedBy(blocker domain.Step) pgStage {
	stage := pgAuth(domain.StateSkipped, domain.FailureExecSkippedByPolicy, "", nil)
	stage.blockedBy = blocker
	return stage
}

// pgSession records a session node, with the ParameterStatus facts a passing one
// really carries.
//
// `recovery` is the raw `in_hot_standby` value the endpoint sent, or the empty
// string for a server that did not send it at all — which is what a PostgreSQL
// 13 endpoint and some poolers do, and which must never be read as "off".
func pgSession(
	state domain.State, class domain.FailureClass, sqlState, recovery string, native *bool,
) pgStage {
	attrs := map[domain.AttributeKey]domain.AttrValue{}
	if sqlState != "" {
		attrs[servicepostgres.AttrSQLState] = domain.StringAttr(sqlState)
	}
	if native != nil {
		attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(*native)
	}
	if state == domain.StatePass {
		attrs["postgres.transaction_status"] = domain.StringAttr("idle")
		attrs["postgres.default_transaction_read_only"] = domain.StringAttr("off")
		attrs[servicepostgres.AttrServerVersion] = domain.StringAttr("18.6")
	}
	if recovery != "" {
		attrs[servicepostgres.AttrInHotStandby] = domain.StringAttr(recovery)
	}
	return pgStage{
		step: servicepostgres.StepSession, layer: domain.LayerAuth,
		state: state, class: class, attrs: attrs,
	}
}

// postgresProductionRules is the rule set internal/app/postgres.go wires.
//
// The generic ones come from transportAndBoundary and the service's from
// postgresRules, which test/security/postgres_rule_wiring_test.go pins against
// the composition root itself — so this cannot quietly become a subset.
func postgresProductionRules() []namedRule { return postgresRules() }

// diagnosePostgres drives graph -> engine -> report -> renderers as the
// PostgreSQL composition root does.
//
// It differs from diagnose in one value, the run's service, and that value
// matters: the terminal renderer selects a service's journey, observation lines
// and notes by it (ADR 0052 section 5), so a report labelled anything else would
// render no PostgreSQL observation at all and every assertion about the recovery
// line would pass vacuously.
func diagnosePostgres(t *testing.T, g domain.Graph, incomplete bool) run {
	t.Helper()

	set := diagnosis.NewRuleSet().Add("diag/failure-boundary", diagnosis.FailureBoundary)
	for _, r := range postgresProductionRules() {
		set.Add(r.id, r.rule)
	}
	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("freezing the rule set: %v", err)
	}

	vantage, err := domain.NewLocalVantage("test-host")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	outcome := diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{
		Graph: g, Vantage: vantage, Incomplete: incomplete,
	})

	runMeta, err := domain.NewRunMetadata("0.0.0-test", fixedStart, time.Second, "postgres")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("db.example:5432")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: runMeta, Target: target, Vantage: vantage,
		Graph: g, Findings: outcome.Findings(), Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	return run{graph: g, outcome: outcome, report: report, shareable: shareable}
}

// pgTerminal renders the PostgreSQL report the way an operator sees it.
func pgTerminal(t *testing.T, r run) string {
	t.Helper()

	var out []byte
	buf := &byteBuffer{}
	if err := renderterminal.Write(buf, render.Input{Report: r.report}); err != nil {
		t.Fatalf("terminal.Write: %v", err)
	}
	out = buf.data
	return string(out)
}

// byteBuffer is a minimal io.Writer, so this file needs no bytes import beside
// the one harness_test.go already has.
type byteBuffer struct{ data []byte }

func (b *byteBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

// codesIn returns the finding codes a run produced, for the assertions that are
// about which claims exist rather than about their wording.
func codesIn(r run) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(r.report.Findings()))
	for _, f := range r.report.Findings() {
		out = append(out, f.Code())
	}
	return out
}

// hasCode reports whether a run produced one code.
func hasCode(r run, code domain.FindingCode) bool {
	for _, got := range codesIn(r) {
		if got == code {
			return true
		}
	}
	return false
}

// findingWithCode returns the one finding carrying a code.
func findingWithCode(t *testing.T, r run, code domain.FindingCode) domain.Finding {
	t.Helper()

	var found []domain.Finding
	for _, f := range r.report.Findings() {
		if f.Code() == code {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d findings carry %s, want exactly 1: %v", len(found), code, codesIn(r))
	}
	return found[0]
}

// Compile-time proof that the production rules really are the ones named here.
var (
	_ diagnosis.Rule = diagnosispostgres.Session
	_ diagnosis.Rule = diagnosispostgres.AdmissionScope
)
