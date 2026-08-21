package domain

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// --- fixture helpers ---------------------------------------------------------

func fixtureRun(t *testing.T) RunMetadata {
	t.Helper()
	run, err := NewRunMetadata("0.1.0", testStart, 1500*time.Millisecond, "kafka")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	return run
}

func fixtureTarget(t *testing.T) Target {
	t.Helper()
	tgt, err := NewTarget("kafka.internal:9092", "kafka.internal:9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}

func fixtureVantage(t *testing.T) Vantage {
	t.Helper()
	v, err := NewLocalVantage("build-agent-07")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	return v
}

func fixtureSecurity(t *testing.T) ReportSecurity {
	t.Helper()
	sec, err := NewReportSecurity(OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	return sec
}

// fixtureGraph builds a small realistic graph:
//
//	dns   PASS
//	  |
//	tcp   FAIL   (TCP_CONNECTION_REFUSED)
//	  |
//	tls   SKIPPED, blocked by tcp
func fixtureGraph(t *testing.T) Graph {
	t.Helper()

	node := func(id string, layer Layer, step string, state State, failure FailureClass) Evidence {
		t.Helper()
		e, err := NewEvidence(EvidenceInput{
			ID:           mustID(t, id),
			Subject:      mustEndpointSubject(t, "kafka.internal:9092"),
			Layer:        layer,
			Step:         mustStep(t, step),
			State:        state,
			FailureClass: failure,
			StartedAt:    testStart,
			Duration:     12 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewEvidence(%q): %v", id, err)
		}
		return e
	}

	b := NewGraphBuilder()
	addAll(t, b,
		node("ep/dns", LayerDNS, "dns.lookup", StatePass, FailureNone),
		node("ep/tcp", LayerTCP, "tcp.connect", StateFail, FailureTCPConnectionRefused),
		node("ep/tls", LayerTLS, "tls.handshake", StateSkipped, FailureExecSkippedPrerequisiteFailed),
	)
	if err := b.AddParent("ep/tcp", "ep/dns"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddParent("ep/tls", "ep/tcp"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddBlockedBy("ep/tls", "ep/tcp"); err != nil {
		t.Fatalf("AddBlockedBy: %v", err)
	}
	return mustFreeze(t, b)
}

func fixtureFinding(t *testing.T, code string, severity Severity, refs ...string) Finding {
	t.Helper()

	ids := make([]EvidenceID, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, mustID(t, r))
	}

	f, err := NewFinding(FindingInput{
		Code:             mustCode(t, code),
		Kind:             FindingKindConfirmed,
		Severity:         severity,
		Confidence:       ConfidenceHigh,
		Layer:            LayerTCP,
		Summary:          "the endpoint refused the connection",
		EvidenceRefs:     ids,
		VantageDependent: true,
	})
	if err != nil {
		t.Fatalf("NewFinding(%q): %v", code, err)
	}
	return f
}

func fixtureInput(t *testing.T) ReportInput {
	t.Helper()
	return ReportInput{
		Run:      fixtureRun(t),
		Target:   fixtureTarget(t),
		Vantage:  fixtureVantage(t),
		Graph:    fixtureGraph(t),
		Findings: []Finding{fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/tcp")},
		Security: fixtureSecurity(t),
	}
}

// --- construction ------------------------------------------------------------

func TestNewReport(t *testing.T) {
	r, err := NewReport(fixtureInput(t))
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	if r.IsZero() {
		t.Error("a constructed Report must not be zero")
	}
	if r.Run().Service() != "kafka" {
		t.Errorf("Run().Service() = %q", r.Run().Service())
	}
	if r.Target().Requested() != "kafka.internal:9092" {
		t.Errorf("Target() = %s", r.Target())
	}
	if r.Vantage().Host() != "build-agent-07" {
		t.Errorf("Vantage() = %s", r.Vantage())
	}
	if r.Graph().Len() != 3 {
		t.Errorf("Graph().Len() = %d, want 3", r.Graph().Len())
	}
	if r.FindingCount() != 1 {
		t.Errorf("FindingCount() = %d, want 1", r.FindingCount())
	}
	if r.Security().OutputMode() != OutputModeLocalFull {
		t.Errorf("Security().OutputMode() = %s", r.Security().OutputMode())
	}
}

func TestNewReportRejectsMissingParts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ReportInput)
	}{
		{"no run", func(in *ReportInput) { in.Run = RunMetadata{} }},
		{"no target", func(in *ReportInput) { in.Target = Target{} }},
		{"no vantage", func(in *ReportInput) { in.Vantage = Vantage{} }},
		{"no security", func(in *ReportInput) { in.Security = ReportSecurity{} }},
		{"zero finding", func(in *ReportInput) { in.Findings = []Finding{{}} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := fixtureInput(t)
			tt.mutate(&in)

			r, err := NewReport(in)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if !r.IsZero() {
				t.Error("a rejected input must return the zero Report")
			}
		})
	}
}

// TestReportWithoutFindingsIsValid covers a run that found nothing wrong.
func TestReportWithoutFindingsIsValid(t *testing.T) {
	in := fixtureInput(t)
	in.Findings = nil

	r, err := NewReport(in)
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	if r.FindingCount() != 0 {
		t.Errorf("FindingCount() = %d, want 0", r.FindingCount())
	}
	if r.Summary().Status() != SummaryStatusOK {
		t.Errorf("Status() = %s, want OK", r.Summary().Status())
	}
}

// TestReportAcceptsOnlyFrozenGraph pins the ADR 0013 boundary: the input field
// is a Graph, so a GraphBuilder cannot be handed to a report at all.
func TestReportAcceptsOnlyFrozenGraph(t *testing.T) {
	var in any = ReportInput{}

	if _, ok := in.(interface{ Builder() *GraphBuilder }); ok {
		t.Error("ReportInput must not accept a GraphBuilder")
	}

	var r any = Report{}
	if _, ok := r.(interface{ Freeze() Graph }); ok {
		t.Error("Report must not freeze anything; it receives a frozen graph")
	}
	if _, ok := r.(interface{ AddFinding(Finding) error }); ok {
		t.Error("Report must be immutable")
	}
}

// --- ADR 0014 cross-object integrity ----------------------------------------

// TestDanglingEvidenceRefIsRejected is the ADR 0014 acceptance criterion.
func TestDanglingEvidenceRefIsRejected(t *testing.T) {
	in := fixtureInput(t)
	in.Findings = []Finding{
		fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/does-not-exist"),
	}

	r, err := NewReport(in)
	if !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("err = %v, want ErrInvalidReport", err)
	}
	if !r.IsZero() {
		t.Error("a rejected report must be the zero value")
	}
}

// TestPartiallyDanglingRefsAreRejected covers a finding where only one of
// several references is missing. The finding is not repaired and not dropped.
func TestPartiallyDanglingRefsAreRejected(t *testing.T) {
	in := fixtureInput(t)
	in.Findings = []Finding{
		fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/dns", "ep/missing", "ep/tcp"),
	}

	if _, err := NewReport(in); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("err = %v, want ErrInvalidReport", err)
	}
}

// TestOneBadFindingRejectsTheWholeReport pins that a dangling reference is not
// silently isolated to its own finding.
func TestOneBadFindingRejectsTheWholeReport(t *testing.T) {
	in := fixtureInput(t)
	in.Findings = []Finding{
		fixtureFinding(t, "DNS_RESOLUTION_FAILED", SeverityWarn, "ep/dns"),
		fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/missing"),
		fixtureFinding(t, "TLS_CERTIFICATE_EXPIRED", SeverityInfo, "ep/tls"),
	}

	if _, err := NewReport(in); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("err = %v, want ErrInvalidReport", err)
	}
}

// TestGraphIsUnaffectedByRejection pins that a failed construction leaves the
// caller's graph untouched: the report never repairs by mutation.
func TestGraphIsUnaffectedByRejection(t *testing.T) {
	g := fixtureGraph(t)
	before := idsOf(g.Nodes())

	in := fixtureInput(t)
	in.Graph = g
	in.Findings = []Finding{fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/missing")}

	if _, err := NewReport(in); err == nil {
		t.Fatal("expected rejection")
	}

	if after := idsOf(g.Nodes()); !equalIDs(before, after) {
		t.Errorf("the graph changed: %v -> %v", before, after)
	}
	if g.Len() != 3 {
		t.Errorf("Len() = %d, want 3", g.Len())
	}
}

func TestAllRefsResolvingIsAccepted(t *testing.T) {
	in := fixtureInput(t)
	in.Findings = []Finding{
		fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/dns", "ep/tcp", "ep/tls"),
	}

	if _, err := NewReport(in); err != nil {
		t.Fatalf("NewReport: %v", err)
	}
}

// --- summary derivation ------------------------------------------------------

// TestSummaryIsDerivedNotSupplied pins ADR 0015 structurally: there is no input
// field through which a caller could supply a contradicting summary.
func TestSummaryIsDerivedNotSupplied(t *testing.T) {
	var in any = ReportInput{}
	if _, ok := in.(interface{ SummaryField() Summary }); ok {
		t.Error("ReportInput must not accept a summary")
	}

	var s any = Summary{}
	if _, ok := s.(interface{ SetStatus(SummaryStatus) }); ok {
		t.Error("Summary must have no setters")
	}
}

func TestSummaryDerivation(t *testing.T) {
	in := fixtureInput(t)
	in.Findings = []Finding{
		fixtureFinding(t, "DNS_RESOLUTION_FAILED", SeverityInfo, "ep/dns"),
		fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/tcp"),
		fixtureFinding(t, "TLS_CERTIFICATE_EXPIRED", SeverityWarn, "ep/tls"),
	}

	r, err := NewReport(in)
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	s := r.Summary()

	if s.Status() != SummaryStatusProblemsFound {
		t.Errorf("Status() = %s, want PROBLEMS_FOUND", s.Status())
	}
	// The graph's only FAIL node is at L2.
	if s.FirstBrokenLayer() != LayerTCP {
		t.Errorf("FirstBrokenLayer() = %s, want L2", s.FirstBrokenLayer())
	}
	counts := s.FindingCountsBySeverity()
	if counts.Info != 1 || counts.Warn != 1 || counts.Error != 1 || counts.Critical != 0 {
		t.Errorf("counts = %+v", counts)
	}
	if counts.Total() != 3 {
		t.Errorf("Total() = %d, want 3", counts.Total())
	}
	if s.SkippedEvidenceCount() != 1 {
		t.Errorf("SkippedEvidenceCount() = %d, want 1", s.SkippedEvidenceCount())
	}
	if s.UnknownEvidenceCount() != 0 {
		t.Errorf("UnknownEvidenceCount() = %d, want 0", s.UnknownEvidenceCount())
	}
}

func TestSummaryStatusFollowsExitCodeBoundary(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     SummaryStatus
	}{
		{"info only", SeverityInfo, SummaryStatusOK},
		{"warn only", SeverityWarn, SummaryStatusOK},
		{"error", SeverityError, SummaryStatusProblemsFound},
		{"critical", SeverityCritical, SummaryStatusProblemsFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := fixtureInput(t)
			in.Findings = []Finding{fixtureFinding(t, "TCP_CONNECTION_REFUSED", tt.severity, "ep/tcp")}

			r, err := NewReport(in)
			if err != nil {
				t.Fatalf("NewReport: %v", err)
			}
			if got := r.Summary().Status(); got != tt.want {
				t.Errorf("Status() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestFirstBrokenLayerRules pins the exact aggregation rule: only positively
// evidenced FAIL counts, and the lowest such layer wins.
func TestFirstBrokenLayerRules(t *testing.T) {
	build := func(t *testing.T, states map[string]struct {
		layer Layer
		state State
	}) Graph {
		t.Helper()
		b := NewGraphBuilder()
		for id, spec := range states {
			failure := FailureNone
			switch spec.state {
			case StateFail:
				failure = FailureTCPConnectionRefused
			case StateSkipped:
				failure = FailureExecSkippedPrerequisiteFailed
			case StateUnknown, StatePass, StateDegraded:
			}
			e, err := NewEvidence(EvidenceInput{
				ID:           mustID(t, id),
				Subject:      mustEndpointSubject(t, "kafka.internal:9092"),
				Layer:        spec.layer,
				Step:         mustStep(t, "dns.lookup"),
				State:        spec.state,
				FailureClass: failure,
				StartedAt:    testStart,
			})
			if err != nil {
				t.Fatalf("NewEvidence: %v", err)
			}
			addAll(t, b, e)
		}
		return mustFreeze(t, b)
	}

	type spec = struct {
		layer Layer
		state State
	}

	tests := []struct {
		name  string
		nodes map[string]spec
		want  Layer
	}{
		{
			name:  "no failure",
			nodes: map[string]spec{"a": {LayerDNS, StatePass}, "b": {LayerTCP, StatePass}},
			want:  LayerUnspecified,
		},
		{
			name:  "unknown is not a failure",
			nodes: map[string]spec{"a": {LayerDNS, StateUnknown}, "b": {LayerTCP, StatePass}},
			want:  LayerUnspecified,
		},
		{
			name:  "skipped is not a failure",
			nodes: map[string]spec{"a": {LayerDNS, StateSkipped}, "b": {LayerTCP, StateSkipped}},
			want:  LayerUnspecified,
		},
		{
			name:  "degraded is not a failure",
			nodes: map[string]spec{"a": {LayerTLS, StateDegraded}},
			want:  LayerUnspecified,
		},
		{
			name:  "lowest failing layer wins",
			nodes: map[string]spec{"a": {LayerTLS, StateFail}, "b": {LayerDNS, StateFail}},
			want:  LayerDNS,
		},
		{
			name:  "several failures at one layer stay that layer",
			nodes: map[string]spec{"a": {LayerTCP, StateFail}, "b": {LayerTCP, StateFail}},
			want:  LayerTCP,
		},
		{
			name:  "failure below a skip",
			nodes: map[string]spec{"a": {LayerDNS, StateSkipped}, "b": {LayerTCP, StateFail}},
			want:  LayerTCP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := fixtureInput(t)
			in.Graph = build(t, tt.nodes)
			in.Findings = nil

			r, err := NewReport(in)
			if err != nil {
				t.Fatalf("NewReport: %v", err)
			}
			if got := r.Summary().FirstBrokenLayer(); got != tt.want {
				t.Errorf("FirstBrokenLayer() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestFirstBrokenLayerOmittedWhenNothingFailed pins that an absent field means
// "no evidenced failure" rather than "failed somewhere unnamed".
func TestFirstBrokenLayerOmittedWhenNothingFailed(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "ok"))

	in := fixtureInput(t)
	in.Graph = mustFreeze(t, b)
	in.Findings = nil

	r, err := NewReport(in)
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	raw, err := json.Marshal(r.Summary())
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, present := decoded["firstBrokenLayer"]; present {
		t.Errorf("firstBrokenLayer should be omitted: %s", raw)
	}
}

// TestSummaryCountsSkippedSoOKIsNotMistakenForHealthy pins the reason skipped and
// unknown counts sit beside the status.
func TestSummaryCountsSkippedSoOKIsNotMistakenForHealthy(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, skipped(t, "a"), skipped(t, "b"), evidenceAt(t, "c", StateUnknown))

	in := fixtureInput(t)
	in.Graph = mustFreeze(t, b)
	in.Findings = nil

	r, err := NewReport(in)
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	s := r.Summary()

	if s.Status() != SummaryStatusOK {
		t.Errorf("Status() = %s, want OK", s.Status())
	}
	if s.SkippedEvidenceCount() != 2 {
		t.Errorf("SkippedEvidenceCount() = %d, want 2", s.SkippedEvidenceCount())
	}
	if s.UnknownEvidenceCount() != 1 {
		t.Errorf("UnknownEvidenceCount() = %d, want 1", s.UnknownEvidenceCount())
	}
}

// --- ordering, determinism, immutability ------------------------------------

func TestFindingsAreCanonicallyOrdered(t *testing.T) {
	in := fixtureInput(t)
	in.Findings = []Finding{
		fixtureFinding(t, "AAA_LOW_SEVERITY", SeverityInfo, "ep/dns"),
		fixtureFinding(t, "ZZZ_TOP_SEVERITY", SeverityCritical, "ep/tcp"),
		fixtureFinding(t, "MMM_MID_SEVERITY", SeverityWarn, "ep/tls"),
		fixtureFinding(t, "BBB_TOP_SEVERITY", SeverityCritical, "ep/dns"),
	}

	r, err := NewReport(in)
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	want := []FindingCode{
		// Most severe first; within a severity, code ascending.
		"BBB_TOP_SEVERITY",
		"ZZZ_TOP_SEVERITY",
		"MMM_MID_SEVERITY",
		"AAA_LOW_SEVERITY",
	}
	got := r.Findings()
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i, code := range want {
		if got[i].Code() != code {
			t.Errorf("position %d = %s, want %s", i, got[i].Code(), code)
		}
	}
}

func TestFindingOrderIsIndependentOfInputOrder(t *testing.T) {
	make4 := func(t *testing.T) []Finding {
		t.Helper()
		return []Finding{
			fixtureFinding(t, "AAA_ONE", SeverityInfo, "ep/dns"),
			fixtureFinding(t, "BBB_TWO", SeverityCritical, "ep/tcp"),
			fixtureFinding(t, "CCC_THREE", SeverityWarn, "ep/tls"),
			fixtureFinding(t, "DDD_FOUR", SeverityError, "ep/dns"),
		}
	}
	orders := [][]int{{0, 1, 2, 3}, {3, 2, 1, 0}, {2, 0, 3, 1}, {1, 3, 0, 2}}

	var reference []byte
	for _, order := range orders {
		src := make4(t)
		in := fixtureInput(t)
		in.Findings = nil
		for _, i := range order {
			in.Findings = append(in.Findings, src[i])
		}

		r, err := NewReport(in)
		if err != nil {
			t.Fatalf("NewReport: %v", err)
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if reference == nil {
			reference = raw
			continue
		}
		if string(raw) != string(reference) {
			t.Fatalf("input order %v changed the report bytes", order)
		}
	}
}

func TestReportJSONIsDeterministic(t *testing.T) {
	r, err := NewReport(fixtureInput(t))
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	first, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for i := 0; i < 25; i++ {
		again, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(first) != string(again) {
			t.Fatalf("encoding varied between runs")
		}
	}
}

// TestGraphInsertionOrderDoesNotChangeReportBytes covers the other source of
// nondeterminism: how the graph was built.
func TestGraphInsertionOrderDoesNotChangeReportBytes(t *testing.T) {
	build := func(t *testing.T, order []int) Graph {
		t.Helper()
		nodes := []Evidence{passing(t, "a"), passing(t, "b"), passing(t, "c")}
		b := NewGraphBuilder()
		for _, i := range order {
			if err := b.AddEvidence(nodes[i]); err != nil {
				t.Fatalf("AddEvidence: %v", err)
			}
		}
		if err := b.AddParent("b", "a"); err != nil {
			t.Fatalf("AddParent: %v", err)
		}
		if err := b.AddParent("c", "a"); err != nil {
			t.Fatalf("AddParent: %v", err)
		}
		return mustFreeze(t, b)
	}

	var reference []byte
	for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 0, 2}} {
		in := fixtureInput(t)
		in.Graph = build(t, order)
		in.Findings = nil

		r, err := NewReport(in)
		if err != nil {
			t.Fatalf("NewReport: %v", err)
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if reference == nil {
			reference = raw
			continue
		}
		if string(raw) != string(reference) {
			t.Fatalf("graph insertion order %v changed the report bytes", order)
		}
	}
}

func TestReportImmutability(t *testing.T) {
	findings := []Finding{
		fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/tcp"),
		fixtureFinding(t, "DNS_RESOLUTION_FAILED", SeverityWarn, "ep/dns"),
	}

	in := fixtureInput(t)
	in.Findings = findings

	r, err := NewReport(in)
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	// Mutating the caller's slice must not reach the report.
	findings[0] = Finding{}
	if r.FindingCount() != 2 {
		t.Errorf("FindingCount() = %d, want 2", r.FindingCount())
	}
	if r.Findings()[0].IsZero() {
		t.Error("the report changed with the caller's slice")
	}

	// Mutating a returned slice must not reach the report either.
	out := r.Findings()
	out[0] = Finding{}
	if r.Findings()[0].IsZero() {
		t.Error("the report changed through a returned slice")
	}

	// The graph handed back is immutable and copies on read.
	g := r.Graph()
	parents := g.Parents("ep/tcp")
	if len(parents) > 0 {
		parents[0] = "mutated"
	}
	if got := r.Graph().Parents("ep/tcp"); !equalIDs(got, []EvidenceID{"ep/dns"}) {
		t.Errorf("graph changed through the report: %v", got)
	}
}

// --- canonical JSON ----------------------------------------------------------

// TestReportJSONExact is the schema v1 fixture. The serializer itself is under
// test here, which is why an exact assertion is justified.
func TestReportJSONExact(t *testing.T) {
	in := fixtureInput(t)
	in.Findings = []Finding{
		fixtureFinding(t, "TCP_CONNECTION_REFUSED", SeverityError, "ep/tcp"),
	}

	hypothesis, err := NewFinding(FindingInput{
		Code:             mustCode(t, "TLS_HANDSHAKE_NOT_ATTEMPTED"),
		Kind:             FindingKindHypothesis,
		Severity:         SeverityWarn,
		Confidence:       ConfidenceMedium,
		Layer:            LayerTLS,
		Summary:          "TLS was never attempted because the connection failed",
		EvidenceRefs:     []EvidenceID{mustID(t, "ep/tls")},
		VantageDependent: false,
		Discriminator:    "Retry once the TCP connection succeeds.",
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	in.Findings = append(in.Findings, hypothesis)

	r, err := NewReport(in)
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	got, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	const want = `{` +
		`"schemaVersion":1,` +
		`"run":{"svcdoctorVersion":"0.1.0","startedAt":"2026-08-21T10:30:00Z",` +
		`"duration":"1.5s","service":"kafka","tlsVerificationDisabled":false,` +
		`"outputMode":"LOCAL_FULL"},` +
		`"target":{"requested":"kafka.internal:9092","normalized":["kafka.internal:9092"]},` +
		`"vantage":{"source":"LOCAL_HOST","host":"build-agent-07"},` +
		`"evidence":{"nodes":[` +
		`{"id":"ep/dns","subject":{"kind":"ENDPOINT","ref":"kafka.internal:9092"},` +
		`"layer":"L1","step":"dns.lookup","state":"PASS",` +
		`"startedAt":"2026-08-21T10:30:00Z","duration":"12ms"},` +
		`{"id":"ep/tcp","subject":{"kind":"ENDPOINT","ref":"kafka.internal:9092"},` +
		`"layer":"L2","step":"tcp.connect","state":"FAIL","failureClass":"TCP_CONNECTION_REFUSED",` +
		`"startedAt":"2026-08-21T10:30:00Z","duration":"12ms"},` +
		`{"id":"ep/tls","subject":{"kind":"ENDPOINT","ref":"kafka.internal:9092"},` +
		`"layer":"L3","step":"tls.handshake","state":"SKIPPED",` +
		`"failureClass":"EXEC_SKIPPED_PREREQUISITE_FAILED",` +
		`"startedAt":"2026-08-21T10:30:00Z","duration":"12ms"}],` +
		`"relationships":[` +
		`{"id":"ep/tcp","parents":["ep/dns"]},` +
		`{"id":"ep/tls","parents":["ep/tcp"],"blockedBy":["ep/tcp"]}]},` +
		`"findings":[` +
		`{"code":"TCP_CONNECTION_REFUSED","kind":"CONFIRMED","severity":"ERROR",` +
		`"confidence":"HIGH","layer":"L2",` +
		`"summary":"the endpoint refused the connection",` +
		`"evidenceRefs":["ep/tcp"],"vantageDependent":true},` +
		`{"code":"TLS_HANDSHAKE_NOT_ATTEMPTED","kind":"HYPOTHESIS","severity":"WARN",` +
		`"confidence":"MEDIUM","layer":"L3",` +
		`"summary":"TLS was never attempted because the connection failed",` +
		`"evidenceRefs":["ep/tls"],"vantageDependent":false,` +
		`"discriminator":"Retry once the TCP connection succeeds."}],` +
		`"summary":{"status":"PROBLEMS_FOUND","firstBrokenLayer":"L2",` +
		`"findingCountsBySeverity":{"info":0,"warn":1,"error":1,"critical":0},` +
		`"skippedEvidenceCount":1,"unknownEvidenceCount":0},` +
		`"security":{"outputMode":"LOCAL_FULL","tlsVerificationDisabled":false,` +
		`"credentialForwardingEnabled":false}` +
		`}`

	if string(got) != want {
		t.Errorf("json.Marshal =\n%s\n\nwant\n%s", got, want)
	}
}

// TestReportJSONHasExactlyTheContractSections pins the top-level shape against
// docs/REPORT_SCHEMA.md, so an accidental extra section is caught.
func TestReportJSONHasExactlyTheContractSections(t *testing.T) {
	r, err := NewReport(fixtureInput(t))
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	want := []string{
		"schemaVersion", "run", "target", "vantage",
		"evidence", "findings", "summary", "security",
	}
	if len(decoded) != len(want) {
		t.Errorf("report has %d top-level sections, want %d: %v", len(decoded), len(want), decoded)
	}
	for _, section := range want {
		if _, present := decoded[section]; !present {
			t.Errorf("missing top-level section %q", section)
		}
	}
}

// TestRunAndSecurityCannotDisagree pins the single-source-of-truth decision for
// the two facts docs/REPORT_SCHEMA.md places in both sections.
func TestRunAndSecurityCannotDisagree(t *testing.T) {
	sec, err := NewReportSecurity(OutputModeLocalFull, true, true)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	in := fixtureInput(t)
	in.Security = sec

	r, err := NewReport(in)
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded struct {
		Run struct {
			TLSVerificationDisabled bool   `json:"tlsVerificationDisabled"`
			OutputMode              string `json:"outputMode"`
		} `json:"run"`
		Security struct {
			TLSVerificationDisabled bool   `json:"tlsVerificationDisabled"`
			OutputMode              string `json:"outputMode"`
		} `json:"security"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Run.TLSVerificationDisabled != decoded.Security.TLSVerificationDisabled {
		t.Error("run and security disagree about TLS verification")
	}
	if decoded.Run.OutputMode != decoded.Security.OutputMode {
		t.Error("run and security disagree about output mode")
	}
	if !decoded.Run.TLSVerificationDisabled {
		t.Error("the value did not come from the security metadata")
	}
}

// TestGraphHasNoStandaloneJSON pins ADR 0016: the report owns the external shape.
func TestGraphHasNoStandaloneJSON(t *testing.T) {
	var g any = Graph{}
	if _, ok := g.(json.Marshaler); ok {
		t.Error("Graph must not define a standalone JSON contract")
	}
}

func TestZeroReportIsInvalid(t *testing.T) {
	var r Report

	if !r.IsZero() {
		t.Error("the zero Report should report IsZero")
	}
	if r.String() != "<invalid report>" {
		t.Errorf("String() = %q", r.String())
	}
	if r.Findings() != nil {
		t.Error("the zero Report should return no findings")
	}
	if _, err := json.Marshal(r); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal err = %v, want ErrInvalidValue", err)
	}
}

// TestReportPerformsNoDiagnosisOrRedaction pins the boundaries this phase must
// not cross.
func TestReportPerformsNoDiagnosisOrRedaction(t *testing.T) {
	var r any = Report{}

	forbidden := []struct {
		name string
		has  bool
	}{
		{"Diagnose", hasMethod[interface{ Diagnose() []Finding }](r)},
		{"Evaluate", hasMethod[interface{ Evaluate() error }](r)},
		{"Redact", hasMethod[interface{ Redact() (Report, error) }](r)},
		{"Sanitize", hasMethod[interface{ Sanitize() Report }](r)},
		{"Render", hasMethod[interface{ Render() string }](r)},
		{"ExitCode", hasMethod[interface{ ExitCode() int }](r)},
		{"Raw", hasMethod[interface{ Raw() any }](r)},
	}
	for _, f := range forbidden {
		if f.has {
			t.Errorf("Report must not expose %s", f.name)
		}
	}
}
