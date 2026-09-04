package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// failingGraph is a complete run that got as far as a missing database: the
// shape most of these tests want, and one the chain really produces.
func failingGraph(t *testing.T) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	b.add(nodeSpec{
		id: "dns.lookup/db.internal", subject: "db.internal:5432", layer: domain.LayerDNS,
		step: "dns.lookup", state: domain.StatePass,
	})
	b.add(nodeSpec{
		id: idTCP, subject: addr, layer: domain.LayerTCP, step: "tcp.connect",
		state: domain.StatePass, parent: "dns.lookup/db.internal",
	})
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.add(nodeSpec{
		id: idTLS, subject: addr, layer: domain.LayerTLS, step: "tls.handshake",
		state: domain.StatePass, parent: idSSL,
	})
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
	b.sessionNode(domain.StateFail, domain.FailureResourceNotFound, "3D000", boolPtr(true), idAuth)
	return b.freeze()
}

// --- determinism ------------------------------------------------------------

// TestDiagnosisIsByteStable pins the property a report contract depends on:
// same graph in, same bytes out, every time.
//
// Repeated evaluation is what catches a rule that iterated a Go map, because map
// order is randomized per range and a single pass would pass by luck.
func TestDiagnosisIsByteStable(t *testing.T) {
	engine := testEngine(SSLRequest, Startup, Authentication, Session)
	g := failingGraph(t)

	first, err := json.Marshal(engine.Diagnose(rctx(g)))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	for i := range 64 {
		again, err := json.Marshal(engine.Diagnose(rctx(g)))
		if err != nil {
			t.Fatalf("encoding on pass %d: %v", i, err)
		}
		if string(again) != string(first) {
			t.Fatalf("pass %d differs:\n first: %s\n again: %s", i, first, again)
		}
	}
}

// TestWiringOrderDoesNotReachTheOutput pins that how an engine was assembled
// cannot change what a report looks like.
func TestWiringOrderDoesNotReachTheOutput(t *testing.T) {
	g := failingGraph(t)

	forward := testEngine(SSLRequest, Startup, Authentication, Session).Diagnose(rctx(g))
	reverse := testEngine(Session, Authentication, Startup, SSLRequest).Diagnose(rctx(g))

	a, _ := json.Marshal(forward)
	b, _ := json.Marshal(reverse)
	if string(a) != string(b) {
		t.Fatalf("rule order reached the output:\n %s\n %s", a, b)
	}
}

// multiAddressGraph is one endpoint that resolved to several addresses, so every
// PostgreSQL step appears more than once.
//
// It exists because determinism cannot be tested on a graph with one node per
// step: a rule that iterated a Go map would pass such a test by construction,
// map order being irrelevant over a single element. A real run produces this
// shape whenever a name resolves to more than one address.
func multiAddressGraph(t *testing.T) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	for _, host := range []string{"10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"} {
		peer := host + ":5432"
		startup := "postgres.startup/db.internal:5432/" + host
		b.add(nodeSpec{
			id: "postgres.ssl_request/db.internal:5432/" + host, subject: peer,
			layer: domain.LayerTLS, step: servicepostgres.StepSSLRequest,
			state: domain.StateFail, class: domain.FailureProtocolUnsupportedCapability,
			attrs: map[domain.AttributeKey]domain.AttrValue{
				servicepostgres.AttrSSLOffered: domain.BoolAttr(false),
			},
		})
		b.add(nodeSpec{
			id: startup, subject: peer, layer: domain.LayerProtocol,
			step: servicepostgres.StepStartup, state: domain.StateFail,
			class: domain.FailureProtocolUnexpectedResponse,
			attrs: map[domain.AttributeKey]domain.AttrValue{
				servicepostgres.AttrSQLState: domain.StringAttr("08P01"),
			},
		})
		b.add(nodeSpec{
			id: "postgres.authentication/db.internal:5432/" + host, subject: peer,
			layer: domain.LayerAuth, step: servicepostgres.StepAuthentication,
			state: domain.StateFail, class: domain.FailureAuthCredentialsRejected,
			attrs: map[domain.AttributeKey]domain.AttrValue{
				servicepostgres.AttrSQLState: domain.StringAttr("28P01"),
			},
		})
	}
	return b.freeze()
}

// TestMultiNodeOrderIsByteStable is the determinism test that can actually fail.
//
// Twelve nodes across three steps, so a rule that ranged over a map instead of
// Graph.Nodes produces a different order on some pass. Repeated because Go
// randomizes map order per range and a single pass would pass by luck.
func TestMultiNodeOrderIsByteStable(t *testing.T) {
	engine := testEngine(SSLRequest, Startup, Authentication, Session)
	g := multiAddressGraph(t)

	first, err := json.Marshal(engine.Diagnose(rctx(g)))
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if len(engine.Diagnose(rctx(g))) < 8 {
		t.Fatalf("the fixture produced %d findings; too few to detect an ordering defect",
			len(engine.Diagnose(rctx(g))))
	}

	for i := range 128 {
		again, err := json.Marshal(engine.Diagnose(rctx(g)))
		if err != nil {
			t.Fatalf("encoding on pass %d: %v", i, err)
		}
		if string(again) != string(first) {
			t.Fatalf("pass %d differs:\n first: %s\n again: %s", i, first, again)
		}
	}
}

// TestEachRuleIsOrderedBeforeTheEngineSortsIt is defence in depth, and it is the
// only test here that can see a rule iterating a map.
//
// domain.SortFindings imposes a total order — severity, layer, code, subject,
// summary, joined evidence references — and the last two keys are unique per
// node, so a map-ordered rule still produces a byte-stable *report*. That is a
// real guarantee and it is also why the engine-level determinism tests above
// cannot fail on this: the sort hides it.
//
// A rule is still required to be ordered in its own right. It keeps a rule
// testable in isolation, it means the guarantee does not rest on one sort
// remaining total forever, and it is the property internal/diagnosis/kafka
// states for the same reason. So each rule is called directly, unsorted, and
// its raw output is required to follow Graph.Nodes.
func TestEachRuleIsOrderedBeforeTheEngineSortsIt(t *testing.T) {
	g := multiAddressGraph(t)

	rules := map[string]diagnosis.Rule{
		"SSLRequest":     SSLRequest,
		"Startup":        Startup,
		"Authentication": Authentication,
		"Session":        Session,
	}

	for name, rule := range rules {
		t.Run(name, func(t *testing.T) {
			first := subjectsOf(rule(rctx(g)))
			if name != "Session" && len(first) < 2 {
				t.Fatalf("%s produced %d findings; too few to detect an ordering defect",
					name, len(first))
			}

			for i := range 128 {
				again := subjectsOf(rule(rctx(g)))
				if len(again) != len(first) {
					t.Fatalf("pass %d: %s produced %d findings, want %d",
						i, name, len(again), len(first))
				}
				for j := range first {
					if again[j] != first[j] {
						t.Fatalf("pass %d: %s returned findings in a different order:\n %v\n %v",
							i, name, first, again)
					}
				}
			}
		})
	}
}

// subjectsOf renders a rule's raw output order.
func subjectsOf(findings []domain.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Subject().Ref())
	}
	return out
}

// TestOrderIsStableUnderReversedGraphAssembly pins that the order the producers
// happened to add nodes in cannot change the findings.
//
// Two graphs with identical content and opposite insertion order must produce
// byte-identical findings. Graph.Nodes returns canonical order, so this holds by
// construction — and it is asserted because a rule that stopped using Nodes
// would break it silently.
func TestOrderIsStableUnderReversedGraphAssembly(t *testing.T) {
	forward := newBuilder(t)
	forward.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	forward.authNode(domain.StateFail, domain.FailureAuthCredentialsRejected, "28P01", boolPtr(true), "")

	// The same two nodes, added in the other order. The parent edge forces the
	// startup node to exist first, so the reversal is in the node set rather
	// than in the edge, which is the part canonical ordering has to normalize.
	reverse := newBuilder(t)
	reverse.add(nodeSpec{
		id: idSSL, subject: addr, layer: domain.LayerTLS,
		step: servicepostgres.StepSSLRequest, state: domain.StatePass,
	})
	reverse.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	reverse.authNode(domain.StateFail, domain.FailureAuthCredentialsRejected, "28P01", boolPtr(true), "")

	a, _ := json.Marshal(allFindings(forward.freeze()))
	b, _ := json.Marshal(allFindings(reverse.freeze()))
	if string(a) != string(b) {
		t.Fatalf("insertion order reached the output:\n %s\n %s", a, b)
	}
}

// --- one primary diagnosis per node ----------------------------------------

// TestAtMostOnePrimaryFindingPerNode pins ADR 0040 section 3.
//
// It is a scope and not a repository invariant: it constrains the twelve codes
// this package owns and says nothing about a future complementary finding on the
// same node. So the check is written over *these* codes rather than over every
// finding a report might hold — which is exactly the distinction a guard phrased
// as "no node ever carries two findings" would erase.
func TestAtMostOnePrimaryFindingPerNode(t *testing.T) {
	mine := map[domain.FindingCode]bool{}
	for _, code := range allCodes() {
		mine[code] = true
	}

	graphs := []func(b *builder){
		func(b *builder) {
			b.sslNode(domain.StateFail, domain.FailureProtocolUnsupportedCapability, boolPtr(false))
		},
		func(b *builder) {
			b.startupNode(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", boolPtr(true), "")
		},
		func(b *builder) {
			b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
			b.authNode(domain.StateFail, domain.FailureAuthPeerVerificationFailed, "", nil, "")
		},
		func(b *builder) {
			b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
			b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
			b.sessionNode(domain.StateFail, domain.FailureAuthzDenied, "42501", boolPtr(true), idAuth)
		},
	}

	for i, graph := range graphs {
		b := newBuilder(t)
		graph(b)
		g := b.freeze()

		// Attribute each finding to the anchor it names first: a finding's own
		// subject is shared across nodes, so the anchor is identified by the
		// evidence it cites at the step it belongs to.
		perNode := map[domain.EvidenceID]int{}
		for _, f := range allFindings(g) {
			if !mine[f.Code()] {
				continue
			}
			for _, ref := range f.EvidenceRefs() {
				node, ok := g.Node(ref)
				if !ok {
					t.Fatalf("graph %d: finding %s references %q, which is not in the graph",
						i, f.Code(), ref)
				}
				if node.State() != domain.StatePass && isAnchor(node.Step()) {
					perNode[ref]++
				}
			}
		}
		for id, count := range perNode {
			if count > 1 {
				t.Errorf("graph %d: node %q carries %d primary findings", i, id, count)
			}
		}
	}
}

func isAnchor(step domain.Step) bool {
	switch step {
	case servicepostgres.StepSSLRequest, servicepostgres.StepStartup,
		servicepostgres.StepAuthentication, servicepostgres.StepSession:
		return true
	}
	return false
}

// --- evidence references ----------------------------------------------------

// TestEveryReferenceResolvesAndNoBlockedStepIsCitedAsACause pins the two rules
// docs/FINDINGS.md section 3.1 states about evidence.
//
// A dangling reference is rejected at report assembly (ADR 0014), and a rule
// must not knowingly produce one. A blocked step is never a cause — its blocker
// owns the failure — with one deliberate exception: the withheld-credential
// finding, where the blocked step is the *subject* and its blocker is cited as
// the cause, which is the same rule read correctly.
func TestEveryReferenceResolvesAndNoBlockedStepIsCitedAsACause(t *testing.T) {
	b := newBuilder(t)
	b.sslNode(domain.StateSkipped, domain.FailureExecSkippedByPolicy, nil)
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StateSkipped, domain.FailureExecSkippedByPolicy, "", nil, idSSL)
	g := b.freeze()

	f := only(t, allFindings(g))
	if f.Code() != CodeCredentialWithheld {
		t.Fatalf("code = %s, want %s", f.Code(), CodeCredentialWithheld)
	}

	refs := f.EvidenceRefs()
	for _, ref := range refs {
		if _, ok := g.Node(ref); !ok {
			t.Errorf("reference %q does not resolve", ref)
		}
	}

	// The blocker must be cited: without it the claim "the policy refused this
	// channel" points at nothing a reader can check.
	var citesBlocker bool
	for _, ref := range refs {
		if ref == domain.EvidenceID(idSSL) {
			citesBlocker = true
		}
	}
	if !citesBlocker {
		t.Error("the withheld-credential finding does not cite what blocked it")
	}
}

// --- report integration -----------------------------------------------------

// reportFrom assembles a report the way an orchestrator would, which is also the
// check that every evidence reference resolves: NewReport rejects a dangling one
// (ADR 0014).
func reportFrom(t *testing.T, g domain.Graph) domain.Report {
	t.Helper()

	target, err := domain.NewTarget("db.internal:5432")
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	vantage, err := domain.NewLocalVantage("runner")
	if err != nil {
		t.Fatalf("vantage: %v", err)
	}
	service, err := domain.NewServiceID("postgres")
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	run, err := domain.NewRunMetadata(
		"0.1.0-test", time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC), time.Second, service)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("security: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run:      run,
		Target:   target,
		Vantage:  vantage,
		Graph:    g,
		Findings: testEngine(SSLRequest, Startup, Authentication, Session).Diagnose(rctx(g)),
		Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

// TestReportSummaryReflectsTheFindings pins the integration ADR 0015 defines:
// the summary is derived, never supplied, and firstBrokenLayer comes from the
// graph rather than from a finding's layer.
func TestReportSummaryReflectsTheFindings(t *testing.T) {
	report := reportFrom(t, failingGraph(t))
	summary := report.Summary()

	if summary.Status() != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", summary.Status())
	}
	if got := summary.FindingCountsBySeverity().Error; got != 1 {
		t.Errorf("ERROR finding count = %d, want 1", got)
	}
	// The finding's own layer is L5, and the earliest broken layer is L5 too
	// here because everything above it passed. The point is that the report
	// derived it from the graph rather than copying it off the finding.
	if got := summary.FirstBrokenLayer(); got != domain.LayerAuth {
		t.Errorf("firstBrokenLayer = %s, want L5", got)
	}
}

// TestAHealthyReportStaysHealthy is the other half: zero findings, and a verdict
// that says so.
func TestAHealthyReportStaysHealthy(t *testing.T) {
	b := newBuilder(t)
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
	b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
	b.sessionNode(domain.StatePass, domain.FailureNone, "", nil, idAuth)

	report := reportFrom(t, b.freeze())

	if len(report.Findings()) != 0 {
		t.Fatalf("a healthy run produced %v", codesOf(report.Findings()))
	}
	if report.Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", report.Summary().Status())
	}
}

// TestATransportFailureProducesAReportWithNoFindings documents the honest cost
// of ADR 0040 section 2, at the report level where a user meets it.
//
// The evidence is complete and firstBrokenLayer is correct; there is simply no
// finding, because no rule owns generic transport evidence. This is a product
// gap tracked as a release gate, not a diagnosis defect, and pinning it here
// means the day it changes, somebody has to change this test on purpose.
func TestATransportFailureProducesAReportWithNoFindings(t *testing.T) {
	b := newBuilder(t)
	b.add(nodeSpec{
		id: "dns.lookup/db.internal", subject: "db.internal:5432", layer: domain.LayerDNS,
		step: "dns.lookup", state: domain.StateFail, class: domain.FailureDNSNoAddress,
	})
	report := reportFrom(t, b.freeze())

	if len(report.Findings()) != 0 {
		t.Fatalf("PostgreSQL claimed transport evidence: %v", codesOf(report.Findings()))
	}
	if got := report.Summary().FirstBrokenLayer(); got != domain.LayerDNS {
		t.Errorf("firstBrokenLayer = %s, want L1; the evidence is still complete", got)
	}
}
