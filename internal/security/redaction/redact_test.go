package redaction

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Canaries. Every assertion checks that the exact original value is absent,
// never that the output merely looks masked.
const (
	canaryHostBootstrap = "kafka.prod.internal"
	canaryHostBroker    = "broker-7.corp.example.com"
	canaryIP            = "10.20.30.40"
	canaryVantageHost   = "laptop-of-jane.corp.example.com"
	canarySecret        = "svcdoctor-canary-secret-9f3c7a"
)

var allCanaries = []string{
	canaryHostBootstrap, canaryHostBroker, canaryIP, canaryVantageHost, canarySecret,
}

var testStart = time.Date(2026, 8, 21, 10, 30, 0, 0, time.UTC)

// --- fixture -----------------------------------------------------------------

func mustID(t *testing.T, s string) domain.EvidenceID {
	t.Helper()
	id, err := domain.NewEvidenceID(s)
	if err != nil {
		t.Fatalf("NewEvidenceID(%q): %v", s, err)
	}
	return id
}

func mustStep(t *testing.T, s string) domain.Step {
	t.Helper()
	step, err := domain.NewStep(s)
	if err != nil {
		t.Fatalf("NewStep(%q): %v", s, err)
	}
	return step
}

func mustEndpointSubject(t *testing.T, ref string) domain.Subject {
	t.Helper()
	s, err := domain.NewEndpointSubject(ref)
	if err != nil {
		t.Fatalf("NewEndpointSubject(%q): %v", ref, err)
	}
	return s
}

type nodeSpec struct {
	id      string
	ref     string
	layer   domain.Layer
	step    string
	state   domain.State
	failure domain.FailureClass
	attrs   map[domain.AttributeKey]domain.AttrValue
}

func mustEvidence(t *testing.T, s nodeSpec) domain.Evidence {
	t.Helper()
	e, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           mustID(t, s.id),
		Subject:      mustEndpointSubject(t, s.ref),
		Layer:        s.layer,
		Step:         mustStep(t, s.step),
		State:        s.state,
		FailureClass: s.failure,
		Attributes:   s.attrs,
		StartedAt:    testStart,
		Duration:     12 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewEvidence(%q): %v", s.id, err)
	}
	return e
}

func nodeSpecs() []nodeSpec {
	return []nodeSpec{
		{
			id: "target/ep:" + canaryHostBootstrap + ":9092/dns", ref: canaryHostBootstrap + ":9092",
			layer: domain.LayerDNS, step: "dns.lookup", state: domain.StatePass,
			attrs: map[domain.AttributeKey]domain.AttrValue{
				"dns.rcode":     domain.StringAttr("NOERROR"),
				"dns.addresses": domain.StringListAttr(canaryIP),
				"dns.latency":   domain.DurationAttr(3 * time.Millisecond),
				"dns.answers":   domain.IntAttr(1),
			},
		},
		{
			id: "target/ep:" + canaryHostBroker + ":9092/tcp", ref: canaryHostBroker + ":9092",
			layer: domain.LayerTCP, step: "tcp.connect", state: domain.StateFail,
			failure: domain.FailureTCPConnectionRefused,
			attrs: map[domain.AttributeKey]domain.AttrValue{
				"tcp.peer":    domain.StringAttr(canaryIP + ":9092"),
				"tcp.latency": domain.DurationAttr(500 * time.Millisecond),
			},
		},
		{
			id: "target/ep:" + canaryHostBroker + ":9092/tls", ref: canaryHostBroker + ":9092",
			layer: domain.LayerTLS, step: "tls.handshake", state: domain.StateSkipped,
			failure: domain.FailureExecSkippedPrerequisiteFailed,
			attrs: map[domain.AttributeKey]domain.AttrValue{
				"tls.negotiated_version": domain.StringAttr("TLSv1.3"),
			},
		},
	}
}

// buildLocalReport assembles a LOCAL_FULL report, adding nodes and findings in
// the given orders so tests can prove ordering does not affect the result.
func buildLocalReport(t *testing.T, nodeOrder, findingOrder []int) domain.Report {
	t.Helper()

	specs := nodeSpecs()
	b := domain.NewGraphBuilder()
	for _, i := range nodeOrder {
		if err := b.AddEvidence(mustEvidence(t, specs[i])); err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
	}
	dnsID := mustID(t, specs[0].id)
	tcpID := mustID(t, specs[1].id)
	tlsID := mustID(t, specs[2].id)

	if err := b.AddParent(tcpID, dnsID); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddParent(tlsID, tcpID); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddBlockedBy(tlsID, tcpID); err != nil {
		t.Fatalf("AddBlockedBy: %v", err)
	}
	graph, err := b.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	findings := []domain.Finding{
		mustFinding(t, domain.FindingInput{
			Code:     mustCode(t, "TCP_CONNECTION_REFUSED"),
			Kind:     domain.FindingKindConfirmed,
			Severity: domain.SeverityError,
			// Prose deliberately embeds identifiers copied from evidence.
			Confidence:   domain.ConfidenceHigh,
			Layer:        domain.LayerTCP,
			Subject:      mustEndpointSubject(t, canaryHostBroker+":9092"),
			Summary:      "connection to " + canaryHostBroker + ":9092 was refused",
			Detail:       "The bootstrap host " + canaryHostBootstrap + " resolved to " + canaryIP + ".",
			EvidenceRefs: []domain.EvidenceID{tcpID},
			Recommendations: []domain.Recommendation{
				mustRecommendation(t, "Check whether "+canaryHostBroker+" accepts connections."),
			},
			VantageDependent: true,
		}),
		mustFinding(t, domain.FindingInput{
			Code:             mustCode(t, "TLS_HANDSHAKE_NOT_ATTEMPTED"),
			Kind:             domain.FindingKindHypothesis,
			Severity:         domain.SeverityWarn,
			Confidence:       domain.ConfidenceMedium,
			Layer:            domain.LayerTLS,
			Summary:          "TLS was never attempted",
			EvidenceRefs:     []domain.EvidenceID{tlsID},
			VantageDependent: false,
			Discriminator:    "Retry once " + canaryHostBroker + " accepts connections.",
		}),
	}
	ordered := make([]domain.Finding, 0, len(findings))
	for _, i := range findingOrder {
		ordered = append(ordered, findings[i])
	}

	run, err := domain.NewRunMetadata("0.1.0", testStart, 1500*time.Millisecond, "kafka")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(canaryHostBootstrap+":9092", canaryHostBootstrap+":9092", canaryIP+":9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(canaryVantageHost)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, true, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: ordered, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func mustCode(t *testing.T, s string) domain.FindingCode {
	t.Helper()
	c, err := domain.NewFindingCode(s)
	if err != nil {
		t.Fatalf("NewFindingCode(%q): %v", s, err)
	}
	return c
}

func mustRecommendation(t *testing.T, action string) domain.Recommendation {
	t.Helper()
	r, err := domain.NewRecommendation(action)
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	return r
}

func mustFinding(t *testing.T, in domain.FindingInput) domain.Finding {
	t.Helper()
	f, err := domain.NewFinding(in)
	if err != nil {
		t.Fatalf("NewFinding(%q): %v", in.Code, err)
	}
	return f
}

func localReport(t *testing.T) domain.Report {
	t.Helper()
	return buildLocalReport(t, []int{0, 1, 2}, []int{0, 1})
}

func mustRedact(t *testing.T, r domain.Report) domain.Report {
	t.Helper()
	out, err := Redact(r)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	return out
}

func encode(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(raw)
}

// --- transformation ----------------------------------------------------------

func TestRedactProducesShareableReport(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	if got := shareable.Security().OutputMode(); got != domain.OutputModeShareableRedacted {
		t.Errorf("OutputMode() = %s, want SHAREABLE_REDACTED", got)
	}
	if shareable.IsZero() {
		t.Error("the shareable report must be valid")
	}
	// Constructed through domain constructors, so it re-encodes cleanly.
	if _, err := json.Marshal(shareable); err != nil {
		t.Errorf("the shareable report does not encode: %v", err)
	}
}

func TestInputReportIsUnchanged(t *testing.T) {
	local := localReport(t)
	before := encode(t, local)

	_ = mustRedact(t, local)

	if after := encode(t, local); after != before {
		t.Errorf("the local report changed:\n%s\n%s", before, after)
	}
	if local.Security().OutputMode() != domain.OutputModeLocalFull {
		t.Error("the local report's output mode changed")
	}
	if !strings.Contains(before, canaryHostBootstrap) {
		t.Error("the fixture should contain the canary before redaction")
	}
}

// --- canaries ----------------------------------------------------------------

// TestNoCanarySurvivesRedaction is the central security assertion. It checks for
// the exact original values, not for the presence of pseudonyms.
func TestNoCanarySurvivesRedaction(t *testing.T) {
	shareable := mustRedact(t, localReport(t))
	encoded := encode(t, shareable)

	paths := map[string]string{
		"canonical JSON":  encoded,
		"report String()": shareable.String(),
		"target":          encode(t, shareable.Target()),
		"vantage":         encode(t, shareable.Vantage()),
		"security":        encode(t, shareable.Security()),
		"summary":         encode(t, shareable.Summary()),
		"fmt %v":          fmt.Sprintf("%v", shareable),
		"fmt %+v":         fmt.Sprintf("%+v", shareable),
	}
	for _, node := range shareable.Graph().Nodes() {
		paths["evidence "+string(node.ID())] = encode(t, node)
		paths["evidence id "+string(node.ID())] = string(node.ID())
	}
	for i, f := range shareable.Findings() {
		paths[fmt.Sprintf("finding %d", i)] = encode(t, f)
		paths[fmt.Sprintf("finding %d String()", i)] = f.String()
	}

	for path, got := range paths {
		for _, canary := range allCanaries {
			if strings.Contains(got, canary) {
				t.Errorf("%q leaked through %s", canary, path)
			}
		}
	}
}

// TestCanariesArePresentBeforeRedaction guards the guard: if the fixture ever
// stops containing the canaries, the test above would pass vacuously.
func TestCanariesArePresentBeforeRedaction(t *testing.T) {
	encoded := encode(t, localReport(t))

	for _, canary := range []string{canaryHostBootstrap, canaryHostBroker, canaryIP, canaryVantageHost} {
		if !strings.Contains(encoded, canary) {
			t.Errorf("the fixture should contain %q before redaction", canary)
		}
	}
	// The secret canary must never be present at all: a report has no field
	// that can hold one.
	if strings.Contains(encoded, canarySecret) {
		t.Error("a report must never carry a secret, even before redaction")
	}
}

// --- pseudonymization --------------------------------------------------------

// TestSameValueMapsToOnePseudonym is the "preserve correlation" requirement: a
// reader must still be able to see that one host appears in several places.
func TestSameValueMapsToOnePseudonym(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	// The broker appears as two evidence subjects and one finding subject.
	refs := map[string]int{}
	for _, n := range shareable.Graph().Nodes() {
		refs[n.Subject().Ref()]++
	}
	brokerRefs := 0
	for ref, n := range refs {
		if strings.HasSuffix(ref, ":9092") && n == 2 {
			brokerRefs = n
		}
	}
	if brokerRefs != 2 {
		t.Errorf("the two broker subjects should share one pseudonym, got %v", refs)
	}

	var findingRef string
	for _, f := range shareable.Findings() {
		if !f.Subject().IsZero() {
			findingRef = f.Subject().Ref()
		}
	}
	found := false
	for ref := range refs {
		if ref == findingRef {
			found = true
		}
	}
	if !found {
		t.Errorf("the finding subject %q should match an evidence subject %v", findingRef, refs)
	}
}

func TestDistinctValuesMapToDistinctPseudonyms(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	seen := map[string]struct{}{}
	for _, n := range shareable.Graph().Nodes() {
		seen[n.Subject().Ref()] = struct{}{}
	}
	// Two distinct hosts were present, so two distinct pseudonyms must remain.
	if len(seen) != 2 {
		t.Errorf("expected 2 distinct subject pseudonyms, got %v", seen)
	}
}

func TestPseudonymShape(t *testing.T) {
	shareable := mustRedact(t, localReport(t))
	encoded := encode(t, shareable)

	for _, want := range []string{"host-001", "ip-001", "evidence-001"} {
		if !strings.Contains(encoded, want) {
			t.Errorf("expected a %q pseudonym in the shareable report: %s", want, encoded)
		}
	}
}

// --- vantage, target ---------------------------------------------------------

func TestVantageKeepsSourceAndLosesIdentity(t *testing.T) {
	shareable := mustRedact(t, localReport(t))
	v := shareable.Vantage()

	if v.Source() != domain.VantageSourceLocalHost {
		t.Errorf("Source() = %s, want LOCAL_HOST", v.Source())
	}
	if v.Host() == canaryVantageHost {
		t.Error("the vantage host was not redacted")
	}
	if v.Host() == "" {
		t.Error("the vantage must still identify a position, pseudonymously")
	}
}

// TestTargetKeepsPortAndLosesHost pins the rule that a port is diagnostic
// information rather than an identifier.
func TestTargetKeepsPortAndLosesHost(t *testing.T) {
	shareable := mustRedact(t, localReport(t))
	tgt := shareable.Target()

	if strings.Contains(tgt.Requested(), canaryHostBootstrap) {
		t.Errorf("the requested target still names the host: %q", tgt.Requested())
	}
	if !strings.HasSuffix(tgt.Requested(), ":9092") {
		t.Errorf("the port should be preserved: %q", tgt.Requested())
	}
	for _, n := range tgt.Normalized() {
		for _, canary := range allCanaries {
			if strings.Contains(n, canary) {
				t.Errorf("normalized target %q leaked %q", n, canary)
			}
		}
		if !strings.HasSuffix(n, ":9092") {
			t.Errorf("normalized target lost its port: %q", n)
		}
	}
}

// --- attributes --------------------------------------------------------------

// TestDiagnosticAttributesSurvive is the usefulness requirement: redaction must
// not destroy the values a reader needs.
func TestDiagnosticAttributesSurvive(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	want := map[domain.AttributeKey]string{
		"dns.rcode":              "NOERROR",
		"tls.negotiated_version": "TLSv1.3",
	}
	found := map[domain.AttributeKey]bool{}

	for _, n := range shareable.Graph().Nodes() {
		for key, value := range n.Attributes() {
			if expected, ok := want[key]; ok {
				got, _ := value.Str()
				if got != expected {
					t.Errorf("attribute %q = %q, want %q", key, got, expected)
				}
				found[key] = true
			}
			// Non-string kinds must survive untouched.
			if key == "dns.latency" {
				if d, ok := value.Duration(); !ok || d != 3*time.Millisecond {
					t.Errorf("dns.latency = %v, %v", d, ok)
				}
			}
			if key == "dns.answers" {
				if n, ok := value.Int(); !ok || n != 1 {
					t.Errorf("dns.answers = %v, %v", n, ok)
				}
			}
		}
	}
	for key := range want {
		if !found[key] {
			t.Errorf("attribute %q disappeared", key)
		}
	}
}

func TestIdentifyingAttributesAreRedacted(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	sawAddresses, sawPeer := false, false
	for _, n := range shareable.Graph().Nodes() {
		for key, value := range n.Attributes() {
			switch key {
			case "dns.addresses":
				list, ok := value.StringList()
				if !ok {
					t.Fatal("dns.addresses is not a string list")
				}
				sawAddresses = true
				for _, v := range list {
					if v == canaryIP {
						t.Error("dns.addresses still contains the raw IP")
					}
					if !strings.HasPrefix(v, "ip-") {
						t.Errorf("dns.addresses entry %q is not pseudonymized", v)
					}
				}
			case "tcp.peer":
				got, _ := value.Str()
				sawPeer = true
				if strings.Contains(got, canaryIP) {
					t.Errorf("tcp.peer still contains the raw IP: %q", got)
				}
				if !strings.HasSuffix(got, ":9092") {
					t.Errorf("tcp.peer lost its port: %q", got)
				}
			}
		}
	}
	if !sawAddresses || !sawPeer {
		t.Error("the identifying attributes disappeared instead of being redacted")
	}
}

// --- prose -------------------------------------------------------------------

func TestFindingProseIsRedacted(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	for _, f := range shareable.Findings() {
		fields := map[string]string{
			"summary":       f.Summary(),
			"detail":        f.Detail(),
			"discriminator": f.Discriminator(),
		}
		for _, r := range f.Recommendations() {
			fields["recommendation"] = r.Action()
		}
		for name, value := range fields {
			for _, canary := range allCanaries {
				if strings.Contains(value, canary) {
					t.Errorf("finding %s %s leaked %q: %q", f.Code(), name, canary, value)
				}
			}
		}
		if f.Summary() == "" {
			t.Error("prose was blanked instead of pseudonymized")
		}
	}
}

// TestProseKeepsItsShape pins that redaction substitutes values rather than
// destroying the sentence, so a shareable report is still readable.
func TestProseKeepsItsShape(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	for _, f := range shareable.Findings() {
		if f.Code() != "TCP_CONNECTION_REFUSED" {
			continue
		}
		if !strings.HasPrefix(f.Summary(), "connection to ") ||
			!strings.HasSuffix(f.Summary(), " was refused") {
			t.Errorf("the sentence lost its shape: %q", f.Summary())
		}
		if !strings.Contains(f.Summary(), "host-") {
			t.Errorf("the summary should carry a pseudonym: %q", f.Summary())
		}
	}
}

// --- graph and identifiers ---------------------------------------------------

// TestEvidenceIDsAreRemapped pins the decision that identifiers are rewritten
// because the identifier grammar allows a hostname inside them.
func TestEvidenceIDsAreRemapped(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	for _, n := range local.Graph().Nodes() {
		if !strings.Contains(string(n.ID()), ".") {
			t.Fatalf("the fixture should use identity-bearing identifiers, got %q", n.ID())
		}
	}
	for _, n := range shareable.Graph().Nodes() {
		if !strings.HasPrefix(string(n.ID()), "evidence-") {
			t.Errorf("identifier %q was not remapped", n.ID())
		}
	}
}

func TestGraphTopologyIsPreserved(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	if local.Graph().Len() != shareable.Graph().Len() {
		t.Fatalf("node count changed: %d -> %d", local.Graph().Len(), shareable.Graph().Len())
	}

	// Same shape: one node with no parents, two with one each, one blocked.
	countEdges := func(g domain.Graph) (parents, blockers int) {
		for _, n := range g.Nodes() {
			parents += len(g.Parents(n.ID()))
			blockers += len(g.BlockedBy(n.ID()))
		}
		return parents, blockers
	}
	lp, lb := countEdges(local.Graph())
	sp, sb := countEdges(shareable.Graph())
	if lp != sp || lb != sb {
		t.Errorf("edges changed: parents %d->%d, blockers %d->%d", lp, sp, lb, sb)
	}

	// Every relationship still points at a node that exists.
	for _, n := range shareable.Graph().Nodes() {
		for _, p := range shareable.Graph().Parents(n.ID()) {
			if _, ok := shareable.Graph().Node(p); !ok {
				t.Errorf("parent %q of %q does not exist", p, n.ID())
			}
		}
		for _, blk := range shareable.Graph().BlockedBy(n.ID()) {
			if _, ok := shareable.Graph().Node(blk); !ok {
				t.Errorf("blocker %q of %q does not exist", blk, n.ID())
			}
		}
	}
}

// TestFindingRefsResolveAfterRemapping proves the ADR 0014 invariant survives:
// NewReport would have rejected the result otherwise.
func TestFindingRefsResolveAfterRemapping(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	for _, f := range shareable.Findings() {
		if f.EvidenceRefCount() == 0 {
			t.Errorf("finding %s lost its evidence references", f.Code())
		}
		for _, ref := range f.EvidenceRefs() {
			if !strings.HasPrefix(string(ref), "evidence-") {
				t.Errorf("finding %s references an unmapped identifier %q", f.Code(), ref)
			}
			if _, ok := shareable.Graph().Node(ref); !ok {
				t.Errorf("finding %s references %q which is not in the graph", f.Code(), ref)
			}
		}
	}
}

// --- semantic preservation ---------------------------------------------------

// TestDiagnosticSemanticsAreUnchanged is the usefulness contract: only
// identifying data may change.
func TestDiagnosticSemanticsAreUnchanged(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	// Evidence, compared by canonical position rather than identifier.
	ln, sn := local.Graph().Nodes(), shareable.Graph().Nodes()
	if len(ln) != len(sn) {
		t.Fatalf("node count changed: %d -> %d", len(ln), len(sn))
	}
	for i := range ln {
		if ln[i].Layer() != sn[i].Layer() {
			t.Errorf("node %d layer changed: %s -> %s", i, ln[i].Layer(), sn[i].Layer())
		}
		if ln[i].State() != sn[i].State() {
			t.Errorf("node %d state changed: %s -> %s", i, ln[i].State(), sn[i].State())
		}
		if ln[i].FailureClass() != sn[i].FailureClass() {
			t.Errorf("node %d failure class changed", i)
		}
		if ln[i].Step() != sn[i].Step() {
			t.Errorf("node %d step changed: %s -> %s", i, ln[i].Step(), sn[i].Step())
		}
		if !ln[i].StartedAt().Equal(sn[i].StartedAt()) || ln[i].Duration() != sn[i].Duration() {
			t.Errorf("node %d timing changed", i)
		}
		if ln[i].AttributeCount() != sn[i].AttributeCount() {
			t.Errorf("node %d attribute count changed", i)
		}
		if ln[i].Subject().Kind() != sn[i].Subject().Kind() {
			t.Errorf("node %d subject kind changed", i)
		}
	}

	// Findings.
	lf, sf := local.Findings(), shareable.Findings()
	if len(lf) != len(sf) {
		t.Fatalf("finding count changed: %d -> %d", len(lf), len(sf))
	}
	for i := range lf {
		if lf[i].Code() != sf[i].Code() {
			t.Errorf("finding %d code changed: %s -> %s", i, lf[i].Code(), sf[i].Code())
		}
		if lf[i].Kind() != sf[i].Kind() ||
			lf[i].Severity() != sf[i].Severity() ||
			lf[i].Confidence() != sf[i].Confidence() ||
			lf[i].Layer() != sf[i].Layer() ||
			lf[i].VantageDependent() != sf[i].VantageDependent() {
			t.Errorf("finding %d judgement changed", i)
		}
		if lf[i].EvidenceRefCount() != sf[i].EvidenceRefCount() {
			t.Errorf("finding %d evidence reference count changed", i)
		}
	}

	// Summary.
	ls, ss := local.Summary(), shareable.Summary()
	if ls.Status() != ss.Status() {
		t.Errorf("status changed: %s -> %s", ls.Status(), ss.Status())
	}
	if ls.FirstBrokenLayer() != ss.FirstBrokenLayer() {
		t.Errorf("first broken layer changed: %s -> %s", ls.FirstBrokenLayer(), ss.FirstBrokenLayer())
	}
	if ls.FindingCountsBySeverity() != ss.FindingCountsBySeverity() {
		t.Errorf("severity counts changed: %+v -> %+v",
			ls.FindingCountsBySeverity(), ss.FindingCountsBySeverity())
	}
	if ls.SkippedEvidenceCount() != ss.SkippedEvidenceCount() {
		t.Errorf("skipped count changed: %d -> %d", ls.SkippedEvidenceCount(), ss.SkippedEvidenceCount())
	}
	if ls.UnknownEvidenceCount() != ss.UnknownEvidenceCount() {
		t.Errorf("unknown count changed: %d -> %d", ls.UnknownEvidenceCount(), ss.UnknownEvidenceCount())
	}
}

// TestRunMetadataIsPreserved pins that nothing was removed without repository
// support. docs/SECURITY.md names no run field as sensitive.
func TestRunMetadataIsPreserved(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	lr, sr := local.Run(), shareable.Run()
	if lr.SvcdoctorVersion() != sr.SvcdoctorVersion() ||
		!lr.StartedAt().Equal(sr.StartedAt()) ||
		lr.Duration() != sr.Duration() ||
		lr.Service() != sr.Service() {
		t.Error("run metadata changed")
	}
}

// TestSecurityFlagsArePreserved pins that interpretation caveats survive: a
// shareable report must still say the run ran with TLS verification off.
func TestSecurityFlagsArePreserved(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	if shareable.Security().TLSVerificationDisabled() != local.Security().TLSVerificationDisabled() {
		t.Error("the TLS verification flag was lost")
	}
	if shareable.Security().CredentialForwardingEnabled() != local.Security().CredentialForwardingEnabled() {
		t.Error("the credential forwarding flag was lost")
	}
}

// --- metadata ----------------------------------------------------------------

func TestRedactionCountsAreDerived(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	counts := shareable.Security().Redactions()
	if counts.Total() == 0 {
		t.Fatal("the counts should reflect an actual transformation")
	}
	if counts.Hostname == 0 {
		t.Error("hostnames were replaced but not counted")
	}
	if counts.IPAddress == 0 {
		t.Error("IP addresses were replaced but not counted")
	}
	// Distinct values, not occurrences: three identifiers exist, each referenced
	// several times as a node, a parent, a blocker and a finding reference.
	if counts.EvidenceID != 3 {
		t.Errorf("EvidenceID count = %d, want 3 distinct identifiers", counts.EvidenceID)
	}
	// The bootstrap host, the broker host and the vantage host.
	if counts.Hostname != 3 {
		t.Errorf("Hostname count = %d, want 3 distinct hosts", counts.Hostname)
	}
	if counts.IPAddress != 1 {
		t.Errorf("IPAddress count = %d, want 1 distinct address", counts.IPAddress)
	}
	if counts.Prose == 0 {
		t.Error("prose was rewritten but not counted")
	}

	// A local report carries no counts at all.
	if local.Security().Redactions().Total() != 0 {
		t.Error("a local report must not report redactions")
	}
	if strings.Contains(encode(t, local.Security()), "redactions") {
		t.Error("a local report must not encode a redaction section")
	}
	if !strings.Contains(encode(t, shareable.Security()), "redactions") {
		t.Error("a shareable report must encode its redaction counts")
	}
}

// TestCountsRevealNoValues pins that metadata describes what was removed, never
// what it was.
func TestCountsRevealNoValues(t *testing.T) {
	shareable := mustRedact(t, localReport(t))
	encoded := encode(t, shareable.Security())

	for _, canary := range allCanaries {
		if strings.Contains(encoded, canary) {
			t.Errorf("the security metadata leaked %q", canary)
		}
	}
}

// --- determinism -------------------------------------------------------------

func TestRedactionIsDeterministic(t *testing.T) {
	local := localReport(t)

	first := encode(t, mustRedact(t, local))
	for i := 0; i < 25; i++ {
		if again := encode(t, mustRedact(t, local)); again != first {
			t.Fatalf("run %d differed:\n%s\n%s", i, first, again)
		}
	}
}

// TestPseudonymsDoNotDependOnInsertionOrder is the reason assignment is a
// separate sorted pass rather than numbering on first encounter.
func TestPseudonymsDoNotDependOnInsertionOrder(t *testing.T) {
	orders := []struct {
		nodes    []int
		findings []int
	}{
		{[]int{0, 1, 2}, []int{0, 1}},
		{[]int{2, 1, 0}, []int{1, 0}},
		{[]int{1, 0, 2}, []int{0, 1}},
		{[]int{2, 0, 1}, []int{1, 0}},
	}

	var reference string
	for _, o := range orders {
		got := encode(t, mustRedact(t, buildLocalReport(t, o.nodes, o.findings)))
		if reference == "" {
			reference = got
			continue
		}
		if got != reference {
			t.Fatalf("insertion order %v/%v changed the shareable report:\n%s\n%s",
				o.nodes, o.findings, reference, got)
		}
	}
}

// --- idempotence -------------------------------------------------------------

// TestRedactIsIdempotent pins behaviour A: an already-shareable report comes
// back unchanged, so pseudonyms are never pseudonymized again.
func TestRedactIsIdempotent(t *testing.T) {
	once := mustRedact(t, localReport(t))
	twice := mustRedact(t, once)

	if encode(t, once) != encode(t, twice) {
		t.Errorf("a second redaction changed the report:\n%s\n%s", encode(t, once), encode(t, twice))
	}
	if strings.Contains(encode(t, twice), "host-002") &&
		!strings.Contains(encode(t, once), "host-002") {
		t.Error("pseudonyms were pseudonymized again")
	}

	thrice := mustRedact(t, twice)
	if encode(t, thrice) != encode(t, once) {
		t.Error("redaction is not stable after three applications")
	}
}

// --- fail closed -------------------------------------------------------------

func TestRedactRejectsZeroReport(t *testing.T) {
	out, err := Redact(domain.Report{})
	if !errors.Is(err, ErrRedaction) {
		t.Fatalf("err = %v, want ErrRedaction", err)
	}
	if !out.IsZero() {
		t.Error("a failed redaction must return no report")
	}
}

// TestErrorsRevealNoValues pins that failing safely does not leak what was being
// protected.
func TestErrorsRevealNoValues(t *testing.T) {
	_, err := Redact(domain.Report{})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, canary := range allCanaries {
		if strings.Contains(err.Error(), canary) {
			t.Errorf("the error leaked %q: %v", canary, err)
		}
	}
}

// --- boundaries --------------------------------------------------------------

// TestRedactionMakesNoDiagnosis pins that this is a structural transformation.
func TestRedactionMakesNoDiagnosis(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	if local.FindingCount() != shareable.FindingCount() {
		t.Errorf("finding count changed: %d -> %d", local.FindingCount(), shareable.FindingCount())
	}
	if local.Graph().Len() != shareable.Graph().Len() {
		t.Errorf("evidence count changed: %d -> %d", local.Graph().Len(), shareable.Graph().Len())
	}
}

// TestShareableModeCannotBeClaimedDirectly pins that the honesty guarantee from
// Phase 1.4b still holds: only a real transformation produces the mode.
func TestShareableModeCannotBeClaimedDirectly(t *testing.T) {
	_, err := domain.NewReportSecurity(domain.OutputModeShareableRedacted, false, false)
	if !errors.Is(err, domain.ErrInvalidValue) {
		t.Fatalf("the ordinary constructor should still refuse the mode, got %v", err)
	}

	// And the derivation refuses a source that is not a local report.
	shareable := mustRedact(t, localReport(t))
	if _, err := domain.NewShareableReportSecurity(shareable.Security(), domain.RedactionCounts{}); err == nil {
		t.Error("deriving shareable metadata from shareable metadata should fail")
	}
}

// TestDeclaredHostAttributesAreAlwaysRedacted covers the gap the TLS probe
// found. A bare hostname in a plain string attribute cannot be recognized by
// shape — "broker.internal" and "TLS1.3" look the same — so a producer declares
// identity through the value's kind instead, and a declared value is replaced
// whatever it looks like and wherever it appears. See ADR 0022.
func TestDeclaredHostAttributesAreAlwaysRedacted(t *testing.T) {
	const (
		bareName = "cert-canary.internal"
		version  = "TLS1.3"
	)

	shareable := mustRedact(t, reportWithHostAttributes(t, map[domain.AttributeKey]domain.AttrValue{
		"tls.server_name":    domain.HostAttr(bareName),
		"tls.peer_dns_names": domain.HostListAttr(bareName, "alt-canary.internal"),
		"tls.version":        domain.StringAttr(version),
	}))
	encoded, err := shareable.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	for _, canary := range []string{bareName, "alt-canary.internal"} {
		if strings.Contains(string(encoded), canary) {
			t.Errorf("a declared host attribute leaked %q:\n%s", canary, encoded)
		}
	}

	node := shareable.Graph().Nodes()[0]

	name, ok := node.Attribute("tls.server_name")
	if !ok {
		t.Fatal("tls.server_name disappeared")
	}
	if host, isHost := name.Host(); !isHost || !strings.HasPrefix(host, "host-") {
		t.Errorf("tls.server_name = %q (kind %s), want a host pseudonym", host, name.Kind())
	}

	// A non-identifying value must survive intact, or a shareable report stops
	// being worth sharing.
	kept, ok := node.Attribute("tls.version")
	if !ok {
		t.Fatal("tls.version disappeared")
	}
	if got, _ := kept.Str(); got != version {
		t.Errorf("tls.version = %q, want %q untouched", got, version)
	}
}

// TestDeclaredHostAttributesCorrelate checks that the same name in two
// attributes maps to one pseudonym, which is what lets a reader see that the
// certificate carries the name that was asked for.
func TestDeclaredHostAttributesCorrelate(t *testing.T) {
	const name = "shared-canary.internal"

	node := mustRedact(t, reportWithHostAttributes(t, map[domain.AttributeKey]domain.AttrValue{
		"tls.server_name":    domain.HostAttr(name),
		"tls.peer_dns_names": domain.HostListAttr(name),
	})).Graph().Nodes()[0]

	serverName, _ := mustAttribute(t, node, "tls.server_name").Host()
	names, _ := mustAttribute(t, node, "tls.peer_dns_names").HostList()

	if len(names) != 1 {
		t.Fatalf("peer names = %v, want one entry", names)
	}
	if serverName != names[0] {
		t.Errorf("the same name became %q and %q: correlation was lost", serverName, names[0])
	}
}

func mustAttribute(t *testing.T, e domain.Evidence, key domain.AttributeKey) domain.AttrValue {
	t.Helper()

	v, ok := e.Attribute(key)
	if !ok {
		t.Fatalf("attribute %s is missing", key)
	}
	return v
}

// reportWithHostAttributes builds a minimal local report whose single node
// carries the given attributes and nothing else identifying, so that a leak can
// only come from the attributes themselves.
func reportWithHostAttributes(t *testing.T, attrs map[domain.AttributeKey]domain.AttrValue) domain.Report {
	t.Helper()

	evidence := mustEvidence(t, nodeSpec{
		id:    "tls.handshake/endpoint/10.0.0.1",
		ref:   "10.0.0.1:9092",
		layer: domain.LayerTLS,
		step:  "tls.handshake",
		state: domain.StatePass,
		attrs: attrs,
	})

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	run, err := domain.NewRunMetadata("0.1.0", testStart, time.Second, "example")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("10.0.0.1:9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("runner.local")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: graph, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}
