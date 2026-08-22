package security

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The ADR 0042 redaction proof.
//
// The requested endpoint is now rendered twice in one report: on the envelope as
// `target.requested`, and in the graph as the anchor's subject. ADR 0042 section
// 14 claimed that needs no new redaction code, because both already flow through
// the same pseudonym table — and that both must therefore land on the *same*
// pseudonym, or a shareable report would show one endpoint as two.
//
// That claim was verified from the source when the record was written. This
// verifies it from a real report, which is a different and stronger thing.
//
// **Non-vacuity is the point.** A test that only asserted "the hostname is
// absent" would pass on an empty report. Every assertion here first proves the
// raw value was present locally.

const (
	anchorCanaryHost = "anchor-canary.prod.internal"
	anchorCanaryPort = 5432
	anchorCanaryV4   = "10.51.52.53"
	anchorCanaryV6   = "2001:db8::a1c0"
)

// anchorResolver answers with the canary addresses.
type anchorResolver struct{}

func (anchorResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{
		netip.MustParseAddr(anchorCanaryV6),
		netip.MustParseAddr(anchorCanaryV4),
	}, nil
}

// anchorDialer refuses, so the run stops at L2 and the report stays small.
type anchorDialer struct{}

func (anchorDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
}

// anchorRun produces a real LOCAL_FULL report from the production composition.
func anchorRun(t *testing.T) domain.Report {
	t.Helper()

	vantage, err := domain.NewLocalVantage("anchor-runner-canary.local")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	result, err := app.DiagnosePostgres(context.Background(), app.PostgresParams{
		Host: anchorCanaryHost, Port: anchorCanaryPort,
		Role:     "svcdoctor",
		Resolver: anchorResolver{}, Dialer: anchorDialer{},
		StepTimeout: time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-security",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	return result.Report()
}

// anchorSubject returns the requested-target node's subject reference.
func anchorSubject(t *testing.T, report domain.Report) string {
	t.Helper()

	var found []string
	for _, n := range report.Graph().Nodes() {
		if n.Step() == vocabulary.StepTargetRequested {
			found = append(found, n.Subject().Ref())
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d requested-target nodes, want 1", len(found))
	}
	return found[0]
}

// TestTheAnchorAndTheReportTargetShareOnePseudonym is the ADR 0042 section 14
// claim, measured.
func TestTheAnchorAndTheReportTargetShareOnePseudonym(t *testing.T) {
	local := anchorRun(t)

	// Non-vacuity: both raw copies exist locally, and they agree.
	localTarget := local.Target().Requested()
	localAnchor := anchorSubject(t, local)

	want := anchorCanaryHost + ":" + "5432"
	if localTarget != want {
		t.Fatalf("local report target = %q, want %q", localTarget, want)
	}
	if localAnchor != want {
		t.Fatalf("local anchor subject = %q, want %q", localAnchor, want)
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	sharedTarget := shareable.Target().Requested()
	sharedAnchor := anchorSubject(t, shareable)

	// The identity is gone.
	if strings.Contains(sharedTarget, anchorCanaryHost) {
		t.Errorf("shareable report target %q still names the host", sharedTarget)
	}
	if strings.Contains(sharedAnchor, anchorCanaryHost) {
		t.Errorf("shareable anchor subject %q still names the host", sharedAnchor)
	}

	// The correlation survives, which is the whole property.
	if sharedTarget != sharedAnchor {
		t.Fatalf("the two projections redacted differently: target %q, anchor %q; "+
			"a reader would see one endpoint as two", sharedTarget, sharedAnchor)
	}

	// The port is preserved, because it identifies nobody and a reader needs it.
	if !strings.HasSuffix(sharedTarget, ":5432") {
		t.Errorf("shareable target %q lost its port", sharedTarget)
	}
}

// TestNoCanaryIdentitySurvivesTheWholeReport is the residual check over the
// serialized document.
//
// The anchor added a node carrying a hostname to every graph. If any redaction
// path had missed it, the raw name would appear in the shareable JSON — which is
// the only form that actually leaves a machine.
func TestNoCanaryIdentitySurvivesTheWholeReport(t *testing.T) {
	local := anchorRun(t)

	localJSON, err := json.Marshal(local)
	if err != nil {
		t.Fatalf("marshalling the local report: %v", err)
	}
	// Non-vacuity: the canary is in the local document, more than once.
	if count := strings.Count(string(localJSON), anchorCanaryHost); count < 2 {
		t.Fatalf("the local report names the canary %d times, want at least 2 "+
			"(the envelope and the anchor); the scan would be vacuous", count)
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	shareableJSON, err := json.Marshal(shareable)
	if err != nil {
		t.Fatalf("marshalling the shareable report: %v", err)
	}

	for _, canary := range []string{anchorCanaryHost, anchorCanaryV4, anchorCanaryV6} {
		if strings.Contains(string(shareableJSON), canary) {
			t.Errorf("the shareable report still contains %q", canary)
		}
	}
}

// TestRedactingTheAnchorIsDeterministic pins the two stability properties a
// shared report depends on.
//
// **Idempotent over one report**: redacting the same facts twice produces the
// same document, byte for byte. A transformation that moved on each application
// would make a shared report unreproducible.
//
// **Stable across runs**: two independent runs of one target produce the same
// pseudonym for it. Numbering depends on the set of identifying values, not on
// the order they were discovered, so two people redacting reports of the same
// endpoint can talk about the same "host-001".
func TestRedactingTheAnchorIsDeterministic(t *testing.T) {
	local := anchorRun(t)

	first, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	second, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact again: %v", err)
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Error("redacting one report twice produced different documents")
	}

	// Across two runs the timings differ, so only the pseudonyms are compared —
	// which is the property that actually matters.
	other, err := redaction.Redact(anchorRun(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if first.Target().Requested() != other.Target().Requested() {
		t.Errorf("the same endpoint got two pseudonyms across runs: %q and %q",
			first.Target().Requested(), other.Target().Requested())
	}
	if anchorSubject(t, first) != anchorSubject(t, other) {
		t.Errorf("the anchor got two pseudonyms across runs: %q and %q",
			anchorSubject(t, first), anchorSubject(t, other))
	}
}

// TestTheAnchorSurvivesRedactionAsANode pins that the node itself is preserved.
//
// Redaction removes identity, not evidence. An anchor that disappeared from a
// shareable report would take with it the one structural answer to "which sweep
// did the operator ask for" — so a shared report would be undiagnosable by the
// very rule the anchor exists to enable.
func TestTheAnchorSurvivesRedactionAsANode(t *testing.T) {
	local := anchorRun(t)
	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	if local.Graph().Len() != shareable.Graph().Len() {
		t.Errorf("node count changed: %d local, %d shareable",
			local.Graph().Len(), shareable.Graph().Len())
	}

	var anchor domain.Evidence
	for _, n := range shareable.Graph().Nodes() {
		if n.Step() == vocabulary.StepTargetRequested {
			anchor = n
		}
	}
	if anchor.IsZero() {
		t.Fatal("the shareable report has no requested-target node")
	}
	if got := anchor.Subject().Kind(); got != domain.SubjectKindTarget {
		t.Errorf("subject kind = %s after redaction, want %s", got, domain.SubjectKindTarget)
	}
	if got := anchor.Layer(); got != domain.LayerInput {
		t.Errorf("layer = %s after redaction, want %s", got, domain.LayerInput)
	}
	if got := anchor.State(); got != domain.StatePass {
		t.Errorf("state = %s after redaction, want PASS", got)
	}

	// The edge that carries ownership must survive identifier remapping, or a
	// shareable report would lose the sweep's declared cause.
	children := shareable.Graph().Children(anchor.ID())
	if len(children) != 1 {
		t.Fatalf("the redacted anchor has %d children, want 1", len(children))
	}
	child, ok := shareable.Graph().Node(children[0])
	if !ok {
		t.Fatalf("child %s is not in the redacted graph", children[0])
	}
	if child.Step() != vocabulary.StepDNSLookup {
		t.Errorf("the anchor's child is %s, want %s", child.Step(), vocabulary.StepDNSLookup)
	}
}
