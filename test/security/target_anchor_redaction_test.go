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

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
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

// --- generic transport findings (ADR 0043) -------------------------------------

// TestAGenericFindingRedactsWithItsSubject is the ADR 0043 redaction proof.
//
// The generic findings are the first whose subject is the operator's logical
// endpoint rather than a service fact, and the first that appear in a report
// where the same endpoint is also the report target and an evidence subject.
// All three must pseudonymize to one value, or a shared report shows one endpoint
// as three.
//
// The run refuses every address, so the TCP finding fires against real evidence
// from the production composition.
func TestAGenericFindingRedactsWithItsSubject(t *testing.T) {
	local := anchorRun(t)

	// Phase 10.1b added the generic failure boundary to every composition, so
	// the run now carries one boundary per failing subject alongside the claim
	// this test is about. Selecting by code keeps the test about what it says it
	// is about; TestTheFailureBoundaryRedactsWithItsSubject covers the others.
	findings := findingsWithCode(t, local.Findings(), "TCP_CONNECTION_NOT_ESTABLISHED")
	if len(findings) != 1 {
		t.Fatalf("got %d generic TCP findings, want 1: %v", len(findings), findings)
	}

	// Non-vacuity: locally, all three carry the real endpoint.
	want := anchorCanaryHost + ":5432"
	if got := findings[0].Subject().Ref(); got != want {
		t.Fatalf("finding subject = %q, want %q", got, want)
	}
	if got := local.Target().Requested(); got != want {
		t.Fatalf("report target = %q, want %q", got, want)
	}
	if got := anchorSubject(t, local); got != want {
		t.Fatalf("anchor subject = %q, want %q", got, want)
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	shared := findingsWithCode(t, shareable.Findings(), "TCP_CONNECTION_NOT_ESTABLISHED")
	if len(shared) != 1 {
		t.Fatalf("redaction changed the finding count to %d", len(shared))
	}

	findingRef := shared[0].Subject().Ref()
	targetRef := shareable.Target().Requested()
	anchorRef := anchorSubject(t, shareable)

	if strings.Contains(findingRef, anchorCanaryHost) {
		t.Errorf("the shareable finding subject %q still names the host", findingRef)
	}
	if findingRef != targetRef || findingRef != anchorRef {
		t.Errorf("one endpoint got several pseudonyms: finding %q, target %q, anchor %q",
			findingRef, targetRef, anchorRef)
	}

	// Every reference still resolves after identifiers were remapped wholesale.
	for _, ref := range shared[0].EvidenceRefs() {
		if _, ok := shareable.Graph().Node(ref); !ok {
			t.Errorf("evidence ref %s does not resolve in the redacted graph", ref)
		}
	}
	if got, want := len(shared[0].EvidenceRefs()), len(findings[0].EvidenceRefs()); got != want {
		t.Errorf("redaction changed the reference count from %d to %d", want, got)
	}
}

// TestGenericFindingProseCarriesNoIdentity pins that the sentences are safe.
//
// Structural redaction transforms subjects, attributes and identifiers. It cannot
// rewrite prose, so a finding whose summary named a host would leak on the day
// somebody shared a report — which is why docs/FINDINGS.md requires the prose to
// carry no identity that structure already carries.
func TestGenericFindingProseCarriesNoIdentity(t *testing.T) {
	local := anchorRun(t)
	if len(local.Findings()) == 0 {
		t.Fatal("the run produced no finding; the scan would be vacuous")
	}

	for _, f := range local.Findings() {
		text := f.Summary() + " " + f.Detail()
		for _, r := range f.Recommendations() {
			text += " " + r.Action()
		}
		for _, canary := range []string{anchorCanaryHost, anchorCanaryV4, anchorCanaryV6} {
			if strings.Contains(text, canary) {
				t.Errorf("%s prose contains %q", f.Code(), canary)
			}
		}
	}
}

// --- PostgreSQL in-band TLS findings (ADR 0044) --------------------------------

// tlsCanaryDialer answers the SSLRequest with 'S' and then speaks something that
// is not a TLS record, which fails the in-band handshake with TLS_PEER_NOT_TLS.
type tlsCanaryDialer struct{}

func (tlsCanaryDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		request := make([]byte, 8)
		if _, err := server.Read(request); err != nil {
			return
		}
		if _, err := server.Write([]byte{'S'}); err != nil {
			return
		}
		hello := make([]byte, 4096)
		if _, err := server.Read(hello); err != nil {
			return
		}
		_, _ = server.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()
	return client, nil
}

// tlsCanaryRun produces a real LOCAL_FULL report whose in-band handshake failed.
func tlsCanaryRun(t *testing.T) domain.Report {
	t.Helper()

	vantage, err := domain.NewLocalVantage("anchor-runner-canary.local")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	result, err := app.DiagnosePostgres(context.Background(), app.PostgresParams{
		Host: anchorCanaryHost, Port: anchorCanaryPort,
		// A role that shares no substring with any word this repository puts in
		// finding prose. See TestAToolWordAsARoleNameFailsClosed for why that
		// matters and why the behaviour is correct.
		Role:     "tenantrolecanary",
		Resolver: anchorResolver{}, Dialer: tlsCanaryDialer{},
		StepTimeout: 5 * time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-security",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	return result.Report()
}

// TestAPostgresTLSFindingRedactsWithItsEndpoint is the ADR 0044 redaction proof.
//
// The finding's subject is a concrete `ip:port` rather than the logical target,
// so it exercises a different redaction path from the generic transport findings
// — and it must land on the same pseudonym as the evidence nodes describing that
// same address, or a shared report shows one endpoint as several.
func TestAPostgresTLSFindingRedactsWithItsEndpoint(t *testing.T) {
	local := tlsCanaryRun(t)

	// The canary name resolves to two addresses and both handshakes fail, so
	// there are **two** findings — one per endpoint. That is ADR 0044's
	// endpoint scope working: a PostgreSQL finding claims something about the
	// address that presented the certificate, so a second failing address is a
	// second claim rather than the same one restated.
	findings := findingsWithCode(t, local.Findings(), "POSTGRES_TLS_UPGRADE_NOT_HONORED")
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want one per failing endpoint: %v", len(findings), findings)
	}
	localSubjects := map[string]bool{}
	for _, f := range findings {
		localSubjects[f.Subject().Ref()] = true
	}
	if len(localSubjects) != 2 {
		t.Fatalf("the two findings share a subject %v; each is about its own endpoint",
			localSubjects)
	}
	// Non-vacuity: locally the subjects name the real resolved addresses.
	for subject := range localSubjects {
		if !strings.Contains(subject, anchorCanaryV4) && !strings.Contains(subject, anchorCanaryV6) {
			t.Fatalf("local subject %q names neither canary address", subject)
		}
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	shared := findingsWithCode(t, shareable.Findings(), "POSTGRES_TLS_UPGRADE_NOT_HONORED")
	if len(shared) != len(findings) {
		t.Fatalf("redaction changed the finding count to %d", len(shared))
	}

	sharedSubjects := map[string]bool{}
	for _, f := range shared {
		subject := f.Subject().Ref()
		sharedSubjects[subject] = true

		for _, canary := range []string{anchorCanaryV4, anchorCanaryV6, anchorCanaryHost} {
			if strings.Contains(subject, canary) {
				t.Errorf("the shareable subject %q still names %q", subject, canary)
			}
		}

		// The cited evidence describes the same endpoint, so it must carry the
		// same pseudonym — that correlation is the point of structural redaction.
		if len(f.EvidenceRefs()) != 2 {
			t.Fatalf("got %d refs, want the negotiation and the handshake",
				len(f.EvidenceRefs()))
		}
		for _, ref := range f.EvidenceRefs() {
			node, ok := shareable.Graph().Node(ref)
			if !ok {
				t.Fatalf("evidence ref %s does not resolve in the redacted graph", ref)
			}
			if node.Subject().Ref() != subject {
				t.Errorf("finding subject %q and evidence subject %q disagree after redaction",
					subject, node.Subject().Ref())
			}
		}
	}

	// Two endpoints stay two endpoints: redaction removes identity, never
	// distinctions.
	if len(sharedSubjects) != 2 {
		t.Errorf("two endpoints collapsed into %v after redaction", sharedSubjects)
	}

	// Every semantic field survives the transformation unchanged.
	before, after := findings[0], shared[0]
	if before.Code() != after.Code() || before.Kind() != after.Kind() ||
		before.Severity() != after.Severity() || before.Confidence() != after.Confidence() ||
		before.VantageDependent() != after.VantageDependent() {
		t.Error("redaction changed a semantic field of the finding")
	}
}

// TestPostgresTLSFindingCarriesNoCertificateMaterial pins what may not reach a
// report.
//
// Certificate names, the requested identity and the validity window are
// structured attributes on the evidence node, where redaction transforms them.
// None may appear in prose, and no raw TLS library error may either — the probe
// discards that text precisely because it can name hosts in a form structural
// redaction cannot recognize.
func TestPostgresTLSFindingCarriesNoCertificateMaterial(t *testing.T) {
	local := tlsCanaryRun(t)
	if len(local.Findings()) == 0 {
		t.Fatal("the run produced no finding; the scan would be vacuous")
	}

	for _, f := range local.Findings() {
		text := f.Summary() + " " + f.Detail()
		for _, r := range f.Recommendations() {
			text += " " + r.Action()
		}
		for _, leak := range []string{
			anchorCanaryHost, anchorCanaryV4, anchorCanaryV6,
			"x509", "tls:", "certificate is valid for", "-----BEGIN",
		} {
			if strings.Contains(text, leak) {
				t.Errorf("%s prose contains %q", f.Code(), leak)
			}
		}
	}
}

// TestAToolWordAsARoleNameFailsClosed pins a sharp edge found while writing the
// test above, and pins that its behaviour is the safe one.
//
// The residual scan is a substring search for every collected identity. Finding
// prose in this repository says "svcdoctor" — `POSTGRES_TLS_DECLINED` has said so
// since Phase 4.6b — so a run whose PostgreSQL **role** is literally `svcdoctor`
// produces a report where the role's plaintext appears in a sentence that was
// never about the role.
//
// Redaction then refuses to produce a shareable report at all. That is correct:
// the scan cannot know the occurrence is coincidental, and ADR 0018's rule is to
// fail closed. Refusing to share is a smaller harm than sharing a report that
// claims an identity was removed when its plaintext is still present.
//
// This is not introduced by ADR 0044 and is not a defect in any finding. It is
// recorded so that the next person to meet it recognizes it in seconds instead of
// suspecting the new rule, and so that "fix" does not become "make the scan
// cleverer" without a decision.
func TestAToolWordAsARoleNameFailsClosed(t *testing.T) {
	vantage, err := domain.NewLocalVantage("anchor-runner-canary.local")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	result, err := app.DiagnosePostgres(context.Background(), app.PostgresParams{
		Host: anchorCanaryHost, Port: anchorCanaryPort,
		Role:     "svcdoctor", // collides with the word used in finding prose
		Resolver: anchorResolver{}, Dialer: tlsCanaryDialer{},
		StepTimeout: 5 * time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-security",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}

	// The local report is produced normally: nothing about the run failed.
	if len(result.Report().Findings()) == 0 {
		t.Fatal("the run produced no finding; the case is not reproduced")
	}

	// Redaction refuses rather than emitting a report whose promise is false.
	if _, err := redaction.Redact(result.Report()); err == nil {
		t.Error("Redact succeeded; a collected identity's plaintext is present in the " +
			"output and the residual scan must refuse")
	}
}

// --- ADR 0046: a run with nothing to present -----------------------------------

// noCredentialDialer answers a StartupMessage by demanding SCRAM.
type noCredentialDialer struct{}

func (noCredentialDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		startup := make([]byte, 4096)
		if _, err := server.Read(startup); err != nil {
			return
		}
		_, _ = server.Write([]byte{
			'R', 0, 0, 0, 23, 0, 0, 0, 10,
			'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6', 0, 0,
		})
	}()
	return client, nil
}

// TestAMissingCredentialLeaksNothing is the ADR 0046 security proof.
//
// This is the one finding in the repository whose subject is *the absence of a
// secret*, which makes it the one most likely to describe the secret it does not
// have. Nothing about the credential may reach evidence, prose or the report —
// not its length, not that it was empty, not that one was looked for.
func TestAMissingCredentialLeaksNothing(t *testing.T) {
	vantage, err := domain.NewLocalVantage("anchor-runner-canary.local")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	result, err := app.DiagnosePostgres(context.Background(), app.PostgresParams{
		Host: anchorCanaryHost, Port: anchorCanaryPort,
		Role:     "tenantrolecanary",
		Resolver: anchorResolver{}, Dialer: noCredentialDialer{},
		TLS:         postgres.TLSDisabled,
		StepTimeout: 5 * time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-security",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	local := result.Report()

	findings := local.Findings()
	if len(findings) == 0 {
		t.Fatal("no finding was produced; the scan would be vacuous")
	}
	var subject string
	for _, f := range findings {
		if f.Code() != "POSTGRES_CREDENTIAL_NOT_CONFIGURED" {
			continue
		}
		subject = f.Subject().Ref()

		text := f.Summary() + " " + f.Detail()
		for _, r := range f.Recommendations() {
			text += " " + r.Action()
		}
		for _, leak := range []string{
			anchorCanaryHost, anchorCanaryV4, anchorCanaryV6,
			"tenantrolecanary", "empty", "zero-length", "blank",
		} {
			if strings.Contains(text, leak) {
				t.Errorf("prose contains %q", leak)
			}
		}
	}
	if subject == "" {
		t.Fatal("the missing-credential finding was not produced")
	}

	// The authentication node describes no credential at all.
	for _, n := range local.Graph().Nodes() {
		if n.Step() != "postgres.authentication" {
			continue
		}
		if got := n.AttributeCount(); got != 0 {
			t.Errorf("the authentication node carries %d attributes, want 0", got)
		}
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	for _, f := range shareable.Findings() {
		if f.Code() != "POSTGRES_CREDENTIAL_NOT_CONFIGURED" {
			continue
		}
		if strings.Contains(f.Subject().Ref(), anchorCanaryHost) ||
			strings.Contains(f.Subject().Ref(), anchorCanaryV4) {
			t.Errorf("the shareable subject %q still names the endpoint", f.Subject().Ref())
		}
		for _, ref := range f.EvidenceRefs() {
			if _, ok := shareable.Graph().Node(ref); !ok {
				t.Errorf("evidence ref %s does not resolve after redaction", ref)
			}
		}
	}

	// Non-vacuity: the role really is in the local document, and gone from the
	// shareable one.
	localJSON, err := json.Marshal(local)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !strings.Contains(string(localJSON), "tenantrolecanary") {
		t.Fatal("the role is not in the local report; the scan below is vacuous")
	}
	shareableJSON, err := json.Marshal(shareable)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(shareableJSON), "tenantrolecanary") {
		t.Error("the role survived redaction")
	}
}

// findingsWithCode selects the findings this file's assertions are about.
//
// Phase 10.1b activated the generic failure boundary, which fires on every
// failing subject in every composition. These tests are about one service claim
// each, and a count over the whole array would now be counting the boundary too.
func findingsWithCode(
	t *testing.T, findings []domain.Finding, code domain.FindingCode,
) []domain.Finding {
	t.Helper()

	var out []domain.Finding
	for _, f := range findings {
		if f.Code() == code {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s finding was produced at all; the assertion below would be vacuous", code)
	}
	return out
}

// TestTheFailureBoundaryRedactsWithItsSubject is the Phase 10.1B addition to the
// shareable corpus.
//
// The boundary became public in Phase 10.1B and it carries a subject, which for
// a transport failure is a resolved address. That is exactly the identity the
// shareable projection exists to remove, and it must be removed by the existing
// structural redaction rather than by anything the new finding brought with it.
//
// The pseudonym must also be the *same* one every other reference to that
// endpoint got: one endpoint, one pseudonym, or correlation is lost and the
// shareable report stops being readable.
func TestTheFailureBoundaryRedactsWithItsSubject(t *testing.T) {
	local := anchorRun(t)

	boundaries := findingsWithCode(t, local.Findings(), diagnosis.CodeFailureBoundary)
	if len(boundaries) == 0 {
		t.Fatal("the run produced no boundary; this assertion would be vacuous")
	}

	// Non-vacuity: locally every boundary names the real endpoint.
	for _, b := range boundaries {
		if !strings.Contains(b.Subject().Ref(), anchorCanaryHost) &&
			!strings.Contains(b.Subject().Ref(), anchorCanaryV4) &&
			!strings.Contains(b.Subject().Ref(), anchorCanaryV6) {
			t.Fatalf("the local boundary subject %q names no canary, so redacting it "+
				"would prove nothing", b.Subject().Ref())
		}
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	shared := findingsWithCode(t, shareable.Findings(), diagnosis.CodeFailureBoundary)
	if len(shared) != len(boundaries) {
		t.Fatalf("redaction changed the boundary count from %d to %d",
			len(boundaries), len(shared))
	}

	for _, b := range shared {
		subject := b.Subject().Ref()
		for _, canary := range []string{anchorCanaryHost, anchorCanaryV4, anchorCanaryV6} {
			if strings.Contains(subject, canary) {
				t.Errorf("the shareable boundary subject %q still names %q", subject, canary)
			}
		}

		// The prose is rule-owned and carries no identity of its own, so it must
		// survive redaction unchanged and must name nothing.
		for _, text := range []string{b.Summary(), b.Detail()} {
			for _, canary := range []string{anchorCanaryHost, anchorCanaryV4, anchorCanaryV6} {
				if strings.Contains(text, canary) {
					t.Errorf("the boundary prose names %q: %q", canary, text)
				}
			}
		}

		// Every citation still resolves after identifiers were remapped wholesale.
		for _, ref := range b.EvidenceRefs() {
			if _, ok := shareable.Graph().Node(ref); !ok {
				t.Errorf("the shareable boundary cites %q, which no longer resolves", ref)
			}
		}
	}

	// Correlation survives: the mapping from a real subject to its pseudonym is a
	// bijection across the whole findings array.
	//
	// This run legitimately has three subjects — the logical target the generic
	// TCP finding is about, and one resolved address per boundary, because a
	// boundary is per subject (ADR 0079 section 2.2). What must hold is that each
	// one keeps exactly one pseudonym and no two share one, or a reader of the
	// shareable report can no longer tell the endpoints apart.
	localToShared := map[string]string{}
	sharedToLocal := map[string]string{}
	for i, f := range local.Findings() {
		realRef := f.Subject().Ref()
		sharedRef := shareable.Findings()[i].Subject().Ref()

		if existing, seen := localToShared[realRef]; seen && existing != sharedRef {
			t.Errorf("subject %q got two pseudonyms: %q and %q", realRef, existing, sharedRef)
		}
		if existing, seen := sharedToLocal[sharedRef]; seen && existing != realRef {
			t.Errorf("pseudonym %q covers two subjects: %q and %q",
				sharedRef, existing, realRef)
		}
		localToShared[realRef] = sharedRef
		sharedToLocal[sharedRef] = realRef
	}
	if len(localToShared) < 2 {
		t.Errorf("only %d distinct subject was mapped; the bijection above would be "+
			"vacuous", len(localToShared))
	}
}
