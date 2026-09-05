package postgres

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 10.3, level L4: the PostgreSQL rules against arbitrary graphs.
//
// The unit tests drive the shapes a PostgreSQL run produces. This drives the
// shapes it does not: an arbitrary number of addresses in arbitrary states, two
// session nodes, a startup node with no parent, hostile SQLSTATE strings, hostile
// session parameters, and every failure class at every step. A graph is built
// from a server's answers and a server is not obliged to be reasonable.
//
// The properties asserted are the ones that must hold on any input at all.

// FuzzPostgresRules drives the whole PostgreSQL rule set over a generated graph.
//
// The seed corpus covers the shapes the unit tests name, so a regression in one
// of them is caught by `go test` and not only by a fuzzing run.
func FuzzPostgresRules(f *testing.F) {
	f.Add([]byte{}, "53300", "off", false)
	f.Add([]byte{0}, "53300", "on", false)
	f.Add([]byte{1, 2}, "28000", "off", false)
	f.Add([]byte{2, 2, 2}, "08P01", "", true)
	f.Add([]byte{1, 1, 1, 1, 1}, "3D000", "on", false)
	f.Add([]byte{3, 4, 5, 6}, "42501", "off", true)
	f.Add([]byte{7, 8, 9, 0, 1, 2}, "", "\n\r\t", false)
	f.Add([]byte{1, 2, 3}, strings.Repeat("5", 200), strings.Repeat("o", 200), true)
	f.Add([]byte{5, 5}, "53300\x00", "on\x00", false)
	// The two-address contrast and the uniform refusal, which are the shapes the
	// admission scope's two complete sentences come from.
	f.Add([]byte{1, 0}, "28000", "off", false)
	f.Add([]byte{1, 1}, "28000", "off", false)

	f.Fuzz(func(t *testing.T, shape []byte, sqlState, recovery string, incomplete bool) {
		g, built := fuzzPostgresGraph(t, shape, sqlState, recovery)
		if !built {
			return
		}
		ctx := diagnosis.RuleContext{Graph: g, Incomplete: incomplete}

		var findings []domain.Finding
		for _, rule := range []diagnosis.Rule{
			SSLRequest, TLS, Startup, Authentication, Session, AdmissionScope,
		} {
			findings = append(findings, rule(ctx)...)
		}

		assertPostgresFindingsAreWellFormed(t, g, findings)
		assertPostgresProseIsInert(t, findings, sqlState, recovery)
		assertPostgresCompletenessIsHonest(t, findings, incomplete)
		assertPostgresDeterminism(t, ctx, findings)
	})
}

// fuzzPostgresGraph turns a byte string into a run with that many addresses.
//
// Each byte's low nibble selects one address's journey from a table that
// deliberately includes graphs no producer makes: a session with no
// authentication parent, two sessions, a startup node whose parent is the
// anchor, and every non-passing state at every step.
//
// It returns false when the generated graph could not be frozen, which is not a
// finding about the rules.
func fuzzPostgresGraph(
	t *testing.T, shape []byte, sqlState, recovery string,
) (domain.Graph, bool) {
	t.Helper()

	// Bound the work so a fuzzer cannot turn this into a memory test. The
	// performance suite is where scaling is measured.
	if len(shape) > 48 {
		shape = shape[:48]
	}

	b := domain.NewGraphBuilder()
	anchorSubject, err := domain.NewTargetSubject("db.internal:5432")
	if err != nil {
		return domain.Graph{}, false
	}
	anchor, ok := fuzzPGNode(b, domain.EvidenceInput{
		ID: "pgfuzz-target", Subject: anchorSubject, Layer: domain.LayerInput,
		Step: vocabulary.StepTargetRequested, State: domain.StatePass,
		FailureClass: domain.FailureNone, Elapsed: domain.Unmeasured(),
	}, "")
	if !ok {
		return domain.Graph{}, false
	}

	for i, code := range shape {
		fuzzPGPath(b, anchor, i, int(code), sqlState, recovery)
	}

	g, err := b.Freeze()
	if err != nil {
		return domain.Graph{}, false
	}
	return g, true
}

// fuzzPGPath records one address's journey.
func fuzzPGPath(
	b *domain.GraphBuilder, anchor domain.EvidenceID,
	index, code int, sqlState, recovery string,
) {
	address := fmt.Sprintf("10.%d.%d.%d:5432", index/256, index%256, code%256)
	subject, err := domain.NewEndpointSubject(address)
	if err != nil {
		return
	}

	states := []domain.State{
		domain.StatePass, domain.StateFail, domain.StateUnknown,
		domain.StateSkipped, domain.StateDegraded,
	}
	classes := []domain.FailureClass{
		domain.FailureNone, domain.FailureAuthzNotPermitted,
		domain.FailureProtocolUnexpectedResponse, domain.FailureExecLocalTimeout,
		domain.FailureResourceLimitReached, domain.FailureResourceNotFound,
		domain.FailureAuthzDenied, domain.FailureAuthCredentialsRejected,
		domain.FailureExecSkippedByPolicy, domain.FailureExecRequiredInputMissing,
	}

	parent := string(anchor)
	steps := []struct {
		step  domain.Step
		layer domain.Layer
	}{
		{servicepostgres.StepSSLRequest, domain.LayerTLS},
		{vocabulary.StepTLSHandshake, domain.LayerTLS},
		{servicepostgres.StepStartup, domain.LayerProtocol},
		{servicepostgres.StepAuthentication, domain.LayerAuth},
		{servicepostgres.StepSession, domain.LayerAuth},
		// A second session node on one path, which no producer emits and every
		// rule must tolerate.
		{servicepostgres.StepSession, domain.LayerAuth},
	}

	for stage, s := range steps {
		state := states[(code+stage)%len(states)]
		class := classes[(code*3+stage)%len(classes)]
		attrs := map[domain.AttributeKey]domain.AttrValue{}
		if sqlState != "" {
			attrs[servicepostgres.AttrSQLState] = domain.StringAttr(sqlState)
		}
		attrs[servicepostgres.AttrErrorIsNative] = domain.BoolAttr(code%2 == 0)
		switch s.step {
		case servicepostgres.StepStartup:
			attrs[servicepostgres.AttrAuthMethod] = domain.StringAttr(
				[]string{"sasl", "ok", "md5", "unknown", ""}[code%5])
		case servicepostgres.StepSession:
			if recovery != "" {
				attrs[servicepostgres.AttrInHotStandby] = domain.StringAttr(recovery)
			}
			attrs[servicepostgres.AttrServerVersion] = domain.StringAttr(recovery)
		case servicepostgres.StepSSLRequest:
			attrs[servicepostgres.AttrSSLOffered] = domain.BoolAttr(code%3 == 0)
		}

		id := fmt.Sprintf("pgfuzz-%d-%d-%s", index, stage, s.step)
		// Every fifth path detaches its chain from the one above, which produces
		// the malformed anchors the rules must withhold on rather than guess at.
		attach := parent
		if code%5 == 4 && stage > 0 {
			attach = string(anchor)
		}
		node, ok := fuzzPGNode(b, domain.EvidenceInput{
			ID: domain.EvidenceID(id), Subject: subject, Layer: s.layer, Step: s.step,
			State: state, FailureClass: class, Attributes: attrs,
		}, attach)
		if !ok {
			continue
		}
		parent = string(node)
	}
}

// fuzzPGNode records one node, tolerating a rejection.
func fuzzPGNode(
	b *domain.GraphBuilder, in domain.EvidenceInput, parent string,
) (domain.EvidenceID, bool) {
	if in.StartedAt.IsZero() {
		in.StartedAt = fuzzInstant
	}
	if !in.Elapsed.IsMeasured() &&
		in.State != domain.StateSkipped && in.State != domain.StateUnknown {
		in.Elapsed = domain.Measured(1)
	}
	evidence, err := domain.NewEvidence(in)
	if err != nil {
		return "", false
	}
	if err := b.AddEvidence(evidence); err != nil {
		return "", false
	}
	if parent != "" {
		if err := b.AddParent(evidence.ID(), domain.EvidenceID(parent)); err != nil {
			return evidence.ID(), true
		}
	}
	return evidence.ID(), true
}

// assertPostgresFindingsAreWellFormed is the structural half.
func assertPostgresFindingsAreWellFormed(
	t *testing.T, g domain.Graph, findings []domain.Finding,
) {
	t.Helper()

	authorized := map[domain.FindingCode]bool{}
	for _, code := range allCodes() {
		authorized[code] = true
	}
	for _, code := range []domain.FindingCode{
		CodeTLSDeclined, CodeSSLNegotiationFailed, CodeCredentialNotConfigured,
		CodeTLSUpgradeNotHonored, CodeTLSIdentityMismatch, CodeTLSChainNotTrusted,
		CodeTLSCertificateNotValidNow, CodeTLSHandshakeFailed,
	} {
		authorized[code] = true
	}

	for _, f := range findings {
		if f.IsZero() {
			t.Fatal("a rule produced a zero finding")
		}
		if !authorized[f.Code()] {
			t.Errorf("a rule produced the unauthorized code %s", f.Code())
		}
		if f.Subject().IsZero() {
			t.Errorf("%s carries no subject", f.Code())
		}
		for _, ref := range f.EvidenceRefs() {
			if _, ok := g.Node(ref); !ok {
				t.Errorf("%s cites %q, which is not in the graph", f.Code(), ref)
			}
		}
		if len(f.EvidenceRefs()) == 0 {
			t.Errorf("%s rests on nothing", f.Code())
		}
		// The ceiling: a hypothesis may be HIGH only on direct peer authority,
		// and this package produces no hypothesis at all.
		if f.Kind() == domain.FindingKindHypothesis {
			t.Errorf("%s is a HYPOTHESIS; every PostgreSQL claim is directly evidenced "+
				"and narrow rather than hedged", f.Code())
		}
		for _, rec := range f.Recommendations() {
			if err := diagnosis.ValidateActionText(rec.Action()); err != nil {
				t.Errorf("%s carries unsafe advice %q: %v", f.Code(), rec.Action(), err)
			}
		}
	}
}

// assertPostgresProseIsInert is ADR 0081 section 2.7 over generated input.
//
// The SQLSTATE reaches a *detail* verbatim, deliberately and by contract, which
// is why it is excluded below and pinned separately by
// TestPGP13bTheSQLStateDetailIsTheOneVerbatimField. Nothing else a peer chose
// may reach any prose at all.
func assertPostgresProseIsInert(
	t *testing.T, findings []domain.Finding, sqlState, recovery string,
) {
	t.Helper()

	for _, f := range findings {
		surfaces := map[string]string{
			"summary":       f.Summary(),
			"discriminator": f.Discriminator(),
		}
		for i, rec := range f.Recommendations() {
			surfaces[fmt.Sprintf("recommendation %d", i)] = rec.Action()
		}
		surfaces["detail"] = f.Detail()

		for name, text := range surfaces {
			if recovery != "" && len(recovery) > 3 && strings.Contains(text, recovery) {
				t.Errorf("%s's %s contains the session parameter %q", f.Code(), name, recovery)
			}
			if name == "detail" {
				continue // the SQLSTATE's one authorized verbatim home.
			}
			if sqlState != "" && len(sqlState) > 3 && strings.Contains(text, sqlState) {
				t.Errorf("%s's %s contains the peer's SQLSTATE %q", f.Code(), name, sqlState)
			}
		}
	}
}

// assertPostgresCompletenessIsHonest is the RAB18 lesson over generated input.
//
// An interrupted run establishes no total, so no exclusive phrasing may appear.
func assertPostgresCompletenessIsHonest(
	t *testing.T, findings []domain.Finding, incomplete bool,
) {
	t.Helper()

	if !incomplete {
		return
	}
	for _, f := range findings {
		if f.Code() != CodeAdmissionScope {
			continue
		}
		for _, exclusive := range []string{"at all ", "whole set"} {
			if strings.Contains(f.Summary()+f.Detail(), exclusive) {
				t.Errorf("an interrupted run claimed %q:\n%s\n%s",
					exclusive, f.Summary(), f.Detail())
			}
		}
	}
}

// assertPostgresDeterminism drives the same context twice.
func assertPostgresDeterminism(
	t *testing.T, ctx diagnosis.RuleContext, first []domain.Finding,
) {
	t.Helper()

	var second []domain.Finding
	for _, rule := range []diagnosis.Rule{
		AdmissionScope, Session, Authentication, Startup, TLS, SSLRequest,
	} {
		second = append(second, rule(ctx)...)
	}
	if len(first) != len(second) {
		t.Fatalf("wiring order changed the finding count: %d then %d", len(first), len(second))
	}
	domain.SortFindings(first)
	domain.SortFindings(second)
	for i := range first {
		if first[i].Summary() != second[i].Summary() ||
			first[i].Code() != second[i].Code() ||
			first[i].Subject() != second[i].Subject() {
			t.Errorf("the same graph produced two different findings at position %d", i)
		}
	}
}

// fuzzInstant is the fixed start every generated node carries. A rule must never
// consult the clock, so a fuzz corpus that varied time would be testing nothing.
var fuzzInstant = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
