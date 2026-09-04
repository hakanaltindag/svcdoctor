package redis

import (
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// The Redis rules' claim-discipline suite.
//
// Most of these tests assert what a finding does **not** say. That is the point:
// every rule here is one sentence away from a claim Redis cannot support, and the
// sentences are the deliverable. A test that only checked a finding code would
// pass against prose that said "wrong password".

func graphWith(t *testing.T, nodes ...domain.Evidence) domain.Graph {
	t.Helper()
	builder := domain.NewGraphBuilder()
	for _, node := range nodes {
		if err := builder.AddEvidence(node); err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return graph
}

// nodeOf builds one evidence node at a step with a state and class.
func nodeOf(
	t *testing.T,
	step domain.Step,
	state domain.State,
	class domain.FailureClass,
	attrs map[domain.AttributeKey]domain.AttrValue,
) domain.Evidence {
	t.Helper()
	subject, err := domain.NewEndpointSubject("10.0.0.1:6379")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID(string(step) + "/endpoint.internal:6379/10.0.0.1"),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         step,
		State:        state,
		FailureClass: class,
		Attributes:   attrs,
		StartedAt:    time.Unix(1700000000, 0).UTC(),
		Elapsed:      domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	return evidence
}

func prose(f domain.Finding) string {
	text := f.Summary() + " " + f.Detail()
	for _, r := range f.Recommendations() {
		text += " " + r.Action()
	}
	return strings.ToLower(text)
}

// neverSayable are phrases no Redis finding may contain under any circumstances.
//
// Each is a claim about something svcdoctor did not measure: the health of a
// service, of a cluster, of replication, of a primary it never contacted, or of
// an application whose commands it never issued.
var neverSayable = []string{
	"redis is healthy",
	"valkey is healthy",
	"cluster is healthy",
	"cluster healthy",
	"replication is healthy",
	"server is down",
	"primary is down",
	"data was lost",
	"disk is slow",
	"your application will work",
}

// causePhrases name one of the three conditions Redis merges into WRONGPASS.
//
// # Why these are conditional rather than banned
//
// A first draft of this suite banned them outright and immediately failed
// against the finding that is most careful about them. `-WRONGPASS invalid
// username-password pair or user is disabled.` is a single reply site
// (redis/src/acl.c:1511) covering an unknown user, a wrong password and a
// disabled user, and the honest thing for a finding to do is **say so** — naming
// all three, and saying svcdoctor cannot tell which.
//
// So the rule is not "never name a cause". It is "never name a cause without the
// disclaimer", which is a strictly stronger test: prose that asserts one of the
// three, or that names them without saying they are indistinguishable, fails
// here. Banning the words would have rewarded vagueness.
var causePhrases = []string{
	"wrong password",
	"incorrect password",
	"unknown user",
	"user does not exist",
	"disabled user",
}

// mergeDisclaimers are the ways a finding may say the causes are indistinguishable.
var mergeDisclaimers = []string{
	"cannot tell which",
	"does not guess",
}

// TestNoRedisFindingMakesAForbiddenClaim runs every rule over every shape that
// produces a finding and checks the prose.
func TestNoRedisFindingMakesAForbiddenClaim(t *testing.T) {
	for _, shape := range everyFindingShape(t) {
		for _, finding := range shape.findings {
			text := prose(finding)
			for _, phrase := range neverSayable {
				if strings.Contains(text, phrase) {
					t.Errorf("%s says %q.\n\n%s", finding.Code(), phrase, finding.Summary())
				}
			}

			named := ""
			for _, phrase := range causePhrases {
				if strings.Contains(text, phrase) {
					named = phrase
					break
				}
			}
			if named == "" {
				continue
			}
			disclaimed := false
			for _, disclaimer := range mergeDisclaimers {
				if strings.Contains(text, disclaimer) {
					disclaimed = true
					break
				}
			}
			if !disclaimed {
				t.Errorf("%s names the cause %q without saying svcdoctor cannot tell "+
					"which of the merged conditions occurred.\n\n%s",
					finding.Code(), named, finding.Detail())
			}
		}
	}
}

type shape struct {
	name     string
	findings []domain.Finding
}

// everyFindingShape drives all four rules over every input that produces a
// finding, so a new rule that forgets the claim discipline is caught by the
// tests above without anyone remembering to add it there.
func everyFindingShape(t *testing.T) []shape {
	t.Helper()
	mode := func(value string) map[domain.AttributeKey]domain.AttrValue {
		return map[domain.AttributeKey]domain.AttrValue{
			serviceredis.AttrMode: domain.StringAttr(value),
		}
	}
	prefix := func(value string) map[domain.AttributeKey]domain.AttrValue {
		return map[domain.AttributeKey]domain.AttrValue{
			serviceredis.AttrErrorPrefix: domain.StringAttr(value),
		}
	}

	return []shape{
		{"sentinel", Sentinel(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepHello, domain.StatePass, domain.FailureNone, mode("sentinel")))))},
		{"hello failed", Hello(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepHello, domain.StateFail, domain.FailureProtocolPeerClosed, nil))))},
		{"credentials rejected", Authentication(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepAuthentication, domain.StateFail,
			domain.FailureAuthCredentialsRejected, prefix("WRONGPASS")))))},
		{"auth not completed", Authentication(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepAuthentication, domain.StateFail,
			domain.FailureProtocolMalformedResponse, nil))))},
		{"credential withheld", Authentication(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepAuthentication, domain.StateSkipped,
			domain.FailureExecSkippedByPolicy, nil))))},
		{"credential not configured", Authentication(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepAuthentication, domain.StateSkipped,
			domain.FailureExecRequiredInputMissing, nil))))},
		{"noperm", Ping(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepPing, domain.StateUnknown,
			domain.FailureAuthzDenied, prefix("NOPERM")))))},
		{"loading", Ping(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepPing, domain.StateUnknown,
			domain.FailureProtocolUnexpectedResponse, prefix("LOADING")))))},
		{"masterdown", Ping(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepPing, domain.StateUnknown,
			domain.FailureProtocolUnexpectedResponse, prefix("MASTERDOWN")))))},
		{"ping not completed", Ping(rctx(graphWith(t, nodeOf(t,
			serviceredis.StepPing, domain.StateFail,
			domain.FailureProtocolPeerClosed, nil))))},
	}
}

// TestEveryAuthorizedShapeBuildsAValidFinding proves the build helper's error is
// unreachable rather than assumed.
func TestEveryAuthorizedShapeBuildsAValidFinding(t *testing.T) {
	for _, shape := range everyFindingShape(t) {
		if len(shape.findings) != 1 {
			t.Errorf("%s produced %d findings, want exactly 1", shape.name, len(shape.findings))
		}
	}
}

// TestWrongPassNeverBecomesWrongPassword is matrix mutation 19.
func TestWrongPassNeverBecomesWrongPassword(t *testing.T) {
	findings := Authentication(rctx(graphWith(t, nodeOf(t,
		serviceredis.StepAuthentication, domain.StateFail,
		domain.FailureAuthCredentialsRejected, nil))))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	text := prose(findings[0])
	if !strings.Contains(text, "rejected the credential") {
		t.Errorf("the summary must say the endpoint rejected the credential: %q",
			findings[0].Summary())
	}
	// The three merged causes must be named as merged, not chosen between.
	if !strings.Contains(text, "disabled user") || !strings.Contains(text, "unknown user") {
		t.Error("the detail must state that Redis merges the three causes, so that a " +
			"reader is not left to assume the password was wrong")
	}
}

// TestNoPermIsNotAServiceFailure is matrix mutation 20.
func TestNoPermIsNotAServiceFailure(t *testing.T) {
	findings := Ping(rctx(graphWith(t, nodeOf(t,
		serviceredis.StepPing, domain.StateUnknown, domain.FailureAuthzDenied, nil))))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if got := findings[0].Severity(); got != domain.SeverityWarn {
		t.Errorf("severity = %s, want WARN: an ACL denial is not a target failure", got)
	}
	if findings[0].Code() != CodeCommandNotPermitted {
		t.Errorf("code = %s, want %s", findings[0].Code(), CodeCommandNotPermitted)
	}
}

// TestAPassingPingProducesNoFinding is matrix mutation 21.
//
// The endpoint-scoped claim lives on the node. A finding would be a second,
// looser statement of the same thing, and the looser one is the one that becomes
// "Redis healthy".
func TestAPassingPingProducesNoFinding(t *testing.T) {
	findings := Ping(rctx(graphWith(t, nodeOf(t,
		serviceredis.StepPing, domain.StatePass, domain.FailureNone, nil))))

	if len(findings) != 0 {
		t.Fatalf("a passing probe produced %d findings: %v", len(findings), findings)
	}
}

// TestReplicaRoleProducesNoFinding is matrix mutation 22.
func TestReplicaRoleProducesNoFinding(t *testing.T) {
	graph := graphWith(t, nodeOf(t, serviceredis.StepHello, domain.StatePass, domain.FailureNone,
		map[domain.AttributeKey]domain.AttrValue{
			serviceredis.AttrRole:   domain.StringAttr("replica"),
			serviceredis.AttrServer: domain.StringAttr("redis"),
			serviceredis.AttrMode:   domain.StringAttr("standalone"),
		}))
	for _, rule := range []diagnosis.Rule{Hello, Sentinel, Authentication, Ping} {
		if findings := rule(rctx(graph)); len(findings) != 0 {
			t.Fatalf("role=replica produced %d findings; without an expected-role "+
				"contract it is an observation (ADR 0063 section 10)", len(findings))
		}
	}
}

// TestClusterModeProducesNoFinding is matrix mutation 23.
func TestClusterModeProducesNoFinding(t *testing.T) {
	graph := graphWith(t, nodeOf(t, serviceredis.StepHello, domain.StatePass, domain.FailureNone,
		map[domain.AttributeKey]domain.AttrValue{
			serviceredis.AttrMode: domain.StringAttr("cluster"),
		}))
	for _, rule := range []diagnosis.Rule{Hello, Sentinel, Authentication, Ping} {
		if findings := rule(rctx(graph)); len(findings) != 0 {
			t.Fatalf("mode=cluster produced %d findings; topology is not measured "+
				"(ADR 0065 section 2)", len(findings))
		}
	}
}

// TestSentinelIsReportedAsAnEndpointMismatch is matrix mutation 24.
func TestSentinelIsReportedAsAnEndpointMismatch(t *testing.T) {
	findings := Sentinel(rctx(graphWith(t, nodeOf(t,
		serviceredis.StepHello, domain.StatePass, domain.FailureNone,
		map[domain.AttributeKey]domain.AttrValue{
			serviceredis.AttrMode: domain.StringAttr("sentinel"),
		}))))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Code() != CodeEndpointIsSentinel {
		t.Fatalf("code = %s, want %s", finding.Code(), CodeEndpointIsSentinel)
	}
	if finding.Severity() != domain.SeverityError {
		t.Errorf("severity = %s, want ERROR", finding.Severity())
	}
	text := prose(finding)
	if !strings.Contains(text, "sentinel") || !strings.Contains(text, "not a redis") {
		t.Errorf("the finding must say the endpoint is a Sentinel and not a data "+
			"endpoint: %q", finding.Summary())
	}
	for _, forbidden := range []string{"quorum", "unhealthy", "wrong port"} {
		if strings.Contains(text, forbidden) && !strings.Contains(text, "not a claim") {
			t.Errorf("the finding claims %q, which svcdoctor did not measure", forbidden)
		}
	}
}

// TestLocalLimitsProduceNoFinding is matrix mutation 25.
//
// A cancelled run and an expired budget are svcdoctor's, and the report's
// incompleteness already reports them. A finding would dress a local limit as a
// remote failure.
func TestLocalLimitsProduceNoFinding(t *testing.T) {
	for _, class := range []domain.FailureClass{
		domain.FailureExecLocalTimeout,
		domain.FailureExecCancelled,
		domain.FailureExecUnsupportedBySvcdoctor,
	} {
		graph := graphWith(t,
			nodeOf(t, serviceredis.StepHello, domain.StateUnknown, class, nil),
			nodeOf(t, serviceredis.StepPing, domain.StateUnknown, class, nil),
			nodeOf(t, serviceredis.StepAuthentication, domain.StateUnknown, class, nil),
		)
		for _, rule := range []diagnosis.Rule{Hello, Sentinel, Authentication, Ping} {
			if findings := rule(rctx(graph)); len(findings) != 0 {
				t.Errorf("%s produced %d findings; a local limit is not a target claim",
					class, len(findings))
			}
		}
	}
}

// TestOnlyTheNormalizedPrefixReachesFindingProse is matrix mutation 32.
//
// The endpoint's condition may be restated, and only from the closed set. A
// value that is not one svcdoctor declared arrives as UNRECOGNIZED and the prose
// says exactly that.
func TestOnlyTheNormalizedPrefixReachesFindingProse(t *testing.T) {
	const canary = "CANARY-leak"
	findings := Ping(rctx(graphWith(t, nodeOf(t,
		serviceredis.StepPing, domain.StateUnknown, domain.FailureProtocolUnexpectedResponse,
		map[domain.AttributeKey]domain.AttrValue{
			serviceredis.AttrErrorPrefix: domain.StringAttr("UNRECOGNIZED"),
		}))))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	text := findings[0].Detail()
	if strings.Contains(text, canary) {
		t.Fatal("peer text reached the finding prose")
	}
	if !strings.Contains(text, "UNRECOGNIZED") {
		t.Errorf("the detail must name the normalized condition: %q", text)
	}
}

// TestNoRedisFindingAssertsAnExpectation is the standing ban.
//
// It mirrors TestNoPostgresFindingAssertsAnExpectation, and it is the test the
// vocabulary's doc comment promises.
func TestNoRedisFindingAssertsAnExpectation(t *testing.T) {
	banned := []string{
		"expected primary", "expected role", "should be primary", "should be a master",
		"expected implementation", "should be redis", "should be valkey",
		"expected version", "cluster should", "replication should",
	}
	for _, shape := range everyFindingShape(t) {
		for _, finding := range shape.findings {
			text := prose(finding)
			for _, phrase := range banned {
				if strings.Contains(text, phrase) {
					t.Errorf("%s asserts the expectation %q; BASIC has no expected-state "+
						"contract", finding.Code(), phrase)
				}
			}
		}
	}
}

// TestEveryDeclaredCodeIsProducedBySomeShape is the non-vacuity half.
//
// A code nobody can produce is a claim nobody can test, and it would read to the
// next author as a natural part of the vocabulary.
func TestEveryDeclaredCodeIsProducedBySomeShape(t *testing.T) {
	produced := map[domain.FindingCode]bool{}
	for _, shape := range everyFindingShape(t) {
		for _, finding := range shape.findings {
			produced[finding.Code()] = true
		}
	}
	for _, code := range []domain.FindingCode{
		CodeEndpointIsSentinel,
		CodeProtocolNotEstablished,
		CodeCredentialsRejected,
		CodeAuthenticationNotCompleted,
		CodeCredentialWithheld,
		CodeCredentialNotConfigured,
		CodeCommandNotPermitted,
		CodeEndpointNotServing,
		CodePingNotCompleted,
	} {
		if !produced[code] {
			t.Errorf("%s is declared but no shape produces it", code)
		}
	}
	if len(produced) != 9 {
		t.Errorf("the shapes produce %d distinct codes, want 9", len(produced))
	}
}
