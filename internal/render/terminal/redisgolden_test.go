package terminal

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The six Redis golden terminal tests.
//
// # Positive and forbidden wording, together
//
// Each golden asserts what the output must say **and** what it must never say.
// The second half is the load-bearing one: every claim svcdoctor is forbidden
// from making is a claim a reasonable person would write, and a test that only
// checked for the right words would pass against output that also contained the
// wrong ones.
//
// The graphs are built here rather than captured from a run, so the six cases are
// reproducible without Docker. The integration suite proves the same six shapes
// arise from real servers; this proves what the renderer does with them.

// redisGraph builds one Redis report.
type redisGraph struct {
	t       *testing.T
	builder *domain.GraphBuilder
	nodes   []domain.EvidenceID
}

func newRedisGraph(t *testing.T) *redisGraph {
	t.Helper()
	return &redisGraph{t: t, builder: domain.NewGraphBuilder()}
}

func (g *redisGraph) add(
	id string,
	step domain.Step,
	layer domain.Layer,
	state domain.State,
	class domain.FailureClass,
	attrs map[domain.AttributeKey]domain.AttrValue,
	parent string,
) domain.EvidenceID {
	g.t.Helper()

	subject, err := domain.NewEndpointSubject("198.51.100.10:6379")
	if err != nil {
		g.t.Fatalf("NewEndpointSubject: %v", err)
	}
	if step == vocabulary.StepTargetRequested {
		subject, err = domain.NewTargetSubject("redis.internal:6379")
		if err != nil {
			g.t.Fatalf("NewTargetSubject: %v", err)
		}
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID(id),
		Subject:      subject,
		Layer:        layer,
		Step:         step,
		State:        state,
		FailureClass: class,
		Attributes:   attrs,
		StartedAt:    time.Unix(1700000000, 0).UTC(),
		Elapsed:      domain.Measured(2 * time.Millisecond),
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
	g.nodes = append(g.nodes, evidence.ID())
	return evidence.ID()
}

// transport lays down the requested target and a connected path.
func (g *redisGraph) transport() {
	g.t.Helper()
	g.add("target.requested/redis.internal:6379", vocabulary.StepTargetRequested,
		domain.LayerInput, domain.StatePass, domain.FailureNone, nil, "")
	g.add("tcp.connect/redis.internal:6379/198.51.100.10", vocabulary.StepTCPConnect,
		domain.LayerTCP, domain.StatePass, domain.FailureNone, nil,
		"target.requested/redis.internal:6379")
}

func strAttr(pairs ...string) map[domain.AttributeKey]domain.AttrValue {
	out := map[domain.AttributeKey]domain.AttrValue{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out[domain.AttributeKey(pairs[i])] = domain.StringAttr(pairs[i+1])
	}
	return out
}

func withProto(attrs map[domain.AttributeKey]domain.AttrValue) map[domain.AttributeKey]domain.AttrValue {
	attrs[serviceredis.AttrProto] = domain.IntAttr(2)
	return attrs
}

// renderRedis produces the terminal document for a Redis report.
func (g *redisGraph) renderRedis(findings []domain.Finding, incomplete bool) string {
	g.t.Helper()

	graph, err := g.builder.Freeze()
	if err != nil {
		g.t.Fatalf("Freeze: %v", err)
	}
	service, err := domain.NewServiceID("redis")
	if err != nil {
		g.t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("test", time.Unix(1700000000, 0).UTC(),
		12*time.Millisecond, service)
	if err != nil {
		g.t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("redis.internal:6379")
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
		Graph: graph, Findings: findings, Security: security,
	})
	if err != nil {
		g.t.Fatalf("NewReport: %v", err)
	}

	var out bytes.Buffer
	if err := Write(&out, render.Input{Report: report, Incomplete: incomplete}); err != nil {
		g.t.Fatalf("Write: %v", err)
	}
	return out.String()
}

// collapseSpaces reduces runs of whitespace to one space.
//
// The goldens are about **wording**, not about column arithmetic. The Result
// block is tabwriter-aligned, so its padding depends on how many observation
// lines a case happens to have — G6 has none, because the endpoint refused HELLO
// — and an assertion carrying hard-coded padding would fail for a reason that
// has nothing to do with what the output claims. An earlier draft did exactly
// that, and the failure it produced was noise.
func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// assertWording is the shared shape of all six goldens.
func assertWording(t *testing.T, name, text string, must, mustNot []string) {
	t.Helper()
	lowered := collapseSpaces(strings.ToLower(text))
	for _, phrase := range must {
		if !strings.Contains(lowered, collapseSpaces(strings.ToLower(phrase))) {
			t.Errorf("%s: output does not contain %q\n\n%s", name, phrase, text)
		}
	}
	for _, phrase := range mustNot {
		if strings.Contains(lowered, collapseSpaces(strings.ToLower(phrase))) {
			t.Errorf("%s: output contains the forbidden phrase %q\n\n%s", name, phrase, text)
		}
	}
}

// forbiddenHealthClaims are the phrases no Redis output may ever contain.
//
// They are checked in every one of the six goldens rather than only where they
// are plausible, because the one that ships is the one nobody thought to check.
var forbiddenHealthClaims = []string{
	"redis healthy", "redis is healthy",
	"valkey healthy", "valkey is healthy",
	"service healthy", "service is healthy",
	"backend healthy", "backend is healthy",
	"cluster healthy", "cluster is healthy",
	"replication healthy", "replication is healthy",
}

// G1 — Redis standalone success.
func TestGoldenG1RedisStandaloneSuccess(t *testing.T) {
	g := newRedisGraph(t)
	g.transport()
	g.add("redis.hello/redis.internal:6379/198.51.100.10", serviceredis.StepHello,
		domain.LayerProtocol, domain.StatePass, domain.FailureNone,
		withProto(strAttr(
			string(serviceredis.AttrServer), "redis",
			string(serviceredis.AttrServerVersion), "8.2.1",
			string(serviceredis.AttrMode), "standalone",
			string(serviceredis.AttrRole), "master",
		)), "tcp.connect/redis.internal:6379/198.51.100.10")
	g.add("redis.ping/redis.internal:6379/198.51.100.10", serviceredis.StepPing,
		domain.LayerAuth, domain.StatePass, domain.FailureNone, nil,
		"redis.hello/redis.internal:6379/198.51.100.10")

	text := g.renderRedis(nil, false)

	assertWording(t, "G1", text,
		[]string{
			"implementation  redis",
			"version         8.2.1",
			"protocol        RESP2",
			"mode            standalone",
			"role            master",
			"this endpoint answered PING on this connection",
			"status          OK",
		},
		append([]string{
			"healthy", "usable", "wrong password", "topology",
		}, forbiddenHealthClaims...))
}

// G2 — Valkey standalone success.
//
// The operator typed `diagnose redis`. The output must say `valkey`, because the
// identity was observed rather than inferred from the verb.
func TestGoldenG2ValkeyStandaloneSuccess(t *testing.T) {
	g := newRedisGraph(t)
	g.transport()
	g.add("redis.hello/redis.internal:6379/198.51.100.10", serviceredis.StepHello,
		domain.LayerProtocol, domain.StatePass, domain.FailureNone,
		withProto(strAttr(
			string(serviceredis.AttrServer), "valkey",
			string(serviceredis.AttrServerVersion), "8.1.1",
			string(serviceredis.AttrMode), "standalone",
			string(serviceredis.AttrRole), "master",
		)), "tcp.connect/redis.internal:6379/198.51.100.10")
	g.add("redis.ping/redis.internal:6379/198.51.100.10", serviceredis.StepPing,
		domain.LayerAuth, domain.StatePass, domain.FailureNone, nil,
		"redis.hello/redis.internal:6379/198.51.100.10")

	text := g.renderRedis(nil, false)

	assertWording(t, "G2", text,
		[]string{
			"implementation  valkey",
			"version         8.1.1",
			"this endpoint answered PING on this connection",
		},
		append([]string{
			"implementation  redis", "healthy",
		}, forbiddenHealthClaims...))
}

// G3 — a cluster-mode endpoint.
func TestGoldenG3ClusterModeDirectEndpoint(t *testing.T) {
	g := newRedisGraph(t)
	g.transport()
	g.add("redis.hello/redis.internal:6379/198.51.100.10", serviceredis.StepHello,
		domain.LayerProtocol, domain.StatePass, domain.FailureNone,
		withProto(strAttr(
			string(serviceredis.AttrServer), "redis",
			string(serviceredis.AttrServerVersion), "8.2.1",
			string(serviceredis.AttrMode), "cluster",
			string(serviceredis.AttrRole), "master",
		)), "tcp.connect/redis.internal:6379/198.51.100.10")
	g.add("redis.ping/redis.internal:6379/198.51.100.10", serviceredis.StepPing,
		domain.LayerAuth, domain.StatePass, domain.FailureNone, nil,
		"redis.hello/redis.internal:6379/198.51.100.10")

	text := g.renderRedis(nil, false)

	assertWording(t, "G3", text,
		[]string{
			"mode            cluster",
			"Cluster mode was observed at this endpoint",
			"Cluster topology was NOT measured",
			"no node was discovered",
			"no slot",
			"this endpoint answered PING on this connection",
		},
		append([]string{
			"healthy", "slot coverage is complete", "all nodes",
		}, forbiddenHealthClaims...))
}

// G4 — Sentinel detection.
//
// The stop must be visible and the run must not read as a data endpoint that
// merely failed: no PONG-based success, and no outcome line at all.
func TestGoldenG4SentinelDetection(t *testing.T) {
	g := newRedisGraph(t)
	g.transport()
	hello := g.add("redis.hello/redis.internal:6379/198.51.100.10", serviceredis.StepHello,
		domain.LayerProtocol, domain.StatePass, domain.FailureNone,
		withProto(strAttr(
			string(serviceredis.AttrServer), "redis",
			string(serviceredis.AttrServerVersion), "8.2.1",
			string(serviceredis.AttrMode), "sentinel",
		)), "tcp.connect/redis.internal:6379/198.51.100.10")

	subject, err := domain.NewEndpointSubject("198.51.100.10:6379")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	finding, err := domain.NewFinding(domain.FindingInput{
		Code:       "REDIS_ENDPOINT_IS_SENTINEL",
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityError,
		Confidence: domain.ConfidenceHigh,
		Layer:      domain.LayerProtocol,
		Subject:    subject,
		Summary: "This endpoint identified itself as a Redis Sentinel, not a Redis or " +
			"Valkey data endpoint",
		Detail:       "The endpoint answered HELLO with mode=sentinel.",
		EvidenceRefs: []domain.EvidenceID{hello},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	text := g.renderRedis([]domain.Finding{finding}, false)

	assertWording(t, "G4", text,
		[]string{
			"mode            sentinel",
			"This endpoint identified itself as Redis Sentinel",
			"data-endpoint diagnosis stopped here",
			"before any",
			"credential was presented",
			"REDIS_ENDPOINT_IS_SENTINEL",
		},
		append([]string{
			"answered PING", "outcome", "PONG", "quorum", "healthy",
		}, forbiddenHealthClaims...))
}

// G5 — PING refused by ACL.
func TestGoldenG5PingNotPermitted(t *testing.T) {
	g := newRedisGraph(t)
	g.transport()
	g.add("redis.hello/redis.internal:6379/198.51.100.10", serviceredis.StepHello,
		domain.LayerProtocol, domain.StatePass, domain.FailureNone,
		withProto(strAttr(
			string(serviceredis.AttrServer), "redis",
			string(serviceredis.AttrServerVersion), "8.2.1",
			string(serviceredis.AttrMode), "standalone",
			string(serviceredis.AttrRole), "master",
		)), "tcp.connect/redis.internal:6379/198.51.100.10")
	g.add("redis.authentication/redis.internal:6379/198.51.100.10",
		serviceredis.StepAuthentication, domain.LayerAuth,
		domain.StatePass, domain.FailureNone, nil,
		"redis.hello/redis.internal:6379/198.51.100.10")
	ping := g.add("redis.ping/redis.internal:6379/198.51.100.10", serviceredis.StepPing,
		domain.LayerAuth, domain.StateUnknown, domain.FailureAuthzDenied,
		strAttr(string(serviceredis.AttrErrorPrefix), "NOPERM"),
		"redis.authentication/redis.internal:6379/198.51.100.10")

	subject, err := domain.NewEndpointSubject("198.51.100.10:6379")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	finding, err := domain.NewFinding(domain.FindingInput{
		Code:       "REDIS_COMMAND_NOT_PERMITTED",
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityWarn,
		Confidence: domain.ConfidenceHigh,
		Layer:      domain.LayerAuth,
		Subject:    subject,
		Summary: "The endpoint authenticated this identity and then refused to run the " +
			"usability probe for it, so usability was not measured",
		Detail: "Authentication was accepted, but this identity was not authorized to " +
			"execute the PING probe.",
		EvidenceRefs: []domain.EvidenceID{ping},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	text := g.renderRedis([]domain.Finding{finding}, false)

	assertWording(t, "G5", text,
		[]string{
			"authentication was accepted",
			"not authorized to",
			"execute the PING probe",
			"REDIS_COMMAND_NOT_PERMITTED",
			"status          OK",
		},
		append([]string{
			"FAIL", "unhealthy", "wrong password", "unknown user", "disabled user",
		}, forbiddenHealthClaims...))
}

// G6 — the credential was withheld by transport policy.
//
// It must be unmistakable that **svcdoctor** withheld it. "rejected" would put
// the decision on the endpoint, which expressed no opinion at all.
func TestGoldenG6CredentialWithheld(t *testing.T) {
	g := newRedisGraph(t)
	g.transport()
	g.add("redis.hello/redis.internal:6379/198.51.100.10", serviceredis.StepHello,
		domain.LayerProtocol, domain.StateUnknown, domain.FailureNone,
		strAttr(string(serviceredis.AttrErrorPrefix), "NOAUTH"),
		"tcp.connect/redis.internal:6379/198.51.100.10")
	auth := g.add("redis.authentication/redis.internal:6379/198.51.100.10",
		serviceredis.StepAuthentication, domain.LayerAuth,
		domain.StateSkipped, domain.FailureExecSkippedByPolicy, nil,
		"redis.hello/redis.internal:6379/198.51.100.10")

	subject, err := domain.NewEndpointSubject("198.51.100.10:6379")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	finding, err := domain.NewFinding(domain.FindingInput{
		Code:       "REDIS_CREDENTIAL_WITHHELD",
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityWarn,
		Confidence: domain.ConfidenceHigh,
		Layer:      domain.LayerAuth,
		Subject:    subject,
		Summary: "svcdoctor withheld the credential, because the channel to this endpoint " +
			"did not satisfy its credential-transport policy",
		Detail: "Zero credential bytes were written. The endpoint expressed no opinion " +
			"about the credential and this finding is not one.",
		EvidenceRefs: []domain.EvidenceID{auth},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	text := g.renderRedis([]domain.Finding{finding}, false)

	assertWording(t, "G6", text,
		[]string{
			"svcdoctor withheld the credential",
			"zero credential bytes were written",
			"expressed no opinion",
			"REDIS_CREDENTIAL_WITHHELD",
			"status          OK",
		},
		append([]string{
			"rejected the credential", "credential rejected", "wrong password",
			"the endpoint refused", "healthy",
		}, forbiddenHealthClaims...))
}

// TestTheGoldenWordingGuardsCanFail is the non-vacuity proof.
//
// Every golden above is a pair of string lists, and a string list is exactly the
// kind of assertion that can quietly stop matching anything. This drives the
// shared checker against output that violates each rule and asserts it complains.
func TestTheGoldenWordingGuardsCanFail(t *testing.T) {
	for _, tc := range []struct {
		name    string
		text    string
		must    []string
		mustNot []string
	}{
		{"a missing positive phrase", "Result\n  status OK\n",
			[]string{"this endpoint answered PING on this connection"}, nil},
		{"a forbidden health claim", "Result\n  outcome Redis is healthy\n",
			nil, forbiddenHealthClaims},
		{"an inferred identity", "  implementation  redis\n",
			[]string{"implementation  valkey"}, []string{"implementation  redis"}},
		{"a missing topology disclaimer", "  mode  cluster\n",
			[]string{"Cluster topology was NOT measured"}, nil},
		{"a rejected-credential claim on a withheld run", "svcdoctor rejected the credential\n",
			nil, []string{"rejected the credential"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &testing.T{}
			assertWording(fake, tc.name, tc.text, tc.must, tc.mustNot)
			if !fake.Failed() {
				t.Errorf("the wording guard accepted %q, which violates its own rule", tc.text)
			}
		})
	}
}
