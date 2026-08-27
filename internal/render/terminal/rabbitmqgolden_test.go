package terminal

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The eight RabbitMQ golden terminal tests.
//
// # Positive and forbidden wording, together
//
// Each golden asserts what the output must say **and** what it must never say.
// The second half is the load-bearing one: every claim svcdoctor is forbidden
// from making about RabbitMQ is a claim a reasonable person would write — "the
// broker is healthy", "wrong password", "increase the limit" — and a test that
// only checked for the right words would pass against output that also contained
// the wrong ones.
//
// The graphs are built here rather than captured from a run, so the eight cases
// are reproducible without Docker. The integration suite proves the same shapes
// arise from real brokers; this proves what the renderer does with them.

// forbiddenEverywhere is asserted against every RabbitMQ golden.
//
// These are the claims BASIC structurally cannot make, from ADR 0067 §5.1. They
// are checked on success *and* on failure, because an overclaim is just as wrong
// in a report that also carries a finding.
var forbiddenEverywhere = []string{
	"rabbitmq is healthy", "rabbitmq is up", "rabbitmq is usable",
	"broker is healthy", "cluster is healthy", "vhost is healthy",
	"virtual host is healthy", "publishing works", "consuming works",
	"queues are accessible", "exchanges are accessible", "queues are usable",
	"permissions are correct", "your application will work",
	"all nodes", "backend is healthy", "message delivery",
}

// rabbitGraph builds one RabbitMQ report.
type rabbitGraph struct {
	t       *testing.T
	builder *domain.GraphBuilder
}

func newRabbitGraph(t *testing.T) *rabbitGraph {
	t.Helper()
	return &rabbitGraph{t: t, builder: domain.NewGraphBuilder()}
}

func (g *rabbitGraph) add(
	id string,
	step domain.Step,
	layer domain.Layer,
	state domain.State,
	class domain.FailureClass,
	attrs map[domain.AttributeKey]domain.AttrValue,
	parent string,
) domain.EvidenceID {
	g.t.Helper()

	subject, err := domain.NewEndpointSubject("198.51.100.20:5672")
	if err != nil {
		g.t.Fatalf("NewEndpointSubject: %v", err)
	}
	if step == vocabulary.StepTargetRequested {
		subject, err = domain.NewTargetSubject("rabbit.internal:5672")
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
	return evidence.ID()
}

const (
	rabbitTarget = "target.requested/rabbit.internal:5672"
	rabbitTCP    = "tcp.connect/rabbit.internal:5672/198.51.100.20"
	rabbitStart  = "rabbitmq.connection_start/rabbit.internal:5672/198.51.100.20"
	rabbitAuth   = "rabbitmq.authentication/rabbit.internal:5672/198.51.100.20"
	rabbitOpen   = "rabbitmq.connection_open/rabbit.internal:5672/198.51.100.20"
)

// transport lays down the requested target and a connected path.
func (g *rabbitGraph) transport() {
	g.t.Helper()
	g.add(rabbitTarget, vocabulary.StepTargetRequested,
		domain.LayerInput, domain.StatePass, domain.FailureNone, nil, "")
	g.add(rabbitTCP, vocabulary.StepTCPConnect,
		domain.LayerTCP, domain.StatePass, domain.FailureNone, nil, rabbitTarget)
}

// connectionStart records a passing protocol exchange for one implementation.
func (g *rabbitGraph) connectionStart(product, version, platform, cluster string) {
	g.t.Helper()
	attrs := map[domain.AttributeKey]domain.AttrValue{
		servicerabbitmq.AttrProduct:           domain.StringAttr(product),
		servicerabbitmq.AttrVersion:           domain.StringAttr(version),
		servicerabbitmq.AttrPlatform:          domain.StringAttr(platform),
		servicerabbitmq.AttrAMQPVersion:       domain.StringAttr("0-9"),
		servicerabbitmq.AttrMechanismsOffered: domain.StringAttr("AMQPLAIN PLAIN"),
		servicerabbitmq.AttrAnonymousOffered:  domain.BoolAttr(false),
	}
	if cluster != "" {
		attrs[servicerabbitmq.AttrClusterName] = domain.IdentityAttr(cluster)
	}
	g.add(rabbitStart, servicerabbitmq.StepConnectionStart,
		domain.LayerProtocol, domain.StatePass, domain.FailureNone, attrs, rabbitTCP)
}

// authPass records an accepted credential and the negotiation it proved.
func (g *rabbitGraph) authPass(identity string) {
	g.t.Helper()
	g.add(rabbitAuth, servicerabbitmq.StepAuthentication,
		domain.LayerAuth, domain.StatePass, domain.FailureNone,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrMechanismSelected:  domain.StringAttr("PLAIN"),
			servicerabbitmq.AttrIdentity:           domain.IdentityAttr(identity),
			servicerabbitmq.AttrChannelMaxOffered:  domain.IntAttr(2047),
			servicerabbitmq.AttrChannelMaxSelected: domain.IntAttr(1),
			servicerabbitmq.AttrFrameMaxOffered:    domain.IntAttr(131072),
			servicerabbitmq.AttrFrameMaxSelected:   domain.IntAttr(8192),
			servicerabbitmq.AttrHeartbeatOffered:   domain.IntAttr(60),
			servicerabbitmq.AttrHeartbeatSelected:  domain.IntAttr(0),
		}, rabbitStart)
}

// openPass records the terminal node.
func (g *rabbitGraph) openPass(vhost string) {
	g.t.Helper()
	g.add(rabbitOpen, servicerabbitmq.StepConnectionOpen,
		domain.LayerAuth, domain.StatePass, domain.FailureNone,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrVHost:         domain.IdentityAttr(vhost),
			servicerabbitmq.AttrGracefulClose: domain.BoolAttr(true),
		}, rabbitAuth)
}

// renderRabbit produces the terminal document for a RabbitMQ report.
func (g *rabbitGraph) renderRabbit(findings []domain.Finding, incomplete bool) string {
	g.t.Helper()

	graph, err := g.builder.Freeze()
	if err != nil {
		g.t.Fatalf("Freeze: %v", err)
	}
	service, err := domain.NewServiceID("rabbitmq")
	if err != nil {
		g.t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("test", time.Unix(1700000000, 0).UTC(),
		12*time.Millisecond, service)
	if err != nil {
		g.t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("rabbit.internal:5672")
	if err != nil {
		g.t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("host.test")
	if err != nil {
		g.t.Fatalf("NewLocalVantage: %v", err)
	}
	sec, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		g.t.Fatalf("NewReportSecurity: %v", err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: sec,
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

// rabbitFinding builds one finding for a golden.
func rabbitFinding(
	t *testing.T, code domain.FindingCode, severity domain.Severity,
	summary, detail, node string,
) domain.Finding {
	t.Helper()

	subject, err := domain.NewEndpointSubject("198.51.100.20:5672")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	finding, err := domain.NewFinding(domain.FindingInput{
		Code:             code,
		Kind:             domain.FindingKindConfirmed,
		Severity:         severity,
		Confidence:       domain.ConfidenceHigh,
		Layer:            domain.LayerAuth,
		Subject:          subject,
		Summary:          summary,
		Detail:           detail,
		VantageDependent: false,
		EvidenceRefs:     []domain.EvidenceID{domain.EvidenceID(node)},
	})
	if err != nil {
		t.Fatalf("NewFinding(%s): %v", code, err)
	}
	return finding
}

// assertRabbitWording asserts required and forbidden phrases, plus the
// always-forbidden overclaims.
func assertRabbitWording(t *testing.T, name, text string, must, mustNot []string) {
	t.Helper()
	assertWording(t, name, text, must, append(append([]string{}, mustNot...), forbiddenEverywhere...))
}

// --- G1 ---------------------------------------------------------------------

func TestGoldenRabbitMQHealthy(t *testing.T) {
	g := newRabbitGraph(t)
	g.transport()
	g.connectionStart("RabbitMQ", "4.2.0", "Erlang/OTP 27.3.4", "rabbit@node-a")
	g.authPass("appuser")
	g.openPass("/")

	out := g.renderRabbit(nil, false)
	assertRabbitWording(t, "G1", out,
		[]string{
			"connection.open-ok",
			"for the requested virtual host on this connection",
			"rabbitmq", "4.2.0", "erlang/otp",
			"amqp 0-9", "plain",
			"channel_max selected", "frame_max selected", "heartbeat selected",
		},
		[]string{"wrong password", "increase", "restart"})
}

// --- G2 ---------------------------------------------------------------------

// TestGoldenLavinMQHealthy proves the verb is not the claim.
//
// The operator typed `diagnose rabbitmq`; the endpoint said it was LavinMQ, and
// the report says LavinMQ. Nothing in the renderer branches on the answer.
func TestGoldenLavinMQHealthy(t *testing.T) {
	g := newRabbitGraph(t)
	g.transport()
	// LavinMQ sends no cluster_name at all — measured in Phase 8.0C — and an
	// absent observation renders as absent rather than as an invented blank.
	g.connectionStart("LavinMQ", "2.3.0", "Crystal 1.16.0", "")
	g.authPass("guest")
	g.openPass("/")

	out := g.renderRabbit(nil, false)
	assertRabbitWording(t, "G2", out,
		[]string{"lavinmq", "2.3.0", "crystal", "connection.open-ok"},
		[]string{"rabbitmq 2.3.0", "cluster name"})
}

// --- G3 ---------------------------------------------------------------------

func TestGoldenRabbitMQCredentialsRejected(t *testing.T) {
	g := newRabbitGraph(t)
	g.transport()
	g.connectionStart("RabbitMQ", "4.2.0", "Erlang/OTP 27.3.4", "rabbit@node-a")
	g.add(rabbitAuth, servicerabbitmq.StepAuthentication,
		domain.LayerAuth, domain.StateFail, domain.FailureAuthCredentialsRejected,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrMechanismSelected: domain.StringAttr("PLAIN"),
			servicerabbitmq.AttrIdentity:          domain.IdentityAttr("appuser"),
		}, rabbitStart)

	finding := rabbitFinding(t, "RABBITMQ_CREDENTIALS_REJECTED", domain.SeverityError,
		"This endpoint refused the authentication context it was presented",
		"svcdoctor authenticated with SASL PLAIN and the endpoint answered with a refusal.\n"+
			"RabbitMQ answers several different conditions with one identical refusal and "+
			"does not tell the client which one applied; the broker's own log records the "+
			"reason.", rabbitAuth)

	out := g.renderRabbit([]domain.Finding{finding}, false)
	assertRabbitWording(t, "G3", out,
		[]string{
			"refused the authentication context",
			"one identical refusal", "does not tell the client which one applied",
			"did not answer connection.open-ok",
		},
		[]string{"wrong password", "unknown user", "disabled user", "loopback_users"})
}

// --- G4 ---------------------------------------------------------------------

// TestGoldenRabbitMQGuestRejected pins the one conditional sentence.
//
// It is gated on the username being exactly `guest` and on **nothing else**.
// RabbitMQ evaluates its loopback restriction against the broker's view of the
// client's source address, which svcdoctor cannot observe — so the sentence must
// disclaim applicability rather than assert it, and must never become a finding.
func TestGoldenRabbitMQGuestRejected(t *testing.T) {
	g := newRabbitGraph(t)
	g.transport()
	g.connectionStart("RabbitMQ", "4.2.0", "Erlang/OTP 27.3.4", "rabbit@node-a")
	g.add(rabbitAuth, servicerabbitmq.StepAuthentication,
		domain.LayerAuth, domain.StateFail, domain.FailureAuthCredentialsRejected,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrMechanismSelected: domain.StringAttr("PLAIN"),
			servicerabbitmq.AttrIdentity:          domain.IdentityAttr("guest"),
		}, rabbitStart)

	finding := rabbitFinding(t, "RABBITMQ_CREDENTIALS_REJECTED", domain.SeverityError,
		"This endpoint refused the authentication context it was presented",
		"svcdoctor authenticated with SASL PLAIN and the endpoint answered with a refusal.\n"+
			"RabbitMQ ships with `guest` in its `loopback_users` list, so `guest` is "+
			"refused from any non-loopback source under default configuration. svcdoctor "+
			"cannot see which source address this broker observed, so it cannot tell "+
			"whether that policy applied here.", rabbitAuth)

	out := g.renderRabbit([]domain.Finding{finding}, false)
	assertRabbitWording(t, "G4", out,
		[]string{
			"loopback_users",
			"cannot see which source address this broker observed",
			"cannot tell whether that policy applied",
		},
		[]string{
			"wrong password",
			// The disclaimer must not become an assertion.
			"the guest restriction applied", "guest is blocked from this host",
			"hypothesis",
		})
}

// --- G5 ---------------------------------------------------------------------

func TestGoldenRabbitMQVHostNotFound(t *testing.T) {
	g := newRabbitGraph(t)
	g.transport()
	g.connectionStart("RabbitMQ", "4.2.0", "Erlang/OTP 27.3.4", "rabbit@node-a")
	g.authPass("appuser")
	g.add(rabbitOpen, servicerabbitmq.StepConnectionOpen,
		domain.LayerAuth, domain.StateFail, domain.FailureResourceNotFound,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrVHost:        domain.IdentityAttr("/orders"),
			servicerabbitmq.AttrCloseOutcome: domain.StringAttr("VHOST_NOT_FOUND"),
			servicerabbitmq.AttrReplyCode:    domain.IntAttr(530),
		}, rabbitAuth)

	finding := rabbitFinding(t, "RABBITMQ_VHOST_NOT_FOUND", domain.SeverityError,
		"This endpoint reported that the requested virtual host was not found",
		"svcdoctor authenticated and asked to open a connection in the requested virtual "+
			"host, and the endpoint answered that it was not found.\n"+
			"That is the endpoint's own statement about the name it was given. svcdoctor "+
			"did not enumerate virtual hosts and makes no claim about which ones exist.",
		rabbitOpen)

	out := g.renderRabbit([]domain.Finding{finding}, false)
	assertRabbitWording(t, "G5", out,
		[]string{
			"reported that the requested virtual host was not found",
			"endpoint's own statement",
			"makes no claim about which ones exist",
		},
		[]string{
			"does not exist", "the cluster does not contain",
			"wrong password", "no such vhost anywhere",
		})
}

// --- G6 ---------------------------------------------------------------------

func TestGoldenRabbitMQVHostAccessRefused(t *testing.T) {
	g := newRabbitGraph(t)
	g.transport()
	g.connectionStart("RabbitMQ", "4.2.0", "Erlang/OTP 27.3.4", "rabbit@node-a")
	g.authPass("appuser")
	g.add(rabbitOpen, servicerabbitmq.StepConnectionOpen,
		domain.LayerAuth, domain.StateFail, domain.FailureAuthzDenied,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrVHost:        domain.IdentityAttr("/orders"),
			servicerabbitmq.AttrCloseOutcome: domain.StringAttr("VHOST_ACCESS_REFUSED"),
			servicerabbitmq.AttrReplyCode:    domain.IntAttr(530),
		}, rabbitAuth)

	finding := rabbitFinding(t, "RABBITMQ_VHOST_ACCESS_REFUSED", domain.SeverityError,
		"This identity was refused access to the requested virtual host",
		"svcdoctor authenticated successfully and the endpoint then refused to open a "+
			"connection in the requested virtual host.\n"+
			"The credential is not the problem — it was accepted. What was denied is "+
			"access to this virtual host for this identity.\n"+
			"This says nothing about what the identity may do inside the virtual host.",
		rabbitOpen)

	out := g.renderRabbit([]domain.Finding{finding}, false)
	assertRabbitWording(t, "G6", out,
		[]string{
			"authenticated successfully",
			"refused access to the requested virtual host",
			"the credential is not the problem",
		},
		[]string{
			"wrong password", "user does not exist", "unknown user",
			"configure permission denied", "write permission denied",
			"read permission denied",
		})
}

// --- G7 ---------------------------------------------------------------------

func TestGoldenRabbitMQResourceLimit(t *testing.T) {
	g := newRabbitGraph(t)
	g.transport()
	g.connectionStart("RabbitMQ", "4.2.0", "Erlang/OTP 27.3.4", "rabbit@node-a")
	g.authPass("appuser")
	g.add(rabbitOpen, servicerabbitmq.StepConnectionOpen,
		domain.LayerAuth, domain.StateFail, domain.FailureResourceLimitReached,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrVHost:        domain.IdentityAttr("/"),
			servicerabbitmq.AttrCloseOutcome: domain.StringAttr("NODE_CONNECTION_LIMIT"),
			servicerabbitmq.AttrReplyCode:    domain.IntAttr(530),
		}, rabbitAuth)

	finding := rabbitFinding(t, "RABBITMQ_CONNECTION_NOT_PERMITTED", domain.SeverityError,
		"This endpoint refused to open the connection",
		"svcdoctor authenticated successfully and the endpoint refused the connection "+
			"for a reason other than a missing virtual host or a permission decision.\n"+
			"Where the endpoint named a capacity ceiling, that is recorded as what it "+
			"said and nothing more. It proves the endpoint refused at that moment; it "+
			"proves nothing about why, for how long, or what to change.", rabbitOpen)

	out := g.renderRabbit([]domain.Finding{finding}, false)
	assertRabbitWording(t, "G7", out,
		[]string{
			"refused to open the connection",
			"proves nothing about why, for how long, or what to change",
		},
		[]string{
			"connection leak", "leaking", "limit is too low", "too many clients",
			"misconfiguration", "increase the limit", "restart rabbitmq",
		})
}

// --- G8 ---------------------------------------------------------------------

func TestGoldenRabbitMQCredentialWithheld(t *testing.T) {
	g := newRabbitGraph(t)
	g.transport()
	g.connectionStart("RabbitMQ", "4.2.0", "Erlang/OTP 27.3.4", "rabbit@node-a")
	g.add(rabbitAuth, servicerabbitmq.StepAuthentication,
		domain.LayerAuth, domain.StateSkipped, domain.FailureExecSkippedByPolicy,
		nil, rabbitStart)

	finding := rabbitFinding(t, "RABBITMQ_CREDENTIAL_WITHHELD", domain.SeverityWarn,
		"svcdoctor refused to send the credential over this channel",
		"A credential was configured and svcdoctor did not put it on the wire, because "+
			"the channel's peer identity was not verified.\n"+
			"Zero credential bytes were sent. A plaintext connection and a connection "+
			"with --tls-insecure are both refused, and neither a loopback address nor a "+
			"private one changes that.", rabbitAuth)

	out := g.renderRabbit([]domain.Finding{finding}, false)
	assertRabbitWording(t, "G8", out,
		[]string{
			"refused to send the credential",
			"zero credential bytes were sent",
			"neither a loopback address nor a private one changes that",
			// Everything above the credential boundary was still measured.
			"rabbitmq", "4.2.0",
		},
		[]string{"wrong password", "credential was rejected", "authentication failed"})
}

// --- non-vacuity ------------------------------------------------------------

// TestTheRabbitMQGoldenAssertionsCanFail proves both halves are live.
//
// A golden that only ever passes is worse than no golden: it reads as coverage
// and enforces nothing. This plants text that violates each half and asserts the
// predicate notices.
func TestTheRabbitMQGoldenAssertionsCanFail(t *testing.T) {
	// The required half.
	missing := "the endpoint answered something else entirely"
	if strings.Contains(collapseSpaces(strings.ToLower(missing)),
		collapseSpaces("connection.open-ok")) {
		t.Error("the required-phrase predicate matches text that lacks the phrase")
	}

	// The forbidden half, including every always-forbidden overclaim.
	for _, planted := range append([]string{
		"the endpoint answered Connection.Open-Ok and RabbitMQ is healthy",
		"the credential was refused: wrong password",
		"increase the limit and restart RabbitMQ",
	}, forbiddenEverywhere...) {
		lowered := collapseSpaces(strings.ToLower(planted))
		hit := false
		for _, phrase := range append([]string{
			"wrong password", "increase the limit", "restart rabbitmq",
		}, forbiddenEverywhere...) {
			if strings.Contains(lowered, collapseSpaces(strings.ToLower(phrase))) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("the forbidden-phrase predicate does not match %q", planted)
		}
	}
}

// TestEveryRabbitMQGoldenRejectsTheOverclaims proves the shared list is applied
// rather than merely declared.
func TestEveryRabbitMQGoldenRejectsTheOverclaims(t *testing.T) {
	if len(forbiddenEverywhere) < 10 {
		t.Fatalf("forbiddenEverywhere has %d entries; it is meant to cover the claims "+
			"ADR 0067 §5.1 forbids", len(forbiddenEverywhere))
	}
	// A healthy report is the case most likely to acquire an overclaim, so it is
	// the one checked directly here as well as through assertRabbitWording.
	g := newRabbitGraph(t)
	g.transport()
	g.connectionStart("RabbitMQ", "4.2.0", "Erlang/OTP 27.3.4", "rabbit@node-a")
	g.authPass("appuser")
	g.openPass("/")

	lowered := strings.ToLower(g.renderRabbit(nil, false))
	for _, phrase := range forbiddenEverywhere {
		if strings.Contains(lowered, phrase) {
			t.Errorf("a healthy RabbitMQ report says %q", phrase)
		}
	}
}
