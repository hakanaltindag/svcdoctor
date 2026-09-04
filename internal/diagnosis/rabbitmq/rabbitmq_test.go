package rabbitmq

import (
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// --- rule matrix ------------------------------------------------------------

// TestEveryProducibleOutcomeYieldsExactlyOneFinding drives the whole matrix.
//
// Each row is a (step, state, failure class) the adapter can commit to, paired
// with the code that owns it. Anything the adapter can produce and no rule
// explains is the silence ADR 0054 exists to prevent.
func TestEveryProducibleOutcomeYieldsExactlyOneFinding(t *testing.T) {
	tests := []struct {
		name  string
		step  domain.Step
		state domain.State
		class domain.FailureClass
		attrs map[domain.AttributeKey]domain.AttrValue
		want  domain.FindingCode
	}{
		{"start refused", servicerabbitmq.StepConnectionStart, domain.StateFail,
			domain.FailureProtocolUnsupportedVersion, nil, CodeConnectionStartNotCompleted},
		{"start peer closed", servicerabbitmq.StepConnectionStart, domain.StateFail,
			domain.FailureProtocolPeerClosed, nil, CodeConnectionStartNotCompleted},
		{"start malformed", servicerabbitmq.StepConnectionStart, domain.StateFail,
			domain.FailureProtocolMalformedResponse, nil, CodeConnectionStartNotCompleted},

		{"no credential", servicerabbitmq.StepAuthentication, domain.StateSkipped,
			domain.FailureExecRequiredInputMissing, nil, CodeCredentialNotConfigured},
		{"credential withheld", servicerabbitmq.StepAuthentication, domain.StateSkipped,
			domain.FailureExecSkippedByPolicy, nil, CodeCredentialWithheld},
		{"PLAIN not offered", servicerabbitmq.StepAuthentication, domain.StateUnknown,
			domain.FailureAuthMechanismNotOffered, nil, CodeAuthMechanismNotOffered},
		{"tune unsatisfiable", servicerabbitmq.StepAuthentication, domain.StateUnknown,
			domain.FailureProtocolUnsupportedCapability, nil, CodeAuthenticationUnsupported},
		{"credentials rejected", servicerabbitmq.StepAuthentication, domain.StateFail,
			domain.FailureAuthCredentialsRejected, nil, CodeCredentialsRejected},
		{"auth peer closed", servicerabbitmq.StepAuthentication, domain.StateFail,
			domain.FailureProtocolPeerClosed, nil, CodeAuthenticationNotCompleted},

		{"vhost not found", servicerabbitmq.StepConnectionOpen, domain.StateFail,
			domain.FailureResourceNotFound, nil, CodeVHostNotFound},
		{"vhost denied", servicerabbitmq.StepConnectionOpen, domain.StateFail,
			domain.FailureAuthzDenied, nil, CodeVHostAccessRefused},
		{"connection limit", servicerabbitmq.StepConnectionOpen, domain.StateFail,
			domain.FailureResourceLimitReached, nil, CodeConnectionNotPermitted},
		{"unspecified refusal", servicerabbitmq.StepConnectionOpen, domain.StateFail,
			domain.FailureAuthzNotPermitted, nil, CodeConnectionNotPermitted},
		{"open peer closed", servicerabbitmq.StepConnectionOpen, domain.StateFail,
			domain.FailureProtocolPeerClosed, nil, CodeConnectionNotEstablished},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graphWith(t, tt.step, tt.state, tt.class, tt.attrs)
			findings := allFindings(g)
			if len(findings) != 1 {
				t.Fatalf("produced %d findings, want exactly 1: %v", len(findings), codesOf(findings))
			}
			if findings[0].Code() != tt.want {
				t.Errorf("code = %s, want %s", findings[0].Code(), tt.want)
			}
		})
	}
}

// TestPassingNodesProduceNoFinding pins the other direction.
//
// A passing open in particular must not become a claim: not that the broker is
// healthy, not that the virtual host is usable, not that messaging works.
func TestPassingNodesProduceNoFinding(t *testing.T) {
	for _, step := range []domain.Step{
		servicerabbitmq.StepConnectionStart,
		servicerabbitmq.StepAuthentication,
		servicerabbitmq.StepConnectionOpen,
	} {
		g := graphWith(t, step, domain.StatePass, domain.FailureNone, nil)
		if findings := allFindings(g); len(findings) != 0 {
			t.Errorf("%s PASS produced %v", step, codesOf(findings))
		}
	}
}

// TestLocalTimeoutIsNotATargetFailure proves a budget expiry produces no
// finding. It is reported through the run's incompleteness instead.
func TestLocalTimeoutIsNotATargetFailure(t *testing.T) {
	for _, step := range []domain.Step{
		servicerabbitmq.StepConnectionStart,
		servicerabbitmq.StepAuthentication,
		servicerabbitmq.StepConnectionOpen,
	} {
		g := graphWith(t, step, domain.StateUnknown, domain.FailureExecLocalTimeout, nil)
		if findings := allFindings(g); len(findings) != 0 {
			t.Errorf("%s local timeout produced %v; a local deadline is not proof of "+
				"remote failure", step, codesOf(findings))
		}
	}
}

// --- claim discipline -------------------------------------------------------

// TestNoFindingNamesACauseRabbitMQDoesNotName is the truthfulness gate.
func TestNoFindingNamesACauseRabbitMQDoesNotName(t *testing.T) {
	forbidden := []string{
		// A 403 covers four conditions and names none of them.
		"wrong password", "incorrect password", "bad password",
		"unknown user", "user does not exist", "no such user",
		"disabled user", "account is disabled", "account locked",
		// A capacity ceiling names no cause.
		"too low", "leak", "leaking", "misconfigured pool", "load spike",
		// Health BASIC cannot observe.
		"is healthy", "cluster is healthy", "vhost is healthy", "broker is healthy",
		"queues are usable", "publishing works", "consuming works",
		"all nodes", "backend is healthy", "your application will work",
	}

	for _, step := range []domain.Step{
		servicerabbitmq.StepConnectionStart,
		servicerabbitmq.StepAuthentication,
		servicerabbitmq.StepConnectionOpen,
	} {
		for _, class := range []domain.FailureClass{
			domain.FailureProtocolUnsupportedVersion, domain.FailureProtocolPeerClosed,
			domain.FailureAuthCredentialsRejected, domain.FailureAuthMechanismNotOffered,
			domain.FailureResourceNotFound, domain.FailureAuthzDenied,
			domain.FailureResourceLimitReached, domain.FailureAuthzNotPermitted,
		} {
			for _, state := range []domain.State{domain.StateFail, domain.StateUnknown} {
				g := graphWith(t, step, state, class, nil)
				for _, f := range allFindings(g) {
					text := strings.ToLower(f.Summary() + "\n" + f.Detail())
					for _, phrase := range forbidden {
						if strings.Contains(text, phrase) {
							t.Errorf("%s says %q", f.Code(), phrase)
						}
					}
				}
			}
		}
	}
}

// TestTheClaimGuardCanFail proves the phrase list is live.
func TestTheClaimGuardCanFail(t *testing.T) {
	planted := "the endpoint reported a wrong password and the cluster is healthy"
	hits := 0
	for _, phrase := range []string{"wrong password", "cluster is healthy"} {
		if strings.Contains(planted, phrase) {
			hits++
		}
	}
	if hits != 2 {
		t.Errorf("the forbidden-phrase predicate matched %d of 2 planted phrases", hits)
	}
}

// TestTheGuestSentenceIsGatedOnTheUsernameAlone pins ADR 0068 §4.1.
//
// RabbitMQ evaluates its loopback restriction against the broker's view of the
// client's source address, which svcdoctor cannot observe. Gating the sentence on
// any address would build a claim on evidence it does not have.
func TestTheGuestSentenceIsGatedOnTheUsernameAlone(t *testing.T) {
	const marker = "loopback_users"

	withGuest := graphWith(t, servicerabbitmq.StepAuthentication, domain.StateFail,
		domain.FailureAuthCredentialsRejected,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrIdentity: domain.IdentityAttr("guest"),
		})
	f := only(t, allFindings(withGuest))
	if !strings.Contains(f.Detail(), marker) {
		t.Error("a rejection for `guest` does not mention the default loopback policy")
	}
	// It must disclaim applicability rather than assert it.
	if !strings.Contains(f.Detail(), "cannot") {
		t.Error("the guest sentence does not disclaim that svcdoctor knows it applied")
	}

	withOther := graphWith(t, servicerabbitmq.StepAuthentication, domain.StateFail,
		domain.FailureAuthCredentialsRejected,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrIdentity: domain.IdentityAttr("appuser"),
		})
	if strings.Contains(only(t, allFindings(withOther)).Detail(), marker) {
		t.Error("the guest sentence appeared for a non-guest identity")
	}

	noIdentity := graphWith(t, servicerabbitmq.StepAuthentication, domain.StateFail,
		domain.FailureAuthCredentialsRejected, nil)
	if strings.Contains(only(t, allFindings(noIdentity)).Detail(), marker) {
		t.Error("the guest sentence appeared with no identity recorded")
	}
}

// TestTheDefaultedVHostIsNamedOnARefusal pins ADR 0067 §3.1.
func TestTheDefaultedVHostIsNamedOnARefusal(t *testing.T) {
	const marker = "--vhost"

	defaulted := graphWith(t, servicerabbitmq.StepConnectionOpen, domain.StateFail,
		domain.FailureResourceNotFound,
		map[domain.AttributeKey]domain.AttrValue{
			servicerabbitmq.AttrVHostDefaulted: domain.BoolAttr(true),
		})
	if !strings.Contains(only(t, allFindings(defaulted)).Detail(), marker) {
		t.Error("a vhost-not-found refusal on a defaulted vhost does not say the default was used")
	}

	explicit := graphWith(t, servicerabbitmq.StepConnectionOpen, domain.StateFail,
		domain.FailureResourceNotFound, nil)
	detail := only(t, allFindings(explicit)).Detail()
	if strings.Contains(detail, "svcdoctor used the default") {
		t.Error("the default sentence appeared for an explicitly named vhost")
	}
}

// --- helpers ----------------------------------------------------------------

func allFindings(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	out = append(out, ConnectionStart(rctx(g))...)
	out = append(out, Authentication(rctx(g))...)
	out = append(out, ConnectionOpen(rctx(g))...)
	return out
}

func codesOf(findings []domain.Finding) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code())
	}
	return out
}

func only(t *testing.T, findings []domain.Finding) domain.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("want exactly 1 finding, got %d: %v", len(findings), codesOf(findings))
	}
	return findings[0]
}

func graphWith(
	t *testing.T,
	step domain.Step,
	state domain.State,
	class domain.FailureClass,
	attrs map[domain.AttributeKey]domain.AttrValue,
) domain.Graph {
	t.Helper()

	subject, err := domain.NewEndpointSubject("192.0.2.10:5672")
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	layer := domain.LayerAuth
	if step == servicerabbitmq.StepConnectionStart {
		layer = domain.LayerProtocol
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID(string(step) + "|test"),
		Subject:      subject,
		Layer:        layer,
		Step:         step,
		State:        state,
		FailureClass: class,
		Attributes:   attrs,
		StartedAt:    time.Unix(0, 0).UTC(),
		Elapsed:      domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("add: %v", err)
	}
	g, err := builder.Freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	return g
}
