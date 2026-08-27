//go:build integration

package rabbitmq

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/test/harness"
)

// Five RabbitMQ scenarios, expressed in Validation Harness v1.
//
// # Why only five
//
// The harness is service-neutral and stays that way: there is no RabbitMQ branch
// inside test/harness, and these scenarios adapt to its vocabulary rather than
// the other way round. Five representative outcomes are enough to prove the
// vocabulary fits a third service; migrating all twenty would add repetition,
// not confidence.
//
// # The credential counter is the broker's, not svcdoctor's
//
// `CredentialAttempts` is counted from the broker's own log — one line per
// credential-bearing exchange, either `PLAIN login refused` or `authenticated
// and granted access`. Counting svcdoctor's own authentication nodes would make
// the bound a restatement of the thing under test. No counter was added to
// production code to make this convenient.

// credentialAttemptsDuring counts the broker's own record of credential
// exchanges while fn runs.
func credentialAttemptsDuring(t *testing.T, container string, fn func()) int {
	t.Helper()

	before := brokerLogLines(t, container)
	fn()
	// The broker writes its log asynchronously; a short settle avoids counting
	// zero simply because the line had not been flushed yet.
	time.Sleep(500 * time.Millisecond)
	after := brokerLogLines(t, container)

	if len(after) < len(before) {
		t.Fatalf("the broker log shrank from %d to %d lines", len(before), len(after))
	}
	count := 0
	for _, line := range after[len(before):] {
		if strings.Contains(line, "login refused") ||
			strings.Contains(line, "authenticated and granted access") {
			count++
		}
	}
	return count
}

func brokerLogLines(t *testing.T, container string) []string {
	t.Helper()
	out, err := exec.Command("docker", "logs", container).CombinedOutput()
	if err != nil {
		t.Fatalf("docker logs %s: %v", container, err)
	}
	return strings.Split(string(out), "\n")
}

func attempts(n int) *int { return &n }

// RMQ-H1 — a wrong credential.
func TestRMQH1WrongCredential(t *testing.T) {
	var subject harness.Subject
	count := credentialAttemptsDuring(t, "svcd-rabbit", func() {
		r := run(t, runOptions{port: portAMQPS, username: userApp,
			password: "definitely-not-the-password", tls: trustFixtureCA(t)})
		subject = harness.Subject{
			Name:       "RMQ-H1 wrong credential",
			Report:     r.Report(),
			Incomplete: r.Incomplete(),
		}
	})
	subject.CredentialAttempts = attempts(count)

	harness.Assert(t, subject, harness.Expectation{
		Summary:          harness.Status(domain.SummaryStatusProblemsFound),
		FirstBrokenLayer: harness.BrokenAt(domain.LayerAuth),
		Incomplete:       harness.Complete(),
		RequireFindings:  []domain.FindingCode{diagnosisrabbitmq.CodeCredentialsRejected},
		ForbidFindings: []domain.FindingCode{
			diagnosisrabbitmq.CodeVHostAccessRefused,
			diagnosisrabbitmq.CodeCredentialWithheld,
		},
		Nodes: []harness.Node{
			{Step: stepAuth, State: domain.StateFail,
				FailureClass: domain.FailureAuthCredentialsRejected},
		},
		AbsentSteps: []domain.Step{stepOpen},
		// The broker refuses a wrong password and an unknown user identically,
		// so naming either cause would be an invention.
		ForbidProse:           []string{"unknown user", "no such user", "password is wrong"},
		ForbidSecrets:         []string{"definitely-not-the-password"},
		MaxCredentialAttempts: attempts(1),
	})
}

// RMQ-H2 — the virtual host does not exist.
func TestRMQH2VHostNotFound(t *testing.T) {
	var subject harness.Subject
	count := credentialAttemptsDuring(t, "svcd-rabbit", func() {
		r := run(t, runOptions{port: portAMQPS, username: userApp,
			password: passApp, vhost: vhostAbsent, tls: trustFixtureCA(t)})
		subject = harness.Subject{
			Name:       "RMQ-H2 vhost not found",
			Report:     r.Report(),
			Incomplete: r.Incomplete(),
		}
	})
	subject.CredentialAttempts = attempts(count)

	harness.Assert(t, subject, harness.Expectation{
		Summary:         harness.Status(domain.SummaryStatusProblemsFound),
		Incomplete:      harness.Complete(),
		RequireFindings: []domain.FindingCode{diagnosisrabbitmq.CodeVHostNotFound},
		ForbidFindings: []domain.FindingCode{
			diagnosisrabbitmq.CodeCredentialsRejected,
			diagnosisrabbitmq.CodeVHostAccessRefused,
		},
		Nodes: []harness.Node{
			{Step: stepAuth, State: domain.StatePass, FailureClass: domain.FailureNone},
			{Step: stepOpen, State: domain.StateFail,
				FailureClass: domain.FailureResourceNotFound},
		},
		// The peer's own sentence must not appear, and neither may a claim that
		// svcdoctor knows which virtual hosts exist.
		ForbidProse:           []string{"NOT_ALLOWED", "authentication failed"},
		ForbidSecrets:         []string{passApp},
		MaxCredentialAttempts: attempts(1),
	})
}

// RMQ-H3 — the identity is not permitted in the virtual host.
func TestRMQH3VHostAccessRefused(t *testing.T) {
	var subject harness.Subject
	count := credentialAttemptsDuring(t, "svcd-rabbit", func() {
		r := run(t, runOptions{port: portAMQPS, username: userNoPerm,
			password: passNoPerm, tls: trustFixtureCA(t)})
		subject = harness.Subject{
			Name:       "RMQ-H3 vhost access refused",
			Report:     r.Report(),
			Incomplete: r.Incomplete(),
		}
	})
	subject.CredentialAttempts = attempts(count)

	harness.Assert(t, subject, harness.Expectation{
		Summary:         harness.Status(domain.SummaryStatusProblemsFound),
		Incomplete:      harness.Complete(),
		RequireFindings: []domain.FindingCode{diagnosisrabbitmq.CodeVHostAccessRefused},
		ForbidFindings: []domain.FindingCode{
			diagnosisrabbitmq.CodeVHostNotFound,
			diagnosisrabbitmq.CodeCredentialsRejected,
		},
		Nodes: []harness.Node{
			{Step: stepAuth, State: domain.StatePass, FailureClass: domain.FailureNone},
			{Step: stepOpen, State: domain.StateFail, FailureClass: domain.FailureAuthzDenied},
		},
		ForbidProse:           []string{"doesn't have access", "check your password"},
		ForbidSecrets:         []string{passNoPerm},
		MaxCredentialAttempts: attempts(1),
	})
}

// RMQ-H4 — svcdoctor's own budget ends the run.
//
// The peer accepts the socket and never answers, so the credential counter is
// the peer's own and is exactly zero. A blackhole address could not prove that:
// nothing would be there to count.
func TestRMQH4LocalTimeout(t *testing.T) {
	peer := newFakePeer(t, fakeSilent)

	r := run(t, runOptions{
		host: "127.0.0.1", port: peer.port(),
		username: userApp, password: passApp,
		timeout: 12 * time.Second, stepTimeout: 3 * time.Second,
	})
	credentials, _ := peer.counts()

	harness.Assert(t, harness.Subject{
		Name:               "RMQ-H4 local timeout",
		Report:             r.Report(),
		Incomplete:         r.Incomplete(),
		CredentialAttempts: attempts(credentials),
	}, harness.Expectation{
		Incomplete: harness.Incomplete(),
		Nodes: []harness.Node{
			{Step: stepTCP, State: domain.StatePass, FailureClass: domain.FailureNone},
			{Step: stepStart, State: domain.StateUnknown,
				FailureClass: domain.FailureExecLocalTimeout},
		},
		AbsentSteps: []domain.Step{stepOpen},
		// A local deadline is not proof of remote failure.
		ForbidProse: []string{
			"the endpoint timed out", "the broker is slow", "the target is down",
		},
		ForbidSecrets:         []string{passApp},
		MaxCredentialAttempts: attempts(0),
	})
}

// RMQ-H5 — a capacity ceiling.
func TestRMQH5ResourceLimitReached(t *testing.T) {
	var subject harness.Subject
	count := credentialAttemptsDuring(t, "svcd-rabbit", func() {
		r := run(t, runOptions{port: portAMQPS, username: userApp,
			password: passApp, vhost: vhostLimit, tls: trustFixtureCA(t)})
		subject = harness.Subject{
			Name:       "RMQ-H5 resource limit reached",
			Report:     r.Report(),
			Incomplete: r.Incomplete(),
		}
	})
	subject.CredentialAttempts = attempts(count)

	harness.Assert(t, subject, harness.Expectation{
		Summary:         harness.Status(domain.SummaryStatusProblemsFound),
		Incomplete:      harness.Complete(),
		RequireFindings: []domain.FindingCode{diagnosisrabbitmq.CodeConnectionNotPermitted},
		ForbidFindings: []domain.FindingCode{
			diagnosisrabbitmq.CodeVHostAccessRefused,
			diagnosisrabbitmq.CodeCredentialsRejected,
		},
		Nodes: []harness.Node{
			{Step: stepAuth, State: domain.StatePass, FailureClass: domain.FailureNone},
			{Step: stepOpen, State: domain.StateFail,
				FailureClass: domain.FailureResourceLimitReached},
		},
		// A ceiling is not a leak, and the configured number is not svcdoctor's
		// to report.
		ForbidProse: []string{
			"connection leak", "too low", "increase the limit", "is reached",
		},
		ForbidSecrets:         []string{passApp},
		MaxCredentialAttempts: attempts(1),
	})
}
