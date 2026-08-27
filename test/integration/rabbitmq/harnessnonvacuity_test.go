//go:build integration

package rabbitmq

import (
	"fmt"
	"strings"
	"testing"
	"time"

	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/test/harness"
)

// The non-vacuity mutation each migrated scenario needs.
//
// A harness assertion that cannot fail is documentation. Rather than editing
// five scenarios by hand to prove that, this drives `harness.Assert` with a
// **recording T** and a deliberately wrong expectation, and requires it to
// complain. `harness.T` is an interface for exactly this reason.
//
// Each case mutates one dimension the real scenario pins — the finding code, the
// state, the failure class, the incompleteness, the credential bound and a
// forbidden claim — so every dimension is shown to bite.

type recordingT struct {
	failures []string
}

func (r *recordingT) Helper() {}

func (r *recordingT) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// fatalSentinel unwinds Assert without killing the test binary.
type fatalSentinel struct{}

func (r *recordingT) Fatalf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
	panic(fatalSentinel{})
}

// assertRejects runs Assert against a wrong expectation and requires a complaint.
func assertRejects(t *testing.T, what string, s harness.Subject, e harness.Expectation) {
	t.Helper()
	rec := &recordingT{}
	func() {
		defer func() {
			if p := recover(); p != nil {
				if _, ok := p.(fatalSentinel); !ok {
					panic(p)
				}
			}
		}()
		harness.Assert(rec, s, e)
	}()
	if len(rec.failures) == 0 {
		t.Errorf("the harness accepted a wrong expectation: %s\n"+
			"this dimension of the migrated scenario is vacuous", what)
		return
	}
	t.Logf("%s -> rejected: %s", what, strings.SplitN(rec.failures[0], "\n", 2)[0])
}

// TestTheMigratedScenariosAreNotVacuous mutates each pinned dimension.
func TestTheMigratedScenariosAreNotVacuous(t *testing.T) {
	// A wrong credential, the H1 subject.
	wrong := run(t, runOptions{port: portAMQPS, username: userApp,
		password: "definitely-not-the-password", tls: trustFixtureCA(t)})
	h1 := harness.Subject{
		Name: "H1", Report: wrong.Report(), Incomplete: wrong.Incomplete(),
		CredentialAttempts: attempts(1),
	}

	assertRejects(t, "H1 finding code", h1, harness.Expectation{
		RequireFindings: []domain.FindingCode{diagnosisrabbitmq.CodeVHostNotFound},
	})
	assertRejects(t, "H1 forbidden finding", h1, harness.Expectation{
		ForbidFindings: []domain.FindingCode{diagnosisrabbitmq.CodeCredentialsRejected},
	})
	assertRejects(t, "H1 node state", h1, harness.Expectation{
		Nodes: []harness.Node{
			{Step: stepAuth, State: domain.StatePass, FailureClass: domain.FailureNone},
		},
	})
	assertRejects(t, "H1 failure class", h1, harness.Expectation{
		Nodes: []harness.Node{
			{Step: stepAuth, State: domain.StateFail,
				FailureClass: domain.FailureAuthzDenied},
		},
	})
	assertRejects(t, "H1 incompleteness", h1, harness.Expectation{
		Incomplete: harness.Incomplete(),
	})
	assertRejects(t, "H1 credential bound", h1, harness.Expectation{
		MaxCredentialAttempts: attempts(0),
	})
	assertRejects(t, "H1 summary status", h1, harness.Expectation{
		Summary: harness.Status(domain.SummaryStatusOK),
	})
	assertRejects(t, "H1 absent step", h1, harness.Expectation{
		AbsentSteps: []domain.Step{stepAuth},
	})

	// A forbidden claim that the report genuinely does make, so ForbidProse
	// must catch it. The credential-rejection detail says "SASL PLAIN".
	assertRejects(t, "H1 forbidden prose", h1, harness.Expectation{
		ForbidProse: []string{"PLAIN"},
	})

	// H2, the vhost-not-found subject: the authorization outcome must not be
	// accepted as an authentication one.
	notFound := run(t, runOptions{port: portAMQPS, username: userApp,
		password: passApp, vhost: vhostAbsent, tls: trustFixtureCA(t)})
	h2 := harness.Subject{
		Name: "H2", Report: notFound.Report(), Incomplete: notFound.Incomplete(),
		CredentialAttempts: attempts(1),
	}
	assertRejects(t, "H2 collapsed onto access-refused", h2, harness.Expectation{
		RequireFindings: []domain.FindingCode{diagnosisrabbitmq.CodeVHostAccessRefused},
	})
	assertRejects(t, "H2 open-step failure class", h2, harness.Expectation{
		Nodes: []harness.Node{
			{Step: stepOpen, State: domain.StateFail,
				FailureClass: domain.FailureResourceLimitReached},
		},
	})

	// H5, the capacity ceiling: it must not be accepted as an authorization
	// denial, which is the single most misleading confusion in this service.
	limited := run(t, runOptions{port: portAMQPS, username: userApp,
		password: passApp, vhost: vhostLimit, tls: trustFixtureCA(t)})
	h5 := harness.Subject{
		Name: "H5", Report: limited.Report(), Incomplete: limited.Incomplete(),
		CredentialAttempts: attempts(1),
	}
	assertRejects(t, "H5 ceiling as denial", h5, harness.Expectation{
		RequireFindings: []domain.FindingCode{diagnosisrabbitmq.CodeVHostAccessRefused},
	})
	assertRejects(t, "H5 ceiling failure class", h5, harness.Expectation{
		Nodes: []harness.Node{
			{Step: stepOpen, State: domain.StateFail, FailureClass: domain.FailureAuthzDenied},
		},
	})

	// H4, the local timeout: it must not be accepted as a complete run.
	peer := newFakePeer(t, fakeSilent)
	slow := run(t, runOptions{
		host: "127.0.0.1", port: peer.port(), username: userApp, password: passApp,
		timeout: 12 * time.Second, stepTimeout: 3 * time.Second,
	})
	credentials, _ := peer.counts()
	h4 := harness.Subject{
		Name: "H4", Report: slow.Report(), Incomplete: slow.Incomplete(),
		CredentialAttempts: attempts(credentials),
	}
	assertRejects(t, "H4 timeout as complete", h4, harness.Expectation{
		Incomplete: harness.Complete(),
	})
	assertRejects(t, "H4 timeout as remote failure", h4, harness.Expectation{
		Nodes: []harness.Node{
			{Step: stepStart, State: domain.StateFail,
				FailureClass: domain.FailureExecLocalTimeout},
		},
	})

	// And the control: a correct expectation is accepted, so the recorder is
	// not simply complaining about everything.
	rec := &recordingT{}
	harness.Assert(rec, h1, harness.Expectation{
		RequireFindings: []domain.FindingCode{diagnosisrabbitmq.CodeCredentialsRejected},
		Incomplete:      harness.Complete(),
	})
	if len(rec.failures) != 0 {
		t.Errorf("the harness rejected a correct expectation: %v", rec.failures)
	}
}
