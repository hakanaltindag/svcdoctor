//go:build integration

package rabbitmq

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"

	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// assertCredentialNeverLeftTheProcess is the shared obligation of every
// withheld-credential scenario.
//
// The report has to say zero bytes were sent, the journey has to stop before the
// protocol could have carried them, and the password itself must appear nowhere.
func assertCredentialNeverLeftTheProcess(t *testing.T, result app.Result, secret string) {
	t.Helper()
	if !hasCode(result, diagnosisrabbitmq.CodeCredentialWithheld) {
		t.Fatalf("got %v, want RABBITMQ_CREDENTIAL_WITHHELD", codes(result))
	}
	if hasNodeAt(t, result, stepOpen) {
		t.Error("a connection was opened on a channel the credential was withheld from")
	}
	if strings.Contains(reportText(result), secret) {
		t.Error("the credential appears in the report")
	}
	if auth := nodesAt(t, result, stepAuth); len(auth) == 1 {
		if got := auth[0].State(); got != domain.StateSkipped {
			t.Errorf("authentication = %s, want SKIPPED: policy refused before the wire", got)
		}
	}
}

// RAB-12 — a plaintext channel, and a credential that therefore stays put.
//
// This is policy, not a failure of the endpoint: the broker is healthy and
// answered everything below authentication. `RequireVerifiedTLS` is the zero
// value, so a caller that never set a policy refuses rather than permits.
func TestRAB12PlaintextCredentialWithheld(t *testing.T) {
	const secret = "app-pw"

	truth := groundTruthJourney(t, "--port", "56672", "--user", userApp,
		"--password", passApp)
	if !strings.HasPrefix(truth, "OPEN_OK") {
		t.Fatalf("ground truth: the plaintext listener answered %q; the broker must be "+
			"healthy or this scenario measures the wrong refusal", truth)
	}

	result := run(t, runOptions{port: portAMQP, username: userApp, password: secret})

	assertCredentialNeverLeftTheProcess(t, result, secret)

	// Everything below authentication was still measured, and the report must
	// say so rather than implying the endpoint was unreachable.
	if got := oneNodeAt(t, result, stepStart).State(); got != domain.StatePass {
		t.Errorf("connection start = %s, want PASS", got)
	}
	if hasNodeAt(t, result, stepTLS) {
		t.Error("a plaintext run recorded a TLS handshake node")
	}
	lower := strings.ToLower(reportText(result))
	for _, blame := range []string{"unreachable", "endpoint refused", "rejected the credential"} {
		if strings.Contains(lower, blame) {
			t.Errorf("a policy refusal was described as a target problem: %q", blame)
		}
	}
}

// RAB-13 — `--tls-insecure`, which is encryption without identity.
//
// ADR 0068 §5 admits no opt-in: an unverified peer is not the peer the operator
// meant, so the credential is withheld exactly as it is on plaintext. Neither a
// loopback address nor a private one changes that.
func TestRAB13InsecureTLSCredentialWithheld(t *testing.T) {
	const secret = "app-pw"

	result := run(t, runOptions{
		port: portAMQPS, username: userApp, password: secret,
		tls: &transport.TLSOptions{ServerName: serverName, InsecureSkipVerify: true},
	})

	assertCredentialNeverLeftTheProcess(t, result, secret)

	// The handshake itself succeeded — that is the point. Encryption happened;
	// identity did not.
	if got := oneNodeAt(t, result, stepTLS).State(); got != domain.StatePass {
		t.Errorf("tls = %s: the handshake completed, only verification was skipped", got)
	}
	text := reportText(result)
	if !strings.Contains(strings.ToLower(text), "verif") {
		t.Error("the report does not say verification is what was missing")
	}
	if strings.Contains(strings.ToLower(text), "the endpoint is verified") {
		t.Error("an unverified channel was described as verified")
	}
}

// RAB-08 — a certificate signed by an authority the run does not trust.
//
// The credential must not be sent, and the run must not claim the peer is
// someone: a chain that does not build says nothing about identity (ADR 0058).
func TestRAB08TLSUnknownAuthority(t *testing.T) {
	const secret = "app-pw"

	result := run(t, runOptions{
		port: portAMQPS, username: userApp, password: secret, tls: trustRogueCA(t),
	})

	if got := oneNodeAt(t, result, stepTLS).State(); got != domain.StateFail {
		t.Fatalf("tls = %s, want FAIL against an untrusted authority", got)
	}
	if hasNodeAt(t, result, stepStart) {
		t.Error("the protocol exchange continued past a failed handshake")
	}
	if strings.Contains(reportText(result), secret) {
		t.Error("the credential appears in the report")
	}
	if got := oneNodeAt(t, result, stepTCP).State(); got != domain.StatePass {
		t.Errorf("tcp = %s: the connection itself succeeded", got)
	}
	lower := strings.ToLower(reportText(result))
	for _, blame := range []string{"expired", "hostname", "wrong name"} {
		if strings.Contains(lower, blame) {
			t.Errorf("an unknown-authority failure was described as %q", blame)
		}
	}
}

// RAB-09 — a chain that builds, for an identity the run did not ask for.
//
// Trust and identity are different questions (ADR 0058), and this is the pair
// that proves svcdoctor keeps them apart: the same certificate and the same CA
// as RAB-01, failing only because the requested name is not in its SAN set.
func TestRAB09TLSHostnameMismatch(t *testing.T) {
	const secret = "app-pw"

	result := run(t, runOptions{
		port: portAMQPS, username: userApp, password: secret,
		tls: &transport.TLSOptions{
			ServerName: "not-the-name-on-the-certificate.svcdoctor.test",
			RootCAs:    poolFrom(t, certPath),
		},
	})

	if got := oneNodeAt(t, result, stepTLS).State(); got != domain.StateFail {
		t.Fatalf("tls = %s, want FAIL for an identity mismatch", got)
	}
	if hasNodeAt(t, result, stepAuth) {
		t.Error("authentication was attempted over an unverified channel")
	}
	if strings.Contains(reportText(result), secret) {
		t.Error("the credential appears in the report")
	}
	lower := strings.ToLower(reportText(result))
	if strings.Contains(lower, "unknown authority") || strings.Contains(lower, "untrusted") {
		t.Error("an identity mismatch was described as a trust failure; the chain built")
	}
}

// RAB-20 — a plaintext AMQP listener asked for TLS.
//
// The handshake cannot complete because the peer answers AMQP, not TLS. The run
// must not report this as a certificate problem, and must not fall back to
// plaintext: a fallback would put the operator's credential somewhere they did
// not ask for it to go.
func TestRAB20PlaintextPortTargetedAsTLS(t *testing.T) {
	const secret = "app-pw"

	result := run(t, runOptions{
		port: portAMQP, username: userApp, password: secret, tls: trustFixtureCA(t),
	})

	if got := oneNodeAt(t, result, stepTLS).State(); got != domain.StateFail {
		t.Fatalf("tls = %s, want FAIL against a plaintext listener", got)
	}
	if hasNodeAt(t, result, stepStart) {
		t.Error("svcdoctor fell back to plaintext after the handshake failed")
	}
	if strings.Contains(reportText(result), secret) {
		t.Error("the credential appears in the report")
	}
	lower := strings.ToLower(reportText(result))
	for _, wrong := range []string{"expired", "unknown authority", "hostname"} {
		if strings.Contains(lower, wrong) {
			t.Errorf("a non-TLS peer was described as a certificate problem: %q", wrong)
		}
	}
}
