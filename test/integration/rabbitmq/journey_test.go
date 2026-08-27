//go:build integration

package rabbitmq

import (
	"strings"
	"testing"

	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// RAB-01 / RAB-02 — the healthy verified-TLS path with a correct credential.
//
// This is the scenario the whole phase exists to make true: DNS is absent
// because the target is a literal, TCP and TLS pass, the protocol exchange
// completes, the credential is accepted and the virtual host opens. Anything
// weaker than Connection.Open-Ok is not success (ADR 0067 §2).
func TestRAB01And02HealthyVerifiedTLS(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56671", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userApp, "--password", passApp)
	if !strings.HasPrefix(truth, "OPEN_OK") {
		t.Fatalf("ground truth: the broker answered %q, want OPEN_OK", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userApp,
		password: passApp, tls: trustFixtureCA(t)})

	for _, step := range []domain.Step{stepTCP, stepTLS, stepStart, stepAuth, stepOpen} {
		if got := oneNodeAt(t, result, step).State(); got != domain.StatePass {
			t.Errorf("%s state = %s, want PASS", step, got)
		}
	}
	if hasNodeAt(t, result, stepDNS) {
		t.Error("an address literal produced a dns.lookup node; ADR 0059 records none at all")
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", result.Report().Summary().Status())
	}
	if result.Incomplete() {
		t.Error("a complete run reported incomplete")
	}
	if len(result.Report().Findings()) != 0 {
		t.Errorf("a healthy path produced findings %v; a passing probe is the node, "+
			"not a finding", codes(result))
	}

	// The frozen negotiation window, asserted against a real broker rather than
	// against the constant that produced it (ADR 0070).
	open := oneNodeAt(t, result, stepOpen)
	auth := oneNodeAt(t, result, stepAuth)
	for _, tc := range []struct {
		node domain.Evidence
		key  domain.AttributeKey
		want string
	}{
		{auth, servicerabbitmq.AttrChannelMaxSelected, "1"},
		{auth, servicerabbitmq.AttrFrameMaxSelected, "8192"},
		{auth, servicerabbitmq.AttrHeartbeatSelected, "0"},
		{auth, servicerabbitmq.AttrChannelMaxOffered, "2047"},
		{auth, servicerabbitmq.AttrFrameMaxOffered, "131072"},
		{auth, servicerabbitmq.AttrHeartbeatOffered, "60"},
	} {
		if got := attrText(t, tc.node, tc.key); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
		}
	}
	if got := attrText(t, open, servicerabbitmq.AttrGracefulClose); got != "true" {
		t.Errorf("graceful close = %q, want true", got)
	}
	if got, _ := attrOf(t, oneNodeAt(t, result, stepStart),
		servicerabbitmq.AttrProduct); got != "RabbitMQ" {
		t.Errorf("product = %q, want RabbitMQ", got)
	}

	// The mechanism set is svcdoctor's own normalized constants, sorted — never
	// the peer's bytes and never the peer's order (ADR 0067 §4.2).
	mechs, _ := attrOf(t, oneNodeAt(t, result, stepStart), servicerabbitmq.AttrMechanismsOffered)
	if mechs != "AMQPLAIN ANONYMOUS PLAIN" {
		t.Errorf("mechanisms offered = %q, want the sorted normalized set", mechs)
	}
	if !strings.Contains(truth, "ANONYMOUS PLAIN AMQPLAIN") {
		t.Errorf("ground truth no longer offers the order this scenario normalizes: %q", truth)
	}
}

// RAB-00 — no credential configured.
//
// The three facts ADR 0069 keeps separate must stay separate: a WARN finding, an
// OK summary and a complete run, with no session. Exit code 0.
func TestRAB00NoCredentialConfigured(t *testing.T) {
	result := run(t, runOptions{port: portAMQPS, tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeCredentialNotConfigured) {
		t.Fatalf("no credential-not-configured finding; got %v", codes(result))
	}
	f := findingFor(t, result, diagnosisrabbitmq.CodeCredentialNotConfigured)
	if f.Severity() != domain.SeverityWarn {
		t.Errorf("severity = %s, want WARN", f.Severity())
	}
	if f.Kind() != domain.FindingKindConfirmed {
		t.Errorf("kind = %s, want CONFIRMED", f.Kind())
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK: a run given nothing to present proved no "+
			"target-side problem", result.Report().Summary().Status())
	}
	if result.Incomplete() {
		t.Error("a run that was given no credential is complete, not incomplete")
	}
	if hasNodeAt(t, result, stepOpen) {
		t.Error("no session may exist when nothing was presented")
	}
	if got := oneNodeAt(t, result, stepStart).State(); got != domain.StatePass {
		t.Errorf("connection start = %s, want PASS: everything below authentication "+
			"was still measured", got)
	}
	// The remediation must name only sources that exist.
	text := reportText(result)
	if strings.Contains(text, "--password-env") {
		t.Error("the remediation names --password-env, which is not a flag")
	}
	if !strings.Contains(text, "--password-file") {
		t.Error("the remediation does not name a credential source that exists")
	}
}

// RAB-03 / RAB-04 — a wrong password and an unknown user.
//
// Phase 8.0C measured these producing byte-identical frames, and this asserts
// svcdoctor does not invent a distinction the wire does not carry. Both are
// CREDENTIALS_REJECTED and neither names a cause.
func TestRAB03And04WrongPasswordAndUnknownUser(t *testing.T) {
	cases := []struct {
		name, user, password string
	}{
		{"wrong password", userApp, "definitely-not-the-password"},
		{"unknown user", "no-such-user", "irrelevant"},
	}

	var seen []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			truth := groundTruthJourney(t, "--port", "56671", "--tls",
				"--ca", "certs/server.crt", "--server-name", serverName,
				"--user", tc.user, "--password", tc.password)
			if !strings.HasPrefix(truth, "AUTH_REFUSED code=403") {
				t.Fatalf("ground truth: %q, want AUTH_REFUSED code=403", truth)
			}
			seen = append(seen, truth)

			result := run(t, runOptions{port: portAMQPS, username: tc.user,
				password: tc.password, tls: trustFixtureCA(t)})

			if !hasCode(result, diagnosisrabbitmq.CodeCredentialsRejected) {
				t.Fatalf("got %v, want RABBITMQ_CREDENTIALS_REJECTED", codes(result))
			}
			if got := oneNodeAt(t, result, stepAuth).State(); got != domain.StateFail {
				t.Errorf("authentication state = %s, want FAIL", got)
			}
			if hasNodeAt(t, result, stepOpen) {
				t.Error("Connection.Open was reached after authentication failed")
			}
			if result.Incomplete() {
				t.Error("a refusal svcdoctor observed is a complete run")
			}
			assertNoRawPeerText(t, result, peerTextOf(truth))

			// The forbidden claim: neither case may be attributed to a cause the
			// broker deliberately withheld.
			lower := strings.ToLower(reportText(result))
			for _, blame := range []string{
				"password is wrong", "incorrect password", "user does not exist",
				"no such user", "unknown user",
			} {
				if strings.Contains(lower, blame) {
					t.Errorf("the report claims %q, which the wire does not distinguish", blame)
				}
			}
		})
	}

	if len(seen) == 2 {
		a := strings.TrimPrefix(seen[0], "AUTH_REFUSED ")
		b := strings.TrimPrefix(seen[1], "AUTH_REFUSED ")
		if a != b {
			t.Errorf("the broker distinguished the two conditions on the wire:\n  %s\n  %s\n"+
				"ADR 0068 §4 rests on them being byte-identical", a, b)
		}
	}
}

// RAB-05 — the `guest` remote restriction, and why it is a hypothesis.
//
// The fixture restores RabbitMQ's real default, so `guest` with its **correct**
// password is refused from a non-loopback address. The measured point is that
// the refusal is byte-identical to a wrong password: svcdoctor cannot know which
// applied, so the guest sentence is a hint gated on the username alone and never
// a confirmed cause (ADR 0068 §4.1).
func TestRAB05GuestRemoteRestrictionShape(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56671", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", "guest", "--password", "guest")
	if !strings.HasPrefix(truth, "AUTH_REFUSED code=403") {
		t.Fatalf("ground truth: guest answered %q; the fixture must restrict guest "+
			"to loopback for this scenario to measure anything", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: "guest",
		password: "guest", tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeCredentialsRejected) {
		t.Fatalf("got %v, want RABBITMQ_CREDENTIALS_REJECTED", codes(result))
	}
	f := findingFor(t, result, diagnosisrabbitmq.CodeCredentialsRejected)
	if f.Kind() != domain.FindingKindConfirmed {
		t.Errorf("kind = %s: the refusal itself was observed", f.Kind())
	}
	text := strings.ToLower(f.Summary() + " " + f.Detail())
	if !strings.Contains(text, "guest") {
		t.Error("the guest sentence is absent for an identity of exactly `guest`")
	}
	// It must read as a possibility, not a diagnosis: svcdoctor cannot see the
	// address the broker judged.
	for _, overclaim := range []string{
		"because you connected remotely",
		"guest is restricted to loopback, which is why",
		"the cause is",
	} {
		if strings.Contains(text, overclaim) {
			t.Errorf("the guest sentence asserts a cause: %q", overclaim)
		}
	}
	assertNoRawPeerText(t, result, peerTextOf(truth))

	// And it must be gated on the username only — a different user gets no
	// guest sentence even though the wire bytes are identical.
	other := run(t, runOptions{port: portAMQPS, username: userApp,
		password: "definitely-not-the-password", tls: trustFixtureCA(t)})
	otherText := strings.ToLower(reportText(other))
	if strings.Contains(otherText, "guest") {
		t.Error("the guest sentence appeared for an identity that is not `guest`")
	}
}
