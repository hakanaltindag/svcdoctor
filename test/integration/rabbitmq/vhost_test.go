//go:build integration

package rabbitmq

import (
	"strings"
	"testing"

	rmqwire "github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq/wire"
	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// RAB-06 — the virtual host does not exist.
//
// Authentication succeeded, so this is an authorization-stage outcome and never
// a credential problem. The distinction is the whole reason ADR 0069 normalizes
// the reply text rather than reporting the reply code, which is 530 for every
// row in this file.
func TestRAB06VHostNotFound(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56671", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userApp, "--password", passApp, "--vhost", vhostAbsent)
	if !strings.Contains(truth, "OPEN_REFUSED code=530") {
		t.Fatalf("ground truth: %q, want OPEN_REFUSED code=530", truth)
	}
	if !strings.Contains(truth, "vhost "+vhostAbsent+" not found") {
		t.Fatalf("ground truth text changed: %q", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userApp,
		password: passApp, vhost: vhostAbsent, tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeVHostNotFound) {
		t.Fatalf("got %v, want RABBITMQ_VHOST_NOT_FOUND", codes(result))
	}
	if got := oneNodeAt(t, result, stepAuth).State(); got != domain.StatePass {
		t.Errorf("authentication = %s, want PASS: the credential was accepted", got)
	}
	open := oneNodeAt(t, result, stepOpen)
	if open.State() != domain.StateFail {
		t.Errorf("connection open = %s, want FAIL", open.State())
	}
	if got := attrText(t, open, servicerabbitmq.AttrCloseOutcome); got != string(rmqwire.CloseVHostNotFound) {
		t.Errorf("close outcome = %q, want %s", got, rmqwire.CloseVHostNotFound)
	}
	if got := attrText(t, open, servicerabbitmq.AttrReplyCode); got != "530" {
		t.Errorf("reply code = %q, want 530", got)
	}
	assertNoRawPeerText(t, result, peerTextOf(truth))

	// The forbidden claim is misattribution, not the word "credential": the
	// report says the credential *was accepted*, which is a disclaimer and
	// exactly what this outcome needs to state.
	lower := strings.ToLower(reportText(result))
	for _, blame := range []string{
		"credential was rejected", "credentials were rejected",
		"authentication failed", "wrong password", "check your password",
	} {
		if strings.Contains(lower, blame) {
			t.Errorf("an authorization outcome was attributed to authentication: %q", blame)
		}
	}
}

// RAB-07 — the identity authenticated and is not permitted in the virtual host.
//
// It must not collapse into RAB-06: "the vhost is missing" and "you may not use
// it" send an operator to two different places.
func TestRAB07VHostAccessRefused(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56671", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userNoPerm, "--password", passNoPerm)
	if !strings.Contains(truth, "refused for user '"+userNoPerm+"'") {
		t.Fatalf("ground truth: %q, want the bare vhost-denial sentence", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userNoPerm,
		password: passNoPerm, tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeVHostAccessRefused) {
		t.Fatalf("got %v, want RABBITMQ_VHOST_ACCESS_REFUSED", codes(result))
	}
	if hasCode(result, diagnosisrabbitmq.CodeVHostNotFound) {
		t.Error("a permission denial was reported as a missing virtual host")
	}
	if got := oneNodeAt(t, result, stepAuth).State(); got != domain.StatePass {
		t.Errorf("authentication = %s, want PASS", got)
	}
	open := oneNodeAt(t, result, stepOpen)
	if got := attrText(t, open, servicerabbitmq.AttrCloseOutcome); got != string(rmqwire.CloseVHostAccessRefused) {
		t.Errorf("close outcome = %q, want %s", got, rmqwire.CloseVHostAccessRefused)
	}
	assertNoRawPeerText(t, result, peerTextOf(truth))

	// The username is the operator's own input and may be carried, but the
	// peer's sentence about it may not.
	if strings.Contains(reportText(result), "doesn't have access") {
		t.Error("the peer's own phrasing reached the report")
	}
}

// RAB-21 — a capacity ceiling, which is not an authorization denial.
//
// The vhost's max-connections is 0 and the identity **is** permitted there, so
// the only difference from RAB-07 is the suffix RabbitMQ appends. Reporting this
// as a permission problem would send an operator to fix a grant that is already
// correct. RESOURCE_LIMIT_REACHED exists for exactly this.
func TestRAB21ResourceLimitReached(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56671", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userApp, "--password", passApp, "--vhost", vhostLimit)
	if !strings.Contains(truth, "connection limit (0) is reached") {
		t.Fatalf("ground truth: %q, want a connection-limit refusal", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userApp,
		password: passApp, vhost: vhostLimit, tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeConnectionNotPermitted) {
		t.Fatalf("got %v, want RABBITMQ_CONNECTION_NOT_PERMITTED", codes(result))
	}
	if hasCode(result, diagnosisrabbitmq.CodeVHostAccessRefused) {
		t.Error("a capacity ceiling was reported as a permission denial; the identity " +
			"is granted on this vhost and the grant is not the problem")
	}
	open := oneNodeAt(t, result, stepOpen)
	if got := attrText(t, open, servicerabbitmq.AttrCloseOutcome); got != string(rmqwire.CloseVHostConnectionLimit) {
		t.Errorf("close outcome = %q, want %s", got, rmqwire.CloseVHostConnectionLimit)
	}
	if got := open.FailureClass(); got != domain.FailureResourceLimitReached {
		t.Errorf("failure class = %s, want RESOURCE_LIMIT_REACHED", got)
	}
	assertNoRawPeerText(t, result, peerTextOf(truth))

	// The number the broker named is a fact about its configuration that
	// svcdoctor was not asked to report and cannot verify (ADR 0069).
	if strings.Contains(reportText(result), "(0)") {
		t.Error("the peer's configured limit value was carried into the report")
	}
	lower := strings.ToLower(reportText(result))
	for _, blame := range []string{
		"connection leak", "leaking", "too low", "increase the limit", "abnormal",
	} {
		if strings.Contains(lower, blame) {
			t.Errorf("the report interprets a capacity ceiling as %q", blame)
		}
	}
}

// The vhost is not part of the credential authority, and this is the scenario
// that proves it behaviourally.
//
// Connection.Start-Ok carries the credential and Connection.Open names the
// virtual host, in that order. A vhost-scoped authority would have to gate a
// transmission that already happened (ADR 0068 §6). So the same endpoint and the
// same credential across three different virtual hosts is **one** authentication
// authority and three separate authorization outcomes.
func TestVHostIsNotPartOfCredentialAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, vhost string
		wantAuth    domain.State
	}{
		{"default vhost", "/", domain.StatePass},
		{"absent vhost", vhostAbsent, domain.StatePass},
		{"capacity-limited vhost", vhostLimit, domain.StatePass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, runOptions{port: portAMQPS, username: userApp,
				password: passApp, vhost: tc.vhost, tls: trustFixtureCA(t)})

			if got := oneNodeAt(t, result, stepAuth).State(); got != tc.wantAuth {
				t.Errorf("authentication = %s, want %s: the vhost must not change "+
					"whether the credential was authorized", got, tc.wantAuth)
			}
			if hasCode(result, diagnosisrabbitmq.CodeCredentialWithheld) {
				t.Error("the credential was withheld because of the virtual host")
			}
			if hasCode(result, diagnosisrabbitmq.CodeCredentialsRejected) {
				t.Error("a virtual host outcome was attributed to the credential")
			}
		})
	}
}
