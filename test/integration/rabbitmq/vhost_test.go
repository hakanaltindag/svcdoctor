//go:build integration

package rabbitmq

import (
	"strings"
	"testing"

	rmqwire "github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq/wire"
	"github.com/hakanaltindag/svcdoctor/internal/app"
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

	// Phase 10.8B: the canonical explanation names which ceiling this was.
	//
	// Before this phase the finding said *"Where the endpoint named a capacity
	// ceiling…"* and recommended reviewing node, virtual host **and** user
	// limits — for a refusal whose evidence had already identified the virtual
	// host. The scope is what the operator acts on: this one affects one tenant,
	// where a node ceiling affects every client on the broker.
	assertCapacityScope(t, result, "virtual host")

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

// RAB-26 — a node-wide capacity ceiling, on a broker that has one.
//
// The scope matters more here than anywhere else in this file: a node ceiling is
// reached by **every** client at once, so an operator who reads it as their own
// application's problem looks in the wrong place. svcdoctor knew which ceiling
// it was from the reply sentence and, until Phase 10.8B, said so nowhere.
//
// The broker is its own container with `connection_max = 0` because a node-wide
// setting cannot be applied to a node other scenarios use. Zero rather than a
// reached ceiling, so nothing is held open and nothing races.
func TestRAB26NodeConnectionLimit(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56683", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", "guest", "--password", "guest", "--vhost", "/")
	if !strings.Contains(truth, "node connection limit (0) is reached") {
		t.Fatalf("ground truth: %q, want a node connection-limit refusal", truth)
	}

	result := run(t, runOptions{port: portNodeLimit, username: "guest",
		password: "guest", vhost: "/", tls: trustFixtureCA(t)})

	assertCapacityFinding(t, result, truth, rmqwire.CloseNodeConnectionLimit, "node")

	// A node ceiling is the one an operator is most likely to over-read. It says
	// this node refused this attempt, and nothing about a cluster.
	//
	// Scoped to the explanation rather than to the whole report, deliberately.
	// The report legitimately contains the word "cluster" — RabbitMQ reports a
	// `cluster_name` and the terminal renders it as an observation, which
	// predates this phase and is not a claim. A repository-wide keyword scan
	// would fail on that and teach nothing.
	lower := strings.ToLower(findingDetail(t, result))
	for _, overclaim := range []string{"cluster", "every client", "all clients", "globally"} {
		if strings.Contains(lower, overclaim) {
			t.Errorf("the explanation generalizes a node ceiling as %q", overclaim)
		}
	}
}

// RAB-27 — a per-user capacity ceiling.
//
// The third scope, and the one whose next action differs most: a user ceiling
// usually means this application's own connections, where a virtual host ceiling
// is the tenant's and a node ceiling is the broker's. It runs against the
// scenario broker, because a per-user limit affects only that principal — which
// is why `ulimit` exists and `app` is untouched.
func TestRAB27UserConnectionLimit(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56671", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userLimit, "--password", passLimit, "--vhost", "/")
	if !strings.Contains(truth, "user connection limit (0) is reached") {
		t.Fatalf("ground truth: %q, want a user connection-limit refusal", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userLimit,
		password: passLimit, vhost: "/", tls: trustFixtureCA(t)})

	assertCapacityFinding(t, result, truth, rmqwire.CloseUserConnectionLimit, "user")

	// The username is the operator's own input and is identity-classed; the
	// explanation is fixed prose and must not name it.
	if strings.Contains(findingDetail(t, result), userLimit) {
		t.Error("the explanation interpolated the principal name")
	}
}

// assertCapacityFinding is the shared body of the three capacity scenarios.
//
// It asserts the whole chain each one exists to prove: the closed outcome the
// wire package produced, the failure class the adapter derived, the finding code
// that has always owned it, and the canonical explanation Phase 10.8B added —
// plus everything that must **not** have moved.
func assertCapacityFinding(
	t *testing.T, result app.Result, truth string,
	want rmqwire.CloseOutcome, scope string,
) {
	t.Helper()

	if !hasCode(result, diagnosisrabbitmq.CodeConnectionNotPermitted) {
		t.Fatalf("got %v, want RABBITMQ_CONNECTION_NOT_PERMITTED", codes(result))
	}
	if hasCode(result, diagnosisrabbitmq.CodeVHostAccessRefused) {
		t.Error("a capacity ceiling was reported as a permission denial")
	}

	open := oneNodeAt(t, result, stepOpen)
	if got := attrText(t, open, servicerabbitmq.AttrCloseOutcome); got != string(want) {
		t.Errorf("close outcome = %q, want %s", got, want)
	}
	if got := open.FailureClass(); got != domain.FailureResourceLimitReached {
		t.Errorf("failure class = %s, want RESOURCE_LIMIT_REACHED", got)
	}

	assertCapacityScope(t, result, scope)
	assertNoRawPeerText(t, result, peerTextOf(truth))

	// The limit value the peer named is its configuration, not svcdoctor's
	// finding (ADR 0069).
	if strings.Contains(reportText(result), "(0)") {
		t.Error("the peer's configured limit value was carried into the report")
	}
	lower := strings.ToLower(reportText(result))
	for _, blame := range []string{
		"connection leak", "leaking", "too low", "increase the limit", "abnormal",
		"exhausted", "misconfigur", "overload",
	} {
		if strings.Contains(lower, blame) {
			t.Errorf("the report interprets a capacity ceiling as %q", blame)
		}
	}
}

// assertCapacityScope pins the one sentence Phase 10.8B added, and pins that the
// other two scopes are absent.
//
// Naming the wrong ceiling is the failure mode this phase created, so "contains
// the right scope" is not enough on its own.
func assertCapacityScope(t *testing.T, result app.Result, scope string) {
	t.Helper()

	detail := findingDetail(t, result)
	want := "The endpoint named a connection limit scoped to the " + scope + "."
	if !strings.Contains(detail, want) {
		t.Errorf("the explanation does not name the %s scope.\ngot: %q", scope, detail)
	}
	for _, other := range []string{"node", "virtual host", "user"} {
		if other == scope {
			continue
		}
		if strings.Contains(detail, "scoped to the "+other+".") {
			t.Errorf("a %s ceiling also named the %s scope", scope, other)
		}
	}
	// The generic hedge is what the specific sentence replaces.
	if strings.Contains(detail, "Where the endpoint named a capacity ceiling") {
		t.Error("the generic hedge survived beside the specific sentence")
	}
	// And the impermanence sentence is what it must not replace.
	if !strings.Contains(detail, "a second run a moment later may succeed") {
		t.Error("the impermanence sentence was dropped")
	}
}

// findingDetail returns the canonical Detail of the connection-not-permitted
// finding.
func findingDetail(t *testing.T, result app.Result) string {
	t.Helper()
	for _, f := range result.Report().Findings() {
		if f.Code() == diagnosisrabbitmq.CodeConnectionNotPermitted {
			return f.Detail()
		}
	}
	t.Fatalf("no RABBITMQ_CONNECTION_NOT_PERMITTED finding: %v", codes(result))
	return ""
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
