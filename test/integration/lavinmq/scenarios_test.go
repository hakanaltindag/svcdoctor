//go:build integration

package lavinmq

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	rmqwire "github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq/wire"
	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// LMQ-00 / LMQ-02 / LMQ-08 — the healthy path, over TLS, with a correct
// credential.
//
// `Connection.Open-Ok` means exactly what it means against RabbitMQ: this
// endpoint answered for the requested virtual host on this connection. The
// terminal claim does not widen or narrow because the implementation differs.
func TestLMQ00And02And08HealthyVerifiedTLS(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56681", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userDefault, "--password", passDefault)
	if !strings.HasPrefix(truth, "OPEN_OK") {
		t.Fatalf("ground truth: %q, want OPEN_OK", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userDefault,
		password: passDefault, tls: trustFixtureCA(t)})

	for _, step := range []domain.Step{stepTCP, stepTLS, stepStart, stepAuth, stepOpen} {
		if got := oneNodeAt(t, result, step).State(); got != domain.StatePass {
			t.Errorf("%s state = %s, want PASS", step, got)
		}
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", result.Report().Summary().Status())
	}
	if len(result.Report().Findings()) != 0 {
		t.Errorf("a healthy path produced findings %v", codes(result))
	}

	// The frozen negotiation window is svcdoctor's, not the peer's. LavinMQ
	// offers 2048/131072/300 where RabbitMQ offers 2047/131072/60, and
	// svcdoctor selects the same three values against both.
	auth := oneNodeAt(t, result, stepAuth)
	for _, tc := range []struct {
		key  domain.AttributeKey
		want string
	}{
		{servicerabbitmq.AttrChannelMaxSelected, "1"},
		{servicerabbitmq.AttrFrameMaxSelected, "8192"},
		{servicerabbitmq.AttrHeartbeatSelected, "0"},
		{servicerabbitmq.AttrChannelMaxOffered, "2048"},
		{servicerabbitmq.AttrHeartbeatOffered, "300"},
	} {
		if got := attrText(t, auth, tc.key); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
		}
	}
	if got := attrText(t, oneNodeAt(t, result, stepOpen),
		servicerabbitmq.AttrGracefulClose); got != "true" {
		t.Errorf("graceful close = %q, want true", got)
	}
}

// LMQ-01 — the product identity is observed and reported, and drives nothing.
func TestLMQ01ProductIdentityIsLavinMQ(t *testing.T) {
	result := run(t, runOptions{port: portAMQPS, username: userDefault,
		password: passDefault, tls: trustFixtureCA(t)})

	start := oneNodeAt(t, result, stepStart)
	if got := attrText(t, start, servicerabbitmq.AttrProduct); got != "LavinMQ" {
		t.Errorf("product = %q, want LavinMQ", got)
	}
	if got := attrText(t, start, servicerabbitmq.AttrVersion); got == "" {
		t.Error("no version was observed")
	}
	// LavinMQ reports no cluster_name. Its absence is a fact, not a failure.
	if got := attrText(t, start, servicerabbitmq.AttrClusterName); got != "" {
		t.Logf("cluster name = %q (LavinMQ reported one)", got)
	}
}

// LMQ-03 — a rejected credential.
//
// LavinMQ answers 403 with class/method **10/11** and a 17-byte reply text,
// where RabbitMQ answers 403 with **0/0** and 108 bytes. Neither difference may
// change the attribution: svcdoctor's own handshake state decides which stage
// failed, and the peer's class/method is corroboration only (ADR 0069 §1).
func TestLMQ03CredentialRejected(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56681", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userDefault, "--password", "definitely-not-the-password")
	if !strings.Contains(truth, "cm=10/11") {
		t.Fatalf("ground truth: %q, want LavinMQ's 10/11 attribution", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userDefault,
		password: "definitely-not-the-password", tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeCredentialsRejected) {
		t.Fatalf("got %v, want RABBITMQ_CREDENTIALS_REJECTED", codes(result))
	}
	auth := oneNodeAt(t, result, stepAuth)
	if auth.State() != domain.StateFail {
		t.Errorf("authentication = %s, want FAIL", auth.State())
	}
	if got := auth.FailureClass(); got != domain.FailureAuthCredentialsRejected {
		t.Errorf("failure class = %s, want AUTH_CREDENTIALS_REJECTED", got)
	}
	if hasNodeAt(t, result, stepOpen) {
		t.Error("Connection.Open was reached after authentication failed")
	}
	assertNoRawPeerText(t, result, peerTextOf(truth))
}

// LMQ-04 — the virtual host does not exist.
//
// LavinMQ's sentence names **no vhost** where RabbitMQ interpolates one, so the
// normalizer's candidate is a constant rather than a rendering. Same outcome,
// different template, and the difference stays inside the wire package.
func TestLMQ04VHostNotFound(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56681", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userDefault, "--password", passDefault, "--vhost", vhostAbsent)
	if !strings.Contains(truth, "text=NOT_ALLOWED - vhost not found") {
		t.Fatalf("ground truth: %q, want LavinMQ's vhost-not-found sentence", truth)
	}
	if strings.Contains(truth, vhostAbsent+" not found") {
		t.Fatal("LavinMQ now names the vhost; the L1 template assumes it does not")
	}

	result := run(t, runOptions{port: portAMQPS, username: userDefault,
		password: passDefault, vhost: vhostAbsent, tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeVHostNotFound) {
		t.Fatalf("got %v, want RABBITMQ_VHOST_NOT_FOUND", codes(result))
	}
	open := oneNodeAt(t, result, stepOpen)
	if got := attrText(t, open, servicerabbitmq.AttrCloseOutcome); got != string(rmqwire.CloseVHostNotFound) {
		t.Errorf("close outcome = %q, want %s", got, rmqwire.CloseVHostNotFound)
	}
	if got := oneNodeAt(t, result, stepAuth).State(); got != domain.StatePass {
		t.Errorf("authentication = %s, want PASS", got)
	}
	assertNoRawPeerText(t, result, peerTextOf(truth))
}

// LMQ-05 — the identity is not permitted in the virtual host.
//
// LavinMQ reverses the operands relative to RabbitMQ: `'<user>' doesn't have
// access to '<vhost>'`. The normalizer renders that candidate from svcdoctor's
// own inputs and compares for equality, so the reversal is measured rather than
// pattern-matched.
func TestLMQ05VHostAccessDenied(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56681", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userNoPerm, "--password", passNoPerm)
	if !strings.Contains(truth, "doesn't have access") {
		t.Fatalf("ground truth: %q, want LavinMQ's access-denied sentence", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userNoPerm,
		password: passNoPerm, tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeVHostAccessRefused) {
		t.Fatalf("got %v, want RABBITMQ_VHOST_ACCESS_REFUSED", codes(result))
	}
	if hasCode(result, diagnosisrabbitmq.CodeVHostNotFound) {
		t.Error("a permission denial was reported as a missing virtual host")
	}
	open := oneNodeAt(t, result, stepOpen)
	if got := attrText(t, open, servicerabbitmq.AttrCloseOutcome); got != string(rmqwire.CloseVHostAccessRefused) {
		t.Errorf("close outcome = %q, want %s", got, rmqwire.CloseVHostAccessRefused)
	}
	assertNoRawPeerText(t, result, peerTextOf(truth))
}

// LMQ-06 — a capacity ceiling, normalized onto the shared class.
//
// Phase 8.0C could only derive this template from LavinMQ's source; no instance
// was ever measured under a connection limit. This scenario measures it. If the
// bytes had differed, the template would have been corrected against the
// measurement rather than the source, which is what ADR 0069 asks for.
func TestLMQ06ResourceLimitReached(t *testing.T) {
	truth := groundTruthJourney(t, "--port", "56681", "--tls",
		"--ca", "certs/server.crt", "--server-name", serverName,
		"--user", userDefault, "--password", passDefault, "--vhost", vhostLimit)
	if !strings.Contains(truth, "connection limit (0) is reached") {
		t.Fatalf("ground truth: %q, want a connection-limit refusal", truth)
	}

	result := run(t, runOptions{port: portAMQPS, username: userDefault,
		password: passDefault, vhost: vhostLimit, tls: trustFixtureCA(t)})

	if !hasCode(result, diagnosisrabbitmq.CodeConnectionNotPermitted) {
		t.Fatalf("got %v, want RABBITMQ_CONNECTION_NOT_PERMITTED", codes(result))
	}
	open := oneNodeAt(t, result, stepOpen)
	if got := attrText(t, open, servicerabbitmq.AttrCloseOutcome); got != string(rmqwire.CloseVHostConnectionLimit) {
		t.Errorf("close outcome = %q, want %s", got, rmqwire.CloseVHostConnectionLimit)
	}
	if got := open.FailureClass(); got != domain.FailureResourceLimitReached {
		t.Errorf("failure class = %s, want RESOURCE_LIMIT_REACHED", got)
	}
	if hasCode(result, diagnosisrabbitmq.CodeVHostAccessRefused) {
		t.Error("a capacity ceiling was reported as a permission denial")
	}
	assertNoRawPeerText(t, result, peerTextOf(truth))
}

// LMQ-07 — a plaintext channel withholds the credential, identically.
//
// The policy is the transport's, not the vendor's.
func TestLMQ07PlaintextCredentialWithheld(t *testing.T) {
	const secret = passDefault

	result := run(t, runOptions{port: portAMQP, username: userDefault, password: secret})

	if !hasCode(result, diagnosisrabbitmq.CodeCredentialWithheld) {
		t.Fatalf("got %v, want RABBITMQ_CREDENTIAL_WITHHELD", codes(result))
	}
	if hasNodeAt(t, result, stepOpen) {
		t.Error("a connection was opened on a channel the credential was withheld from")
	}
	if strings.Contains(reportText(result), secret) {
		t.Error("the credential appears in the report")
	}
	if got := oneNodeAt(t, result, stepStart).State(); got != domain.StatePass {
		t.Errorf("connection start = %s, want PASS: everything below authentication "+
			"was still measured", got)
	}
}

// The vendor-neutrality guard: there is no LavinMQ branch in the journey.
//
// Separate **measured normalization templates** are allowed and expected — they
// live in the wire package's close normalizer, which is the one place a vendor
// difference is a fact about bytes. Anything else keying on the product name
// would make the journey depend on what the peer calls itself, and a proxy may
// call itself anything at all.
func TestNoVendorBranchExistsInTheJourney(t *testing.T) {
	root := repoRoot(t)
	journeyFiles := []string{
		"internal/adapter/rabbitmq/connectionstart.go",
		"internal/adapter/rabbitmq/authenticate.go",
		"internal/adapter/rabbitmq/open.go",
		"internal/app/rabbitmq.go",
		"internal/diagnosis/rabbitmq/protocol.go",
		"internal/diagnosis/rabbitmq/authentication.go",
		"internal/diagnosis/rabbitmq/connectionopen.go",
	}
	for _, rel := range journeyFiles {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		code := stripComments(string(data))
		for _, vendor := range []string{"LavinMQ", "lavinmq", "Redpanda"} {
			if strings.Contains(code, vendor) {
				t.Errorf("%s branches on the vendor name %q; the journey is decided by "+
					"svcdoctor's own handshake state, never by what the peer calls itself",
					rel, vendor)
			}
		}
	}
}

// The normalizer is the one place a vendor difference may exist, and it must
// still be a comparison against svcdoctor's own rendering.
func TestVendorDifferencesLiveOnlyInTheCloseNormalizer(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "internal/adapter/rabbitmq/wire/close.go"))
	if err != nil {
		t.Fatalf("reading close.go: %v", err)
	}
	code := string(data)
	if !strings.Contains(code, `text == "NOT_ALLOWED - vhost not found"`) {
		t.Error("the LavinMQ vhost-not-found template is gone; LMQ-04 measured it live")
	}
	if strings.Contains(stripComments(code), "regexp") {
		t.Error("the normalizer uses a regular expression; ADR 0069 §3 fixes " +
			"construct-and-compare because two live defects were reproduced without it")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found")
		}
		dir = parent
	}
}

func stripComments(code string) string {
	var sb strings.Builder
	i := 0
	for i < len(code) {
		switch {
		case strings.HasPrefix(code[i:], "//"):
			j := strings.IndexByte(code[i:], '\n')
			if j < 0 {
				return sb.String()
			}
			i += j
		case strings.HasPrefix(code[i:], "/*"):
			j := strings.Index(code[i:], "*/")
			if j < 0 {
				return sb.String()
			}
			i += j + 2
		default:
			sb.WriteByte(code[i])
			i++
		}
	}
	return sb.String()
}
