//go:build integration

package kafka

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// `svcdoctor diagnose kafka`, as a real process, against the real cluster.
//
// # Why a subprocess rather than cli.App
//
// Everything else in this repository drives the command boundary in-process with
// injected writers, and that is right for testing routing and exit codes. It
// cannot test the two things a released binary is judged on: **the process's
// exit status**, and **what an operator actually sees on stdout and stderr**.
// Those come from cmd/svcdoctor's wiring — the signal context, os.Stdin, the
// os.Exit call — and a fake writer cannot reach them.
//
// The binary is built once, from this repository, into the test's temporary
// directory. It is never installed, and no test here depends on one being on
// PATH.

var (
	buildOnce  sync.Once
	binaryPath string
	buildErr   error
)

// svcdoctor returns the path to a freshly built binary.
func svcdoctor(t *testing.T) string {
	t.Helper()

	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "svcdoctor-cli")
		if err != nil {
			buildErr = err
			return
		}
		binaryPath = filepath.Join(dir, "svcdoctor")
		cmd := exec.Command("go", "build", "-o", binaryPath,
			"github.com/hakanaltindag/svcdoctor/cmd/svcdoctor")
		cmd.Dir = repoRoot()
		if out, berr := cmd.CombinedOutput(); berr != nil {
			buildErr = errBuild{out: string(out), err: berr}
		}
	})
	if buildErr != nil {
		t.Fatalf("building svcdoctor: %v", buildErr)
	}
	return binaryPath
}

type errBuild struct {
	out string
	err error
}

func (e errBuild) Error() string { return e.err.Error() + ": " + e.out }

// repoRoot returns the repository root, which is three directories up from
// test/integration/kafka.
func repoRoot() string { return filepath.Join("..", "..", "..") }

// invocation is one run of the binary.
type invocation struct {
	args   []string
	stdin  string
	code   int
	stdout string
	stderr string
}

// invoke runs the binary once and captures both streams and the exit status.
func invoke(t *testing.T, stdin string, args ...string) invocation {
	t.Helper()

	cmd := exec.Command(svcdoctor(t), args...)
	cmd.Dir = repoRoot()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut

	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errorsAs(err, &exit) {
			t.Fatalf("running svcdoctor %v: %v", args, err)
		}
		code = exit.ExitCode()
	}
	return invocation{
		args: args, stdin: stdin, code: code,
		stdout: out.String(), stderr: errOut.String(),
	}
}

func errorsAs(err error, target **exec.ExitError) bool {
	exit, ok := err.(*exec.ExitError)
	if ok {
		*target = exit
	}
	return ok
}

// kafkaArgs builds the flags every scenario shares.
func kafkaArgs(t *testing.T, mechanism string, extra ...string) []string {
	t.Helper()
	base := []string{
		"diagnose", "kafka",
		"--host", bootstrapHost,
		"--port", strconv.Itoa(bootstrapPort),
		"--sasl-mechanism", mechanism,
		"--tls-ca-file", filepath.Join("test", "integration", "kafka", "env", "certs", "ca-cert.pem"),
		"--timeout", "90s",
	}
	return append(base, extra...)
}

// secretFile writes credential material the binary can read.
func secretFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(contents+"\n"), 0o600); err != nil {
		t.Fatalf("writing the credential file: %v", err)
	}
	return path
}

// --- the scenarios ---------------------------------------------------------------

// TestCLIPlainSucceeds is the healthy PLAIN run, end to end through the binary.
func TestCLIPlainSucceeds(t *testing.T) {
	path := secretFile(t, saslSecret)
	got := invoke(t, "", kafkaArgs(t, "PLAIN",
		"--user", saslIdentity, "--password-file", path)...)

	requireArtifact(t, got)
	requireRow(t, got.stdout, "outcome", "Kafka metadata obtained")
	if !strings.Contains(got.stdout, "advertised broker endpoints reached") {
		t.Errorf("no topology line:\n%s", got.stdout)
	}
	// Three brokers in the fixture cluster, and every one of them advertises an
	// endpoint this vantage can reach.
	requireRow(t, got.stdout, "topology", "3 of 3 advertised broker endpoints reached")
	requireRow(t, got.stdout, "execution", "complete")
	if got.code != 0 {
		t.Errorf("exit = %d, want 0:\n%s\n%s", got.code, got.stdout, got.stderr)
	}
}

// TestCLIScramSucceeds is the same run over SCRAM-SHA-256.
//
// waitSCRAMReady is not optional here. cluster_test.go force-recreates brokers,
// which discards the KRaft metadata log and every SCRAM verifier with it, and a
// recreated broker warms its credential cache asynchronously after it starts
// answering. Without the wait this test authenticates against a broker that has
// the verifier written but not yet loaded, and the failure is indistinguishable
// from a wrong password — which is exactly how it presented when the ordering of
// the suite put a recreate before it.
func TestCLIScramSucceeds(t *testing.T) {
	waitSCRAMReady(t)

	path := secretFile(t, scramSecret)
	got := invoke(t, "", kafkaArgs(t, "SCRAM-SHA-256",
		"--user", scramIdentity, "--password-file", path)...)

	requireArtifact(t, got)
	requireRow(t, got.stdout, "outcome", "Kafka metadata obtained")
	if got.code != 0 {
		t.Errorf("exit = %d, want 0:\n%s\n%s", got.code, got.stdout, got.stderr)
	}
	// The secret never appears in what an operator sees.
	requireNoSecret(t, got, scramSecret)
}

// TestCLIWrongCredentialExitsOne is the target-side problem.
//
// The readiness wait matters as much here as in the success case, in the
// opposite direction: without it this test could pass because the credential
// cache was cold rather than because the password was wrong.
func TestCLIWrongCredentialExitsOne(t *testing.T) {
	waitSCRAMReady(t)

	path := secretFile(t, "definitely-not-the-scram-password")
	got := invoke(t, "", kafkaArgs(t, "SCRAM-SHA-256",
		"--user", scramIdentity, "--password-file", path)...)

	requireArtifact(t, got)
	if got.code != 1 {
		t.Errorf("exit = %d, want 1:\n%s", got.code, got.stdout)
	}
	requireRow(t, got.stdout, "outcome", "Kafka metadata NOT obtained")
	if !strings.Contains(got.stdout, "KAFKA_CREDENTIALS_REJECTED") {
		t.Errorf("the rejected credential is not reported:\n%s", got.stdout)
	}
	requireNoSecret(t, got, "definitely-not-the-scram-password")
}

// TestCLINoCredentialExitsZero is the load-bearing product invariant.
//
// The endpoint demands authentication, the run has none, nothing about the
// endpoint is broken. Status OK, a WARN, no metadata, and exit 0.
func TestCLINoCredentialExitsZero(t *testing.T) {
	got := invoke(t, "", kafkaArgs(t, "PLAIN")...)

	requireArtifact(t, got)
	if got.code != 0 {
		t.Errorf("exit = %d, want 0:\n%s", got.code, got.stdout)
	}
	requireRow(t, got.stdout, "status", "OK no target-side error was proven")
	requireRow(t, got.stdout, "outcome", "Kafka metadata NOT obtained")
	requireRow(t, got.stdout, "execution", "complete")
	if !strings.Contains(got.stdout, "KAFKA_CREDENTIAL_NOT_CONFIGURED") {
		t.Errorf("the missing credential is not reported:\n%s", got.stdout)
	}
	if !strings.Contains(got.stdout, "⚠ WARN") {
		t.Errorf("the finding is not marked as a warning:\n%s", got.stdout)
	}
}

// TestCLIUnsupportedMechanismExitsZero is the capability refusal.
//
// The broker offers SCRAM-SHA-512 or it does not; either way svcdoctor cannot
// perform it, says so, and sends no credential.
func TestCLIUnsupportedMechanismExitsZero(t *testing.T) {
	path := secretFile(t, saslSecret)
	got := invoke(t, "", kafkaArgs(t, "SCRAM-SHA-512",
		"--user", saslIdentity, "--password-file", path)...)

	requireArtifact(t, got)
	requireRow(t, got.stdout, "outcome", "Kafka metadata NOT obtained")
	// Either the listener does not offer it — an ERROR at exit 1 — or it does
	// and svcdoctor declines — INFO at exit 0. Both are truthful, and which one
	// the fixture produces depends on the broker's configuration, so the
	// assertion is that one of them happened and no credential was sent.
	switch {
	case strings.Contains(got.stdout, "KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR"):
		if got.code != 0 {
			t.Errorf("an unsupported mechanism exited %d, want 0:\n%s", got.code, got.stdout)
		}
	case strings.Contains(got.stdout, "KAFKA_AUTH_MECHANISM_NOT_OFFERED"):
		if got.code != 1 {
			t.Errorf("an unoffered mechanism exited %d, want 1:\n%s", got.code, got.stdout)
		}
	default:
		t.Errorf("neither refusal was reported:\n%s", got.stdout)
	}
	requireNoSecret(t, got, saslSecret)
}

// TestCLIRejectsALowercaseMechanism is ADR 0057 section 3, through the binary.
func TestCLIRejectsALowercaseMechanism(t *testing.T) {
	got := invoke(t, "", kafkaArgs(t, "scram-sha-256")...)

	if got.code != 2 {
		t.Errorf("exit = %d, want 2:\n%s\n%s", got.code, got.stdout, got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("a usage error wrote an artifact: %q", got.stdout)
	}
	if !strings.Contains(got.stderr, "SCRAM-SHA-256") {
		t.Errorf("the refusal does not name the registered spelling: %q", got.stderr)
	}
}

// TestCLIRequiresAMechanism proves there is no default in the shipped binary.
func TestCLIRequiresAMechanism(t *testing.T) {
	got := invoke(t, "",
		"diagnose", "kafka", "--host", bootstrapHost,
		"--port", strconv.Itoa(bootstrapPort))

	if got.code != 2 {
		t.Errorf("exit = %d, want 2", got.code)
	}
	if !strings.Contains(got.stderr, "--sasl-mechanism is required") {
		t.Errorf("the refusal does not name the flag: %q", got.stderr)
	}
}

// TestCLIReadsTheCredentialFromStdin covers the other allowed source.
func TestCLIReadsTheCredentialFromStdin(t *testing.T) {
	got := invoke(t, saslSecret+"\n", kafkaArgs(t, "PLAIN", "--user", saslIdentity,
		"--password-stdin")...)

	requireArtifact(t, got)
	requireRow(t, got.stdout, "outcome", "Kafka metadata obtained")
	if got.code != 0 {
		t.Errorf("exit = %d, want 0:\n%s", got.code, got.stdout)
	}
	requireNoSecret(t, got, saslSecret)
}

// TestCLIJSONIsTheCanonicalArtifact pins the machine form.
func TestCLIJSONIsTheCanonicalArtifact(t *testing.T) {
	path := secretFile(t, saslSecret)
	got := invoke(t, "", kafkaArgs(t, "PLAIN", "--user", saslIdentity,
		"--password-file", path, "--output", "json")...)

	if got.code != 0 {
		t.Fatalf("exit = %d:\n%s\n%s", got.code, got.stdout, got.stderr)
	}
	if !strings.HasPrefix(got.stdout, `{"schemaVersion":1`) {
		t.Errorf("the canonical JSON changed: %.80s", got.stdout)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got.stdout), &decoded); err != nil {
		t.Fatalf("the artifact is not valid JSON: %v", err)
	}
	if got := decoded["schemaVersion"]; got != float64(1) {
		t.Errorf("schemaVersion = %v, want 1", got)
	}
	if strings.Count(got.stdout, "\n") != 1 {
		t.Error("the JSON newline convention changed")
	}
	requireNoSecret(t, got, saslSecret)
}

// TestCLITextAndJSONAgree is the parity contract, measured twice against a live
// cluster.
func TestCLITextAndJSONAgree(t *testing.T) {
	path := secretFile(t, saslSecret)

	text := invoke(t, "", kafkaArgs(t, "PLAIN", "--user", saslIdentity,
		"--password-file", path)...)
	machine := invoke(t, "", kafkaArgs(t, "PLAIN", "--user", saslIdentity,
		"--password-file", path, "--output", "json")...)

	if text.code != machine.code {
		t.Errorf("text exit = %d, json exit = %d", text.code, machine.code)
	}

	var decoded struct {
		Summary struct {
			Status           string `json:"status"`
			FirstBrokenLayer string `json:"firstBrokenLayer"`
		} `json:"summary"`
		Findings []struct {
			Code string `json:"code"`
		} `json:"findings"`
		Security struct {
			OutputMode string `json:"outputMode"`
		} `json:"security"`
	}
	if err := json.Unmarshal([]byte(machine.stdout), &decoded); err != nil {
		t.Fatalf("decoding the artifact: %v", err)
	}
	for _, finding := range decoded.Findings {
		if !strings.Contains(text.stdout, finding.Code) {
			t.Errorf("the text form lost finding %s", finding.Code)
		}
	}
	if decoded.Security.OutputMode != "LOCAL_FULL" {
		t.Errorf("outputMode = %q, want LOCAL_FULL", decoded.Security.OutputMode)
	}
	if decoded.Summary.Status == "PROBLEMS_FOUND" &&
		!strings.Contains(text.stdout, "PROBLEMS FOUND") {
		t.Error("the two forms disagree about the status")
	}
}

// TestCLIShareableCarriesNoIdentity is redaction through the shipped binary.
func TestCLIShareableCarriesNoIdentity(t *testing.T) {
	path := secretFile(t, saslSecret)

	local := invoke(t, "", kafkaArgs(t, "PLAIN", "--user", saslIdentity,
		"--password-file", path)...)
	shared := invoke(t, "", kafkaArgs(t, "PLAIN", "--user", saslIdentity,
		"--password-file", path, "--shareable")...)

	if local.code != shared.code {
		t.Errorf("redaction changed the exit code: %d -> %d", local.code, shared.code)
	}
	if !strings.Contains(shared.stdout, "Shareable report") {
		t.Errorf("the shareable output does not announce itself:\n%s", shared.stdout)
	}
	// **saslIdentity is deliberately not swept for.** The fixture principal is
	// literally "svcdoctor", which is the tool's own name and appears in the
	// header line of every report; asserting its absence would fail on the
	// banner rather than on a leak. The PostgreSQL suite records the same hazard
	// from the other side, where a role named after the tool makes redaction
	// fail closed on purpose. What is swept for is the material that is
	// unambiguously identity or secret.
	for _, identity := range []string{bootstrapHost, saslSecret, "127.0.0.1", "[::1]"} {
		if strings.Contains(shared.stdout, identity) {
			t.Errorf("the shareable output carries %q:\n%s", identity, shared.stdout)
		}
	}
	// **The port survives, and it must.** A port selects a service; it does not
	// identify a host or an operator, and removing it would take the one fact
	// that lets a reader tell a broker's listener from its controller apart in a
	// report they were sent (ADR 0018: preserve correlation, remove identity).
	if !strings.Contains(shared.stdout, strconv.Itoa(bootstrapPort)) {
		t.Errorf("redaction removed the port, which is not identity:\n%s", shared.stdout)
	}
	// Identity is replaced by a stable pseudonym rather than deleted, so the
	// same endpoint reads as the same endpoint everywhere in the document.
	if !strings.Contains(shared.stdout, "host-") || !strings.Contains(shared.stdout, "ip-") {
		t.Errorf("redaction did not pseudonymize; correlation is lost:\n%s", shared.stdout)
	}
	// The diagnosis and the topology semantics survive.
	requireRow(t, shared.stdout, "outcome", "Kafka metadata obtained")
	if !strings.Contains(shared.stdout, "advertised broker endpoints reached") {
		t.Errorf("the shareable output lost the topology line:\n%s", shared.stdout)
	}
	// Correlation survives: the broker node identifiers are not identities and
	// stay, so a reader can still tell the three advertisements apart.
	for _, nodeID := range []string{"Advertised broker 1", "Advertised broker 2"} {
		if !strings.Contains(shared.stdout, nodeID) {
			t.Errorf("the shareable output lost broker correlation (%s):\n%s", nodeID, shared.stdout)
		}
	}
}

// TestCLIIncompleteExitsFour is svcdoctor's own budget expiring.
func TestCLIIncompleteExitsFour(t *testing.T) {
	got := invoke(t, "",
		"diagnose", "kafka", "--host", bootstrapHost,
		"--port", strconv.Itoa(bootstrapPort),
		"--sasl-mechanism", "PLAIN",
		"--tls-ca-file", filepath.Join("test", "integration", "kafka", "env", "certs", "ca-cert.pem"),
		// Far too short for a TLS handshake plus four exchanges plus a sweep of
		// three advertised endpoints. The whole-run budget is what expires, so
		// the run is incomplete whatever the cluster does — which is the point:
		// this asserts svcdoctor's own limit, not the target's behaviour.
		"--timeout", "5ms", "--step-timeout", "5ms")

	if got.code != 4 {
		t.Errorf("exit = %d, want 4:\n%s\n%s", got.code, got.stdout, got.stderr)
	}
	if got.stdout == "" {
		t.Fatal("an incomplete run wrote no report; a partial run must still produce one")
	}
	requireRow(t, got.stdout, "execution",
		"INCOMPLETE svcdoctor did not finish the intended measurement")
	// A local budget is never rendered as a remote failure.
	if strings.Contains(got.stdout, "✗ FAIL  TCP") {
		t.Errorf("a local timeout was reported as a connection failure:\n%s", got.stdout)
	}
}

// TestCLIAdvertisedEndpointsAreMeasuredNotAuthenticated is ADR 0050 in the
// shipped output.
func TestCLIAdvertisedEndpointsAreMeasuredNotAuthenticated(t *testing.T) {
	path := secretFile(t, saslSecret)
	got := invoke(t, "", kafkaArgs(t, "PLAIN", "--user", saslIdentity,
		"--password-file", path)...)

	requireArtifact(t, got)

	inside := false
	advertised := 0
	for _, line := range strings.Split(got.stdout, "\n") {
		switch {
		case strings.HasPrefix(line, "  Advertised broker"):
			inside = true
			advertised++
		case line == "Findings":
			inside = false
		}
		if !inside {
			continue
		}
		for _, forbidden := range []string{
			"Authentication", "SASL", "Kafka API versions", "Kafka metadata",
		} {
			if strings.Contains(line, forbidden) {
				t.Errorf("a discovered broker's subtree mentions %q:\n%s", forbidden, line)
			}
		}
	}
	if advertised != 3 {
		t.Errorf("advertised broker sections = %d, want 3:\n%s", advertised, got.stdout)
	}
	// Exactly one bootstrap path continued: one credential-bearing attempt.
	if n := strings.Count(got.stdout, "· continued"); n != 1 {
		t.Errorf("continued markers = %d, want 1:\n%s", n, got.stdout)
	}
}

// TestCLIHelpClaimsNothingItCannotDo reads the shipped help.
func TestCLIHelpClaimsNothingItCannotDo(t *testing.T) {
	got := invoke(t, "", "diagnose", "kafka", "--help")

	if got.code != 0 {
		t.Errorf("help exit = %d, want 0", got.code)
	}
	if got.stderr != "" {
		t.Errorf("requested help wrote to stderr: %q", got.stderr)
	}
	// Claims, not words. The help *denies* topic and partition inspection in as
	// many words — "reports nothing about topics, partitions, consumer groups,
	// lag or throughput" — so a bare substring check would flag the denial as
	// the claim. What must be absent is any phrase that offers the capability.
	for _, absent := range []string{
		"reports cluster health", "reports the health", "shows topic",
		"consumer lag", "monitors", "monitoring", "MSK", "OAuth", "OAUTHBEARER",
		"GSSAPI", "Kerberos", "mTLS", "SCRAM-SHA-512", "SCRAM-SHA-1",
	} {
		if strings.Contains(got.stdout, absent) {
			t.Errorf("the Kafka help advertises %q", absent)
		}
	}
	// And the denial is actually there, so the check above is not passing
	// because the subject was never mentioned.
	if !strings.Contains(got.stdout, "reports\nnothing about topics") &&
		!strings.Contains(got.stdout, "reports nothing about topics") {
		t.Errorf("the Kafka help does not say what it leaves out:\n%s", got.stdout)
	}
	for _, present := range []string{
		"PLAIN", "SCRAM-SHA-256", "--password-file", "--password-stdin",
		"--shareable", "Exit code 0 does not mean Kafka metadata was obtained",
	} {
		if !strings.Contains(got.stdout, present) {
			t.Errorf("the Kafka help omits %q", present)
		}
	}
}

// --- assertions -------------------------------------------------------------------

func requireArtifact(t *testing.T, got invocation) {
	t.Helper()
	if got.stdout == "" {
		t.Fatalf("no artifact on stdout (exit %d, stderr %q)", got.code, got.stderr)
	}
	if got.stderr != "" {
		t.Errorf("a run that produced a report also wrote to stderr: %q", got.stderr)
	}
}

// requireRow asserts one Result row, ignoring the column padding tabwriter chose.
func requireRow(t *testing.T, text, label, value string) {
	t.Helper()
	want := strings.Join(strings.Fields(label+" "+value), " ")
	for _, line := range strings.Split(text, "\n") {
		if strings.Join(strings.Fields(line), " ") == want {
			return
		}
	}
	t.Errorf("no Result row %q:\n%s", want, text)
}

// requireNoSecret sweeps both streams for credential material.
func requireNoSecret(t *testing.T, got invocation, secret string) {
	t.Helper()
	for name, stream := range map[string]string{"stdout": got.stdout, "stderr": got.stderr} {
		if strings.Contains(stream, secret) {
			t.Errorf("%s carries the credential", name)
		}
	}
}
