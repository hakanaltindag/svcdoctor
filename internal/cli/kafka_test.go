package cli

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The Kafka command boundary.
//
// # What is exercised here, and what is not
//
// Argument parsing, validation, credential binding, the TLS plan, the output
// switch, the exit mapping and text/JSON parity — everything the command owns.
// The scripted seam returns whatever result a test names, because none of that
// depends on a broker answering.
//
// The runs that need a real graph go through app.DiagnoseKafka against faked
// network seams, which is what `kafkaResult` builds. A full Kafka journey needs
// a peer that speaks the protocol, and depguard denies this package the Kafka
// adapter — deliberately, so a command cannot reach the protocol. Those live in
// test/integration/kafka, against the real cluster.

// --- routing -------------------------------------------------------------------

func TestKafkaIsRouted(t *testing.T) {
	h := newHarness(kafkaRefusedResult(t), nil)
	code := h.run("diagnose", "kafka", "--host", "kafka.internal",
		"--sasl-mechanism", "SCRAM-SHA-256")

	if h.kafkaCalls != 1 {
		t.Fatalf("the Kafka application was called %d times, want 1: %s",
			h.kafkaCalls, h.stderr.String())
	}
	if h.calls != 0 {
		t.Error("a Kafka invocation reached the PostgreSQL command")
	}
	if code != ExitProblemsFound {
		t.Errorf("exit = %d, want %d", code, ExitProblemsFound)
	}
	if h.stdout.Len() == 0 {
		t.Error("no artifact was written")
	}
}

func TestTheRejectedKafkaShapesStayRejected(t *testing.T) {
	for _, args := range [][]string{
		{"kafka", "--host", "k", "--sasl-mechanism", "PLAIN"},
		{"kafka", "diagnose", "--host", "k", "--sasl-mechanism", "PLAIN"},
		{"inspect", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN"},
		{"monitor", "kafka", "--host", "k"},
		{"diagnose", "kafka://k:9092"},
	} {
		h := newHarness(app.Result{}, nil)
		if code := h.run(args...); code != ExitUsage {
			t.Errorf("`%s` exit = %d, want %d", strings.Join(args, " "), code, ExitUsage)
		}
		if h.kafkaCalls != 0 {
			t.Errorf("`%s` reached the application", strings.Join(args, " "))
		}
	}
}

// --- mechanism selection, ADR 0057 ----------------------------------------------

// TestTheMechanismIsRequiredAndHasNoDefault is the security half of ADR 0057.
//
// A default would be a silent decision about the framing that carries the
// operator's password, taken on the run where they were distracted enough to
// forget the flag.
func TestTheMechanismIsRequiredAndHasNoDefault(t *testing.T) {
	h := newHarness(app.Result{}, nil)
	code := h.run("diagnose", "kafka", "--host", "kafka.internal")

	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if h.kafkaCalls != 0 {
		t.Fatal("a run with no mechanism reached the application")
	}
	if !strings.Contains(h.stderr.String(), "--sasl-mechanism is required") {
		t.Errorf("the error does not name the missing flag: %q", h.stderr.String())
	}
}

func TestMechanismNamesAreTakenVerbatim(t *testing.T) {
	tests := []struct {
		name      string
		mechanism string
		wantCode  int
		wantParam string
	}{
		{"PLAIN", "PLAIN", ExitProblemsFound, "PLAIN"},
		{"SCRAM-SHA-256", "SCRAM-SHA-256", ExitProblemsFound, "SCRAM-SHA-256"},
		// Accepted and proposed, not refused. Naming a mechanism sends no
		// secret, and the answer is the only way to ask what a broker offers.
		{"a mechanism svcdoctor cannot perform", "GSSAPI", ExitProblemsFound, "GSSAPI"},
		{"SCRAM-SHA-512", "SCRAM-SHA-512", ExitProblemsFound, "SCRAM-SHA-512"},
		{"AWS_MSK_IAM", "AWS_MSK_IAM", ExitProblemsFound, "AWS_MSK_IAM"},

		// Refused, and never folded: a looser matching rule at the CLI beside
		// the exact-match guard that gates the credential is how that guard
		// fails quietly.
		{"lowercase", "plain", ExitUsage, ""},
		{"mixed case", "Scram-Sha-256", ExitUsage, ""},
		{"a space", "PLAIN SCRAM", ExitUsage, ""},
		{"a comma-separated list", "PLAIN,SCRAM-SHA-256", ExitUsage, ""},
		{"too long", strings.Repeat("A", 21), ExitUsage, ""},
		{"empty", "", ExitUsage, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(kafkaRefusedResult(t), nil)
			code := h.run("diagnose", "kafka", "--host", "kafka.internal",
				"--sasl-mechanism", tt.mechanism)

			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d: %s", code, tt.wantCode, h.stderr.String())
			}
			if tt.wantParam == "" {
				if h.kafkaCalls != 0 {
					t.Error("a refused mechanism reached the application")
				}
				return
			}
			if got := h.capturedKafka.Mechanism; got != tt.wantParam {
				t.Errorf("mechanism = %q, want %q verbatim", got, tt.wantParam)
			}
		})
	}
}

// TestALowercaseMechanismNamesTheUppercaseForm keeps the refusal actionable.
func TestALowercaseMechanismNamesTheUppercaseForm(t *testing.T) {
	h := newHarness(app.Result{}, nil)
	h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "scram-sha-256")

	if !strings.Contains(h.stderr.String(), `"SCRAM-SHA-256"`) {
		t.Errorf("the refusal does not name the registered spelling: %q", h.stderr.String())
	}
}

// TestTheCommandOffersNoMechanismFallback is the behavioural half of ADR 0057 §2.
func TestTheCommandOffersNoMechanismFallback(t *testing.T) {
	// No flag registered can name a second mechanism, an ordering or a retry.
	for _, args := range [][]string{
		{"--sasl-mechanisms", "PLAIN,SCRAM-SHA-256"},
		{"--sasl-mechanism-fallback", "PLAIN"},
		{"--sasl-auto"},
		{"--retry"},
		{"--sasl-mechanism", "PLAIN", "--sasl-mechanism-2", "SCRAM-SHA-256"},
	} {
		h := newHarness(app.Result{}, nil)
		full := append([]string{"diagnose", "kafka", "--host", "k"}, args...)
		if code := h.run(full...); code != ExitUsage {
			t.Errorf("`%s` was accepted; exit = %d", strings.Join(args, " "), code)
		}
		if h.kafkaCalls != 0 {
			t.Errorf("`%s` reached the application", strings.Join(args, " "))
		}
	}
}

// --- credential input, reused from Phase 5.2 ------------------------------------

// TestKafkaCredentialSourcesAreTheOnesADR0049Allows refuses every other route a
// secret could take.
//
// **The refusal has to be "no such flag", not merely exit 2.** An earlier version
// of this test asserted only the exit code, and a mutation that *registered*
// `--password` and discarded its value still exited 2 — for an unrelated reason —
// so the guard proved nothing. Matching the parser's own message is what makes it
// prove the flag does not exist.
func TestKafkaCredentialSourcesAreTheOnesADR0049Allows(t *testing.T) {
	for _, args := range [][]string{
		{"--password", "hunter2"},
		{"--password=hunter2"},
		{"--sasl-password", "hunter2"},
		{"--dsn", "kafka://app:hunter2@k:9092"},
		{"--password-env", "KAFKA_PASSWORD"},
		{"--prompt"},
	} {
		h := newHarness(app.Result{}, nil)
		full := append([]string{
			"diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN",
		}, args...)
		code := h.run(full...)

		if code != ExitUsage {
			t.Errorf("`%s` was accepted; exit = %d", strings.Join(args, " "), code)
		}
		if !strings.Contains(h.stderr.String(), "not defined") {
			t.Errorf("`%s` was refused for some other reason, so this proves nothing: %q",
				strings.Join(args, " "), h.stderr.String())
		}
		if h.kafkaCalls != 0 {
			t.Errorf("`%s` reached the application", strings.Join(args, " "))
		}
	}
}

// TestAFailedKafkaRunWritesNoArtifact is the stdout discipline.
//
// A run that produced no report must leave nothing on stdout for a pipeline to
// parse as one, and the diagnostic goes to stderr (ADR 0048 section 7).
func TestAFailedKafkaRunWritesNoArtifact(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"unusable input", app.ErrInvalidInput, ExitUsage},
		{"svcdoctor itself failed", errKafkaRunFailed, ExitInternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(app.Result{}, tt.err)
			code := h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN")

			if code != tt.want {
				t.Errorf("exit = %d, want %d", code, tt.want)
			}
			if h.stdout.Len() != 0 {
				t.Errorf("a failed run wrote an artifact: %q", h.stdout.String())
			}
			if h.stderr.Len() == 0 {
				t.Error("a failed run said nothing on stderr")
			}
		})
	}
}

var errKafkaRunFailed = errors.New("the run could not be performed")

func TestKafkaReadsTheCredentialFromAFile(t *testing.T) {
	path := writeSecret(t, "kafka-secret-canary\n")

	h := newHarness(kafkaRefusedResult(t), nil)
	code := h.run("diagnose", "kafka", "--host", "kafka.internal",
		"--sasl-mechanism", "SCRAM-SHA-256", "--user", "app", "--password-file", path)

	if code != ExitProblemsFound {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}
	credential := h.capturedKafka.Credential
	if credential.IsZero() {
		t.Fatal("no credential was built from --password-file")
	}
	if got := credential.Identity(); got != "app" {
		t.Errorf("identity = %q, want %q", got, "app")
	}
	// Bound to the logical endpoint the operator named, never to a resolved
	// address and never to an advertised broker (ADR 0050).
	endpoint, err := security.NewEndpoint("kafka.internal", 9092)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if !credential.Endpoint().Equal(endpoint) {
		t.Errorf("the credential is bound to %v, want the requested endpoint", credential.Endpoint())
	}
}

func TestKafkaReadsTheCredentialFromStdin(t *testing.T) {
	h := newHarness(kafkaRefusedResult(t), nil)
	h.app.In = strings.NewReader("kafka-secret-canary\n")

	code := h.run("diagnose", "kafka", "--host", "kafka.internal",
		"--sasl-mechanism", "PLAIN", "--user", "app", "--password-stdin")

	if code != ExitProblemsFound {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}
	if h.capturedKafka.Credential.IsZero() {
		t.Fatal("no credential was built from --password-stdin")
	}
}

func TestKafkaRefusesTwoCredentialSources(t *testing.T) {
	path := writeSecret(t, "x\n")

	h := newHarness(app.Result{}, nil)
	code := h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN",
		"--user", "app", "--password-file", path, "--password-stdin")

	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(h.stderr.String(), "mutually exclusive") {
		t.Errorf("the refusal does not say why: %q", h.stderr.String())
	}
}

// TestKafkaIdentityAndCredentialTravelTogether is ADR 0057 §5.
func TestKafkaIdentityAndCredentialTravelTogether(t *testing.T) {
	path := writeSecret(t, "x\n")

	t.Run("a credential with no identity is refused", func(t *testing.T) {
		h := newHarness(app.Result{}, nil)
		code := h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN",
			"--password-file", path)
		if code != ExitUsage {
			t.Errorf("exit = %d, want %d", code, ExitUsage)
		}
		if !strings.Contains(h.stderr.String(), "--user is required") {
			t.Errorf("the refusal does not name --user: %q", h.stderr.String())
		}
	})

	t.Run("an identity with no credential is refused rather than ignored", func(t *testing.T) {
		h := newHarness(app.Result{}, nil)
		code := h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN",
			"--user", "app")
		if code != ExitUsage {
			t.Errorf("exit = %d, want %d", code, ExitUsage)
		}
		if !strings.Contains(h.stderr.String(), "no effect") {
			t.Errorf("the refusal does not say the flag would do nothing: %q", h.stderr.String())
		}
	})

	t.Run("neither is a valid run", func(t *testing.T) {
		h := newHarness(kafkaRefusedResult(t), nil)
		code := h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN")
		if code != ExitProblemsFound {
			t.Fatalf("exit = %d: %s", code, h.stderr.String())
		}
		if !h.capturedKafka.Credential.IsZero() {
			t.Error("a run with no credential source built one anyway")
		}
	})
}

// --- TLS flags ------------------------------------------------------------------

func TestTheKafkaTLSPlanIsExplicit(t *testing.T) {
	t.Run("require is the default", func(t *testing.T) {
		h := newHarness(kafkaRefusedResult(t), nil)
		h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN")
		if h.capturedKafka.TLS == nil {
			t.Error("the default run carries no TLS plan")
		}
	})

	t.Run("disable carries no plan at all", func(t *testing.T) {
		h := newHarness(kafkaRefusedResult(t), nil)
		h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN",
			"--tls", "disable")
		if h.capturedKafka.TLS != nil {
			t.Error("--tls disable still asked for a handshake")
		}
	})

	t.Run("the trust flags reach the plan", func(t *testing.T) {
		h := newHarness(kafkaRefusedResult(t), nil)
		h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN",
			"--tls-server-name", "broker.internal", "--tls-insecure")
		plan := h.capturedKafka.TLS
		if plan == nil {
			t.Fatal("no TLS plan")
		}
		if plan.ServerName != "broker.internal" {
			t.Errorf("server name = %q", plan.ServerName)
		}
		if !plan.InsecureSkipVerify {
			t.Error("--tls-insecure did not reach the plan")
		}
	})

	t.Run("a trust flag with no handshake is refused, not ignored", func(t *testing.T) {
		for _, extra := range [][]string{
			{"--tls-ca-file", "/nonexistent"},
			{"--tls-server-name", "broker.internal"},
			{"--tls-insecure"},
		} {
			h := newHarness(app.Result{}, nil)
			args := append([]string{"diagnose", "kafka", "--host", "k",
				"--sasl-mechanism", "PLAIN", "--tls", "disable"}, extra...)
			if code := h.run(args...); code != ExitUsage {
				t.Errorf("`%s` with --tls disable was accepted; exit = %d", extra[0], code)
			}
		}
	})

	t.Run("an unknown mode is refused", func(t *testing.T) {
		for _, mode := range []string{"prefer", "verify-full", "allow", ""} {
			h := newHarness(app.Result{}, nil)
			code := h.run("diagnose", "kafka", "--host", "k",
				"--sasl-mechanism", "PLAIN", "--tls", mode)
			if code != ExitUsage {
				t.Errorf("--tls %q was accepted; exit = %d", mode, code)
			}
		}
	})
}

// TestTheKafkaCommandChoosesNoTransportPolicy pins the fail-closed default.
func TestTheKafkaCommandChoosesNoTransportPolicy(t *testing.T) {
	h := newHarness(kafkaRefusedResult(t), nil)
	h.run("diagnose", "kafka", "--host", "k", "--sasl-mechanism", "PLAIN")

	if got := h.capturedKafka.TransportPolicy; got != security.RequireVerifiedTLS {
		t.Errorf("transport policy = %v, want the zero value RequireVerifiedTLS", got)
	}
	// And no flag can change it.
	for _, args := range [][]string{
		{"--allow-plaintext-credential"}, {"--credential-policy", "any"},
		{"--insecure-credential"},
	} {
		h := newHarness(app.Result{}, nil)
		full := append([]string{"diagnose", "kafka", "--host", "k",
			"--sasl-mechanism", "PLAIN"}, args...)
		if code := h.run(full...); code != ExitUsage {
			t.Errorf("`%s` was accepted", strings.Join(args, " "))
		}
	}
}

// --- exit codes and parity -------------------------------------------------------

// TestKafkaExitCodesComeFromTheSharedMapping proves there is no Kafka special
// case.
func TestKafkaExitCodesComeFromTheSharedMapping(t *testing.T) {
	tests := []struct {
		name   string
		result func(*testing.T) app.Result
		want   int
	}{
		{"a complete run with nothing proven wrong", kafkaOKResult, ExitOK},
		{"an endpoint refused the connection", kafkaRefusedResult, ExitProblemsFound},
		{"svcdoctor's own budget expired", kafkaIncompleteResult, ExitIncomplete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, form := range []string{"text", "json"} {
				h := newHarness(tt.result(t), nil)
				code := h.run("diagnose", "kafka", "--host", "kafka.internal",
					"--sasl-mechanism", "PLAIN", "--output", form)
				if code != tt.want {
					t.Errorf("%s: exit = %d, want %d", form, code, tt.want)
				}
				if h.stdout.Len() == 0 {
					t.Errorf("%s: no artifact was written", form)
				}
				if h.stderr.Len() != 0 {
					t.Errorf("%s: stderr = %q", form, h.stderr.String())
				}
			}
		})
	}
}

// TestKafkaTextAndJSONAgree is the parity contract.
func TestKafkaTextAndJSONAgree(t *testing.T) {
	for _, build := range []func(*testing.T) app.Result{
		kafkaRefusedResult, kafkaIncompleteResult,
	} {
		result := build(t)

		text := newHarness(result, nil)
		textCode := text.run("diagnose", "kafka", "--host", "kafka.internal",
			"--sasl-mechanism", "PLAIN", "--output", "text")

		jsonOut := newHarness(result, nil)
		jsonCode := jsonOut.run("diagnose", "kafka", "--host", "kafka.internal",
			"--sasl-mechanism", "PLAIN", "--output", "json")

		if textCode != jsonCode {
			t.Errorf("text exit = %d, json exit = %d", textCode, jsonCode)
		}
		if !strings.HasPrefix(jsonOut.stdout.String(), `{"schemaVersion":1`) {
			t.Errorf("the canonical JSON changed: %.60s", jsonOut.stdout.String())
		}

		// The same facts, in both forms.
		summary := result.Report().Summary()
		for _, finding := range result.Report().Findings() {
			if !strings.Contains(text.stdout.String(), string(finding.Code())) {
				t.Errorf("the text form lost finding %s", finding.Code())
			}
			if !strings.Contains(jsonOut.stdout.String(), string(finding.Code())) {
				t.Errorf("the JSON form lost finding %s", finding.Code())
			}
		}
		if layer := summary.FirstBrokenLayer(); layer != domain.LayerUnspecified {
			if !strings.Contains(text.stdout.String(), layer.String()) {
				t.Errorf("the text form lost the first broken layer %s", layer)
			}
			if !strings.Contains(jsonOut.stdout.String(), layer.String()) {
				t.Errorf("the JSON form lost the first broken layer %s", layer)
			}
		}
	}
}

// TestKafkaShareableRemovesIdentityAndKeepsTheDiagnosis is redaction at the Kafka
// output boundary.
func TestKafkaShareableRemovesIdentityAndKeepsTheDiagnosis(t *testing.T) {
	result := kafkaRefusedResult(t)

	local := newHarness(result, nil)
	localCode := local.run("diagnose", "kafka", "--host", "kafka.internal",
		"--sasl-mechanism", "PLAIN")

	shared := newHarness(result, nil)
	sharedCode := shared.run("diagnose", "kafka", "--host", "kafka.internal",
		"--sasl-mechanism", "PLAIN", "--shareable")

	if localCode != sharedCode {
		t.Errorf("redaction changed the exit code: %d -> %d", localCode, sharedCode)
	}
	if !strings.Contains(local.stdout.String(), kafkaCanaryHost) {
		t.Fatal("the local text has no hostname; this test proves nothing")
	}
	if strings.Contains(shared.stdout.String(), kafkaCanaryHost) {
		t.Error("the shareable text still carries the requested hostname")
	}
	if !strings.Contains(shared.stdout.String(), "Shareable report") {
		t.Error("the shareable text does not announce itself")
	}
	// The diagnosis survives.
	for _, keep := range []string{"Kafka metadata NOT obtained", "PROBLEMS FOUND"} {
		if !strings.Contains(shared.stdout.String(), keep) {
			t.Errorf("the shareable text lost %q", keep)
		}
	}
}

// --- fixtures --------------------------------------------------------------------

const kafkaCanaryHost = "kafka.canary.svcdoctor.test"

func writeSecret(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing the secret file: %v", err)
	}
	return path
}

// runKafka produces a genuine Result from the production composition.
func runKafka(t *testing.T, params app.KafkaParams) app.Result {
	t.Helper()

	params.Mechanism = "SCRAM-SHA-256"
	params.Version = "0.0.0-test"
	if params.StepTimeout == 0 {
		params.StepTimeout = 150 * time.Millisecond
	}
	vantage, err := domain.NewLocalVantage("svcdoctor-test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	params.Vantage = vantage

	result, err := app.DiagnoseKafka(context.Background(), params)
	if err != nil {
		t.Fatalf("DiagnoseKafka: %v", err)
	}
	return result
}

// kafkaRefusedResult is an endpoint whose addresses all refuse: an ERROR at L2.
func kafkaRefusedResult(t *testing.T) app.Result {
	t.Helper()
	return runKafka(t, app.KafkaParams{
		Host: kafkaCanaryHost, Port: 9092,
		Resolver: stubResolver{addrs: []netip.Addr{mustAddr(t, "198.51.100.10")}},
		Dialer:   refusingDialer{},
	})
}

// kafkaOKResult is a complete run with no ERROR or CRITICAL proven.
//
// **It is a PostgreSQL report, and that is the point of the test that uses it.**
// ExitCode reads Summary().Status() and Incomplete() and nothing else — not the
// service, not a finding code, not the graph — so the OK row of the matrix is
// service-independent by construction, and driving it through the Kafka command
// is what shows the Kafka command adds no special case.
//
// The Kafka shapes that are genuinely OK and complete — no credential
// configured, and a mechanism svcdoctor cannot perform — need a broker to answer
// ApiVersions and the SASL handshake. depguard denies this package the Kafka
// adapter, deliberately, so those are proven against the real cluster in
// test/integration/kafka rather than faked here.
func kafkaOKResult(t *testing.T) app.Result {
	t.Helper()
	return resultOKComplete(t)
}

// kafkaIncompleteResult is svcdoctor's own budget expiring mid-measurement.
func kafkaIncompleteResult(t *testing.T) app.Result {
	t.Helper()
	return runKafka(t, app.KafkaParams{
		Host: kafkaCanaryHost, Port: 9092,
		Resolver:    stubResolver{addrs: []netip.Addr{mustAddr(t, "198.51.100.10")}},
		Dialer:      blackHole{},
		StepTimeout: 60 * time.Millisecond,
	})
}

// refusingDialer refuses every address, which is what a closed port looks like.
type refusingDialer struct{}

func (refusingDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errConnectionRefused{}}
}

type errConnectionRefused struct{}

func (errConnectionRefused) Error() string   { return "connection refused" }
func (errConnectionRefused) Timeout() bool   { return false }
func (errConnectionRefused) Temporary() bool { return false }
