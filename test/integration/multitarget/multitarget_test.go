//go:build integration

// Package multitarget validates that `svcdoctor run --config` composes.
//
// # What this suite proves, and what it deliberately does not
//
// It proves **composition**: that one configuration file naming four different
// services reaches four different composition roots, that each produces its own
// canonical report, that the aggregate wraps them in declared order, and that a
// remote refusal in one target does not disturb the other three.
//
// It proves **no protocol behaviour**. Every protocol claim — what a PostgreSQL
// session boundary is, which Kafka mechanisms a broker offers, how a Redis error
// prefix is classified, what a RabbitMQ close frame means — is owned by that
// service's own suite, which runs against its own fixtures with its own ground
// truth. Re-asserting any of it here would create a second place for those
// claims to drift.
//
// LavinMQ, Redpanda and Valkey are absent for the same reason: compatibility is
// owned by the service-level suites, and a compatibility claim does not become
// stronger by being made twice.
package multitarget

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/cli"
)

// The published ports from each service's own env/compose.yaml. One constant per
// listener, so a scenario names the fixture it means rather than a number.
const (
	portPostgresTLS     = 55432 // in-band SSLRequest, then TLS
	portKafkaSASLSSL    = 19192 // SASL_SSL
	portRedisOpen       = 56379 // no authentication
	portRedisTLS        = 56382 // TLS, --requirepass tls-pw
	portRabbitTLS       = 56671 // AMQPS
	portRabbitPlaintext = 56672
)

// The fixture credentials. Every one of these is a throwaway value for a
// loopback container that exists for the duration of a test run, and each is
// already written down in that service's own compose file or jaas.conf.
const (
	postgresUser     = "app"
	postgresPassword = "app-pw"
	postgresDatabase = "appdb"

	kafkaUser     = "svcdoctor"
	kafkaPassword = "svcdoctor-canary-secret"

	redisTLSPassword = "tls-pw"

	rabbitUser     = "app"
	rabbitPassword = "app-pw"
)

// caFile returns a fixture's CA certificate, which is its server certificate.
//
// # Why a credential-bearing target must use TLS here
//
// svcdoctor refuses to put a password on a channel whose peer identity was not
// verified: ADR 0029's policy is fail-closed and ADR 0068 §7 restates it with no
// opt-in. A plaintext target therefore produces `<SERVICE>_CREDENTIAL_WITHHELD`
// and **zero bytes on the wire** — which is the product working, and which is
// how the first version of this suite learned it was asking the wrong question.
//
// So every credential-bearing scenario below points at that fixture's TLS
// listener and supplies its CA. `insecure: true` would not help: an unverified
// channel is still not a verified one, and the policy reads verification rather
// than encryption.
func caFile(t *testing.T, service string) string {
	t.Helper()
	path, err := filepath.Abs(
		filepath.Join("..", service, "env", "certs", "server.crt"))
	if err != nil {
		t.Fatalf("resolving the %s CA: %v", service, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the %s fixture CA is missing; run its `-up` target first: %v", service, err)
	}
	return path
}

// kafkaCAFile returns the Kafka fixture's CA, which is a separate file.
func kafkaCAFile(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "kafka", "env", "certs", "ca-cert.pem"))
	if err != nil {
		t.Fatalf("resolving the Kafka CA: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the Kafka fixture CA is missing; run `make kafka-up` first: %v", err)
	}
	return path
}

// runSvcdoctor drives the real command and returns its exit code and streams.
//
// It calls cli.App.Run, which is what cmd/svcdoctor calls. A harness that
// invoked the scheduler directly would prove the scheduler works and say nothing
// about whether the product does — the flag parsing, the registry wiring, the
// preflight, the projection and the exit mapping all live above it.
func runSvcdoctor(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := cli.New(strings.NewReader(""), &stdout, &stderr, "integration")
	code := app.Run(context.Background(), args)
	return code, stdout.String(), stderr.String()
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// aggregate is the shape these scenarios read back.
type aggregate struct {
	SchemaVersion int    `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Targets       []struct {
		TargetID       string          `json:"targetId"`
		Service        string          `json:"service"`
		ExecutionState string          `json:"executionState"`
		Report         json.RawMessage `json:"report"`
		ExecutionError *struct {
			Class   string `json:"class"`
			Message string `json:"message"`
		} `json:"executionError"`
	} `json:"targets"`
	Summary struct {
		Targets      int    `json:"targets"`
		Completed    int    `json:"completed"`
		WithProblems int    `json:"withProblems"`
		Status       string `json:"status"`
		Incomplete   bool   `json:"incomplete"`
	} `json:"summary"`
}

func decode(t *testing.T, stdout string) aggregate {
	t.Helper()
	var parsed aggregate
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("the aggregate is not valid JSON: %v\n%s", err, stdout)
	}
	return parsed
}

// reportStatus reads one embedded report's summary status.
func reportStatus(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var report struct {
		Summary struct {
			Status string `json:"status"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	return report.Summary.Status
}

// reportCodes reads one embedded report's finding codes.
func reportCodes(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var report struct {
		Findings []struct {
			Code string `json:"code"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	out := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		out = append(out, finding.Code)
	}
	return out
}

// MT-I01: one configuration, four services, four composition roots.
func TestFourServicesThroughOneRun(t *testing.T) {
	pgPassword := writeFile(t, "pg-password", postgresPassword+"\n")
	kafkaSecret := writeFile(t, "kafka-password", kafkaPassword+"\n")
	rabbitSecret := writeFile(t, "rabbit-password", rabbitPassword+"\n")

	config := writeFile(t, "services.yaml", fmt.Sprintf(`
version: 1
run:
  concurrency: 2
targets:
  - id: orders-db
    type: postgres
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      username: %s
      password:
        file: %s
    config:
      database: %s

  - id: events
    type: kafka
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      username: %s
      password:
        file: %s
    config:
      sasl_mechanism: PLAIN

  - id: cache
    type: redis
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: disable

  - id: queue
    type: rabbitmq
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      username: %s
      password:
        file: %s
`,
		portPostgresTLS, caFile(t, "postgres"), postgresUser, pgPassword, postgresDatabase,
		portKafkaSASLSSL, kafkaCAFile(t), kafkaUser, kafkaSecret,
		portRedisOpen,
		portRabbitTLS, caFile(t, "rabbitmq"), rabbitUser, rabbitSecret))

	code, stdout, stderr := runSvcdoctor(t, "run", "--config", config, "--output", "json")
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}

	parsed := decode(t, stdout)
	if parsed.Kind != "run" || parsed.SchemaVersion != 1 {
		t.Errorf("kind/schemaVersion = %q/%d, want run/1", parsed.Kind, parsed.SchemaVersion)
	}

	// Declared order, whatever order the two workers finished in.
	want := []string{"orders-db", "events", "cache", "queue"}
	got := make([]string, 0, len(parsed.Targets))
	for _, target := range parsed.Targets {
		got = append(got, target.TargetID)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("target order = %v, want the declared %v", got, want)
	}

	wantService := map[string]string{
		"orders-db": "postgres", "events": "kafka",
		"cache": "redis", "queue": "rabbitmq",
	}
	for _, target := range parsed.Targets {
		if target.ExecutionState != "COMPLETED" {
			t.Errorf("target %q: state = %s, want COMPLETED (error: %+v)",
				target.TargetID, target.ExecutionState, target.ExecutionError)
			continue
		}
		if len(target.Report) == 0 {
			t.Errorf("target %q: no embedded report", target.TargetID)
		}
		if got := target.Service; got != wantService[target.TargetID] {
			t.Errorf("target %q: service = %q, want %q",
				target.TargetID, got, wantService[target.TargetID])
		}
	}

	// Every target reached a healthy conclusion, which is what makes this the
	// happy path rather than four coincidences.
	for _, target := range parsed.Targets {
		if status := reportStatus(t, target.Report); status != "OK" {
			t.Errorf("target %q: status = %q, want OK; findings %v",
				target.TargetID, status, reportCodes(t, target.Report))
		}
		// And the three credential-bearing targets actually presented one: a
		// WITHHELD finding would mean the policy refused the channel and this
		// scenario proved nothing about authentication.
		for _, code := range reportCodes(t, target.Report) {
			if strings.HasSuffix(code, "_CREDENTIAL_WITHHELD") {
				t.Errorf("target %q: the credential was withheld (%s), so this scenario "+
					"did not exercise authentication", target.TargetID, code)
			}
		}
	}

	if parsed.Summary.Completed != 4 {
		t.Errorf("completed = %d, want 4", parsed.Summary.Completed)
	}
	if parsed.Summary.Incomplete {
		t.Errorf("the run is incomplete; every target should have run: %+v", parsed.Summary)
	}
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
}

// MT-I02: a remote refusal in one target leaves the other three alone.
//
// The Redis TLS fixture requires a password. This target supplies a wrong one
// over a verified channel, so the credential really is presented and the
// endpoint really refuses it — a *diagnosis*, not an execution failure. The
// target is COMPLETED and its report carries the finding.
func TestARemoteRefusalDoesNotDisturbOtherTargets(t *testing.T) {
	pgPassword := writeFile(t, "pg-password", postgresPassword+"\n")
	wrongPassword := writeFile(t, "redis-password", "definitely-not-"+redisTLSPassword+"\n")
	rabbitSecret := writeFile(t, "rabbit-password", rabbitPassword+"\n")

	config := writeFile(t, "services.yaml", fmt.Sprintf(`
version: 1
run:
  concurrency: 4
targets:
  - id: orders-db
    type: postgres
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      username: %s
      password:
        file: %s
    config:
      database: %s

  - id: cache
    type: redis
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      password:
        file: %s

  - id: queue
    type: rabbitmq
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      username: %s
      password:
        file: %s
`,
		portPostgresTLS, caFile(t, "postgres"), postgresUser, pgPassword, postgresDatabase,
		portRedisTLS, caFile(t, "redis"), wrongPassword,
		portRabbitTLS, caFile(t, "rabbitmq"), rabbitUser, rabbitSecret))

	code, stdout, stderr := runSvcdoctor(t, "run", "--config", config, "--output", "json")
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
	parsed := decode(t, stdout)

	byID := map[string]int{}
	for i, target := range parsed.Targets {
		byID[target.TargetID] = i
	}

	// Every target completed. A refused credential is a successful diagnosis.
	for _, target := range parsed.Targets {
		if target.ExecutionState != "COMPLETED" {
			t.Errorf("target %q: state = %s, want COMPLETED (error: %+v)",
				target.TargetID, target.ExecutionState, target.ExecutionError)
		}
	}

	// The refusal is in the Redis report, as a finding, and nowhere else.
	cache := parsed.Targets[byID["cache"]]
	codes := reportCodes(t, cache.Report)
	t.Logf("cache findings: %v", codes)
	if status := reportStatus(t, cache.Report); status != "PROBLEMS_FOUND" {
		t.Errorf("cache report status = %q, want PROBLEMS_FOUND; findings %v", status, codes)
	}
	var rejected bool
	for _, code := range codes {
		if code == "REDIS_CREDENTIALS_REJECTED" {
			rejected = true
		}
		if strings.HasSuffix(code, "_CREDENTIAL_WITHHELD") {
			t.Errorf("the credential was withheld (%s), so the endpoint never saw it and "+
				"this scenario did not exercise a refusal", code)
		}
	}
	if !rejected {
		t.Errorf("findings %v do not include REDIS_CREDENTIALS_REJECTED", codes)
	}

	// And the unrelated targets are untouched: no fail-fast, and no cross-target
	// inference putting a Redis problem into a PostgreSQL report.
	for _, id := range []string{"orders-db", "queue"} {
		target := parsed.Targets[byID[id]]
		if status := reportStatus(t, target.Report); status != "OK" {
			t.Errorf("target %q: report status = %q, want OK; a refusal elsewhere must not "+
				"reach this report. findings %v", id, status, reportCodes(t, target.Report))
		}
	}

	if parsed.Summary.WithProblems != 1 {
		t.Errorf("withProblems = %d, want exactly 1", parsed.Summary.WithProblems)
	}
	if parsed.Summary.Status != "PROBLEMS_FOUND" {
		t.Errorf("status = %q, want PROBLEMS_FOUND", parsed.Summary.Status)
	}
	if parsed.Summary.Incomplete {
		t.Error("every target ran; the run is not incomplete")
	}
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

// MT-I03: the same endpoint under two logical targets is two executions.
func TestDuplicateEndpointsAreTwoExecutions(t *testing.T) {
	password := writeFile(t, "pg-password", postgresPassword+"\n")

	config := writeFile(t, "services.yaml", fmt.Sprintf(`
version: 1
targets:
  - id: appdb
    type: postgres
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      username: %s
      password:
        file: %s
    config:
      database: %s

  - id: absent-database
    type: postgres
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      username: %s
      password:
        file: %s
    config:
      database: no_such_database
`, portPostgresTLS, caFile(t, "postgres"), postgresUser, password, postgresDatabase,
		portPostgresTLS, caFile(t, "postgres"), postgresUser, password))

	_, stdout, stderr := runSvcdoctor(t, "run", "--config", config, "--output", "json")
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}
	parsed := decode(t, stdout)

	if len(parsed.Targets) != 2 {
		t.Fatalf("got %d targets, want 2; endpoints are never deduplicated", len(parsed.Targets))
	}
	for _, target := range parsed.Targets {
		if target.ExecutionState != "COMPLETED" {
			t.Errorf("target %q: state = %s", target.TargetID, target.ExecutionState)
		}
	}
	// The two targets share an endpoint and reached different conclusions, which
	// is the whole reason an endpoint is not identity.
	first := reportStatus(t, parsed.Targets[0].Report)
	second := reportStatus(t, parsed.Targets[1].Report)
	if first == second {
		t.Errorf("both targets on one endpoint reported %q; the second names a database "+
			"that does not exist", first)
	}
	t.Logf("appdb=%s absent-database=%s codes=%v",
		first, second, reportCodes(t, parsed.Targets[1].Report))
}

// MT-I04: a credential the resolver cannot obtain is not an authentication failure.
func TestAMissingCredentialIsNotAnAuthenticationFailure(t *testing.T) {
	config := writeFile(t, "services.yaml", fmt.Sprintf(`
version: 1
targets:
  - id: cache
    type: redis
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      password:
        env: SVCDOCTOR_MULTITARGET_ABSENT_VARIABLE
`, portRedisTLS, caFile(t, "redis")))

	os.Unsetenv("SVCDOCTOR_MULTITARGET_ABSENT_VARIABLE")

	code, stdout, stderr := runSvcdoctor(t, "run", "--config", config, "--output", "json")

	// Preflight refuses the run: nothing is dialled, and no aggregate exists.
	if stdout != "" {
		t.Errorf("stdout = %q, want no report", stdout)
	}
	if code == 0 || code == 1 {
		t.Errorf("exit = %d, want a pre-execution refusal", code)
	}
	// stderr names the variable so it can be fixed, and claims nothing about the
	// endpoint.
	if !strings.Contains(stderr, "SVCDOCTOR_MULTITARGET_ABSENT_VARIABLE") {
		t.Errorf("stderr = %q, want the variable named", stderr)
	}
	for _, forbidden := range []string{"rejected", "AUTH", "authentication failed"} {
		if strings.Contains(stderr, forbidden) {
			t.Errorf("stderr = %q claims something about the endpoint; nothing was sent",
				stderr)
		}
	}
}

// MT-I05: the shareable aggregate removes identity and preserves correlation.
func TestShareableAggregateAcrossServices(t *testing.T) {
	password := writeFile(t, "pg-password", postgresPassword+"\n")

	config := writeFile(t, "services.yaml", fmt.Sprintf(`
version: 1
targets:
  - id: orders-db
    type: postgres
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: require
      ca_file: %s
    credentials:
      username: %s
      password:
        file: %s
    config:
      database: %s

  - id: cache
    type: redis
    host: 127.0.0.1
    port: %d
    timeout: 30s
    step_timeout: 10s
    tls:
      mode: disable
`, portPostgresTLS, caFile(t, "postgres"), postgresUser, password, postgresDatabase,
		portRedisOpen))

	_, stdout, stderr := runSvcdoctor(t,
		"run", "--config", config, "--output", "json", "--shareable")
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing", stderr)
	}

	// The operator's identifiers are gone, and so is the credential material.
	for _, forbidden := range []string{"orders-db", "cache", postgresPassword, password} {
		if strings.Contains(stdout, forbidden) {
			t.Errorf("the shareable aggregate contains %q", forbidden)
		}
	}
	parsed := decode(t, stdout)
	for i, target := range parsed.Targets {
		want := fmt.Sprintf("target-%03d", i+1)
		if target.TargetID != want {
			t.Errorf("target %d: id = %q, want %q", i, target.TargetID, want)
		}
	}
	// Both targets are on 127.0.0.1, so both must carry the same pseudonym.
	if len(parsed.Targets) == 2 {
		first := requestedHost(t, parsed.Targets[0].Report)
		second := requestedHost(t, parsed.Targets[1].Report)
		if first != second {
			t.Errorf("one endpoint received two pseudonyms across the run: %q and %q",
				first, second)
		}
	}
}

func requestedHost(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var report struct {
		Target struct {
			Requested string `json:"requested"`
		} `json:"target"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	host, _, _ := strings.Cut(report.Target.Requested, ":")
	return host
}
