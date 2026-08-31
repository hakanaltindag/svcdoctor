//go:build integration

package multitarget

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Phase 9.1C section 30: one run holding six different outcomes at once.
//
// # Why a single run rather than six tests
//
// The scenarios beside this one each isolate one behaviour, which is right for
// establishing that the behaviour exists. What none of them establishes is that
// the behaviours **coexist**: that a target failing locally, a target refused
// remotely and a target succeeding can occupy one aggregate without any of them
// changing the others.
//
// That is the property multi-target orchestration exists to provide, and it is
// the one an operator relies on when they point svcdoctor at a whole
// environment. So it gets one run with everything in it.
//
// # The six conditions, and how each is produced deterministically
//
//	healthy postgres     the fixture, correct credentials over verified TLS
//	postgres logical     a database that does not exist -> a diagnosis
//	healthy kafka        the fixture, PLAIN over SASL_SSL
//	redis refusal        a wrong password over verified TLS -> a diagnosis
//	healthy rabbitmq     the fixture, correct credentials over AMQPS
//	local resolver       a credential file that passes preflight and fails the read
//
// The last one is the difficult one and is worth stating. A credential
// reference that fails at *preflight* refuses the whole run — exit 2, zero
// targets dialled — which is the frozen contract and is the opposite of what
// this scenario needs. What it needs is a reference that survives preflight and
// fails at resolution, and there is exactly one deterministic way to produce it.
//
// Preflight checks metadata only, and refuses a file whose size is above
// `MaxInput + 1`. The read refuses input longer than `MaxInput`. A file of
// exactly `MaxInput + 1` bytes therefore passes preflight and fails the read,
// which is documented behaviour rather than a gap: preflight "refuses only what
// cannot possibly be within the bound", and the read decides the boundary.
// Measured at 4097 bytes, with and without a trailing newline.
//
// The alternative — deleting a file mid-run — is a race, and a race is not a
// test.
const oversizedCredentialBytes = 4097

// TestTheChaosMixKeepsEveryTargetIndependent is the scenario.
func TestTheChaosMixKeepsEveryTargetIndependent(t *testing.T) {
	pgPassword := writeFile(t, "pg-password", postgresPassword+"\n")
	kafkaSecret := writeFile(t, "kafka-password", kafkaPassword+"\n")
	rabbitSecret := writeFile(t, "rabbit-password", rabbitPassword+"\n")
	wrongRedis := writeFile(t, "redis-password", "definitely-not-"+redisTLSPassword+"\n")

	// Survives preflight, fails the read. See the comment above.
	unresolvable := writeFile(t, "oversized-password",
		strings.Repeat("x", oversizedCredentialBytes))

	config := writeFile(t, "chaos.yaml", fmt.Sprintf(`
version: 1
run:
  concurrency: 3
targets:
  - id: pg-healthy
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

  - id: pg-missing-database
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
      database: no_such_database_exists

  - id: kafka-healthy
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

  - id: redis-refused
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

  - id: rabbit-healthy
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

  - id: local-resolver-failure
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
`,
		portPostgresTLS, caFile(t, "postgres"), postgresUser, pgPassword, postgresDatabase,
		portPostgresTLS, caFile(t, "postgres"), postgresUser, pgPassword,
		portKafkaSASLSSL, kafkaCAFile(t), kafkaUser, kafkaSecret,
		portRedisTLS, caFile(t, "redis"), wrongRedis,
		portRabbitTLS, caFile(t, "rabbitmq"), rabbitUser, rabbitSecret,
		portRedisTLS, caFile(t, "redis"), unresolvable))

	code, stdout, stderr := runSvcdoctor(t, "run", "--config", config, "--output", "json")

	parsed := decode(t, stdout)
	if len(parsed.Targets) != 6 {
		t.Fatalf("%d targets in the aggregate, want 6\nstderr: %s", len(parsed.Targets), stderr)
	}

	// Declared order, whatever order three workers finished six targets in.
	want := []string{
		"pg-healthy", "pg-missing-database", "kafka-healthy",
		"redis-refused", "rabbit-healthy", "local-resolver-failure",
	}
	for i, target := range parsed.Targets {
		if target.TargetID != want[i] {
			t.Fatalf("target %d is %q, want %q: declared order was not preserved",
				i, target.TargetID, want[i])
		}
	}

	byID := map[string]int{}
	for i, target := range parsed.Targets {
		byID[target.TargetID] = i
	}
	at := func(id string) int { return byID[id] }

	// --- the three healthy targets are untouched by their neighbours ---
	for _, id := range []string{"pg-healthy", "kafka-healthy", "rabbit-healthy"} {
		target := parsed.Targets[at(id)]
		if target.ExecutionState != "COMPLETED" {
			t.Errorf("%s: state = %s, want COMPLETED (error: %+v); a failure elsewhere "+
				"in the run must not disturb it", id, target.ExecutionState,
				target.ExecutionError)
			continue
		}
		if status := reportStatus(t, target.Report); status != "OK" {
			t.Errorf("%s: status = %q, want OK; findings %v",
				id, status, reportCodes(t, target.Report))
		}
		for _, code := range reportCodes(t, target.Report) {
			if strings.HasSuffix(code, "_CREDENTIAL_WITHHELD") {
				t.Errorf("%s: the credential was withheld (%s), so this target proved "+
					"nothing about authentication", id, code)
			}
		}
	}

	// --- the two remote refusals are COMPLETED executions carrying a diagnosis ---
	//
	// This is the distinction the execution states exist for: the endpoint
	// answered and said no. svcdoctor executed the target perfectly, and the
	// finding is the product of that execution rather than a failure of it.
	remote := map[string]string{
		"pg-missing-database": "POSTGRES_DATABASE_NOT_FOUND",
		"redis-refused":       "REDIS_CREDENTIALS_REJECTED",
	}
	for id, wantCode := range remote {
		target := parsed.Targets[at(id)]
		if target.ExecutionState != "COMPLETED" {
			t.Errorf("%s: state = %s, want COMPLETED; a remote refusal is a completed "+
				"execution whose report carries the failure", id, target.ExecutionState)
			continue
		}
		codes := reportCodes(t, target.Report)
		if !containsCode(codes, wantCode) {
			t.Errorf("%s: findings %v, want one of them to be %s", id, codes, wantCode)
		}
		if target.ExecutionError != nil {
			t.Errorf("%s: carries an execution error (%+v); the endpoint refused it, "+
				"svcdoctor did not fail", id, target.ExecutionError)
		}
	}

	// --- the local failure is EXECUTION_FAILED and fabricates nothing ---
	local := parsed.Targets[at("local-resolver-failure")]
	if local.ExecutionState != "EXECUTION_FAILED" {
		t.Errorf("local-resolver-failure: state = %s, want EXECUTION_FAILED",
			local.ExecutionState)
	}
	if len(local.Report) != 0 && string(local.Report) != "null" {
		t.Error("local-resolver-failure carries a report; no byte reached the endpoint, " +
			"so there is nothing to report about it")
	}
	if local.ExecutionError == nil {
		t.Fatal("local-resolver-failure carries no execution error")
	}
	if local.ExecutionError.Class != "CREDENTIAL_RESOLUTION" {
		t.Errorf("local-resolver-failure: class = %q, want CREDENTIAL_RESOLUTION",
			local.ExecutionError.Class)
	}
	// It reached the same endpoint as redis-refused. A local resolution failure
	// must not be reported as anything the endpoint did.
	if strings.Contains(strings.ToUpper(local.ExecutionError.Message), "REJECT") ||
		strings.Contains(strings.ToUpper(local.ExecutionError.Message), "AUTH") {
		t.Errorf("local-resolver-failure describes an authentication outcome (%q); "+
			"svcdoctor could not obtain the credential and never presented one",
			local.ExecutionError.Message)
	}

	// --- and no credential reference reached the canonical document ---
	for _, path := range []string{unresolvable, wrongRedis, pgPassword, config} {
		if strings.Contains(stdout, path) {
			t.Errorf("a credential or configuration path reached the aggregate: %s", path)
		}
	}
	for _, secret := range []string{postgresPassword, kafkaPassword, rabbitPassword,
		redisTLSPassword} {
		if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
			t.Errorf("a fixture secret appeared on an output stream")
		}
	}

	// --- the run's own arithmetic reconciles ---
	if parsed.Summary.Targets != 6 {
		t.Errorf("summary counts %d targets, want 6", parsed.Summary.Targets)
	}
	if parsed.Summary.Completed != 5 {
		t.Errorf("summary counts %d completed, want 5", parsed.Summary.Completed)
	}
	if parsed.Summary.WithProblems != 2 {
		t.Errorf("summary counts %d targets with problems, want 2", parsed.Summary.WithProblems)
	}
	if !parsed.Summary.Incomplete {
		t.Error("a run with an EXECUTION_FAILED target is not marked incomplete")
	}

	// Exit 4: the run is incomplete, and incompleteness outranks the two
	// target-side problems because it qualifies every conclusion in the report.
	if code != 4 {
		t.Errorf("exit = %d, want 4; an execution failure makes the run incomplete, "+
			"and 4 outranks 1", code)
	}

	// --- no cross-target inference anywhere in the rendered output ---
	terminalCode, terminalOut, _ := runSvcdoctor(t, "run", "--config", config)
	if terminalCode != 4 {
		t.Errorf("the terminal form exited %d, want 4", terminalCode)
	}
	for _, phrase := range []string{
		"root cause", "common cause", "the network is", "because both",
	} {
		if strings.Contains(strings.ToLower(terminalOut), phrase) {
			t.Errorf("the terminal output says %q; svcdoctor measured six targets "+
				"independently and has no evidence of any relationship between them",
				phrase)
		}
	}
}

// TestSameEndpointDifferentAuthorityThroughRealFixtures is section 31.
//
// Two PostgreSQL targets on one host and port, differing only in the database
// they ask for. Neither may be deduplicated, and each must carry its own
// evidence — which is the whole reason an endpoint is not an identity.
//
// The two outcomes are deliberately different, so a shared report would be
// visible rather than merely suspected.
func TestSameEndpointDifferentAuthorityThroughRealFixtures(t *testing.T) {
	pgPassword := writeFile(t, "pg-password", postgresPassword+"\n")

	config := writeFile(t, "same-endpoint.yaml", fmt.Sprintf(`
version: 1
run:
  concurrency: 2
targets:
  - id: db-exists
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

  - id: db-absent
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
      database: no_such_database_exists
`,
		portPostgresTLS, caFile(t, "postgres"), postgresUser, pgPassword, postgresDatabase,
		portPostgresTLS, caFile(t, "postgres"), postgresUser, pgPassword))

	_, stdout, _ := runSvcdoctor(t, "run", "--config", config, "--output", "json")
	parsed := decode(t, stdout)

	if len(parsed.Targets) != 2 {
		t.Fatalf("%d targets, want 2; two logical targets on one endpoint must never "+
			"be deduplicated", len(parsed.Targets))
	}

	first, second := parsed.Targets[0], parsed.Targets[1]
	if first.TargetID != "db-exists" || second.TargetID != "db-absent" {
		t.Fatalf("target order = %q, %q, want the declared db-exists, db-absent",
			first.TargetID, second.TargetID)
	}

	if status := reportStatus(t, first.Report); status != "OK" {
		t.Errorf("db-exists: status = %q, want OK; findings %v",
			status, reportCodes(t, first.Report))
	}
	if codes := reportCodes(t, second.Report); !containsCode(codes, "POSTGRES_DATABASE_NOT_FOUND") {
		t.Errorf("db-absent: findings %v, want POSTGRES_DATABASE_NOT_FOUND", codes)
	}

	// The strongest statement of "not shared": the two documents differ.
	if string(first.Report) == string(second.Report) {
		t.Error("both targets carry the identical report document; one endpoint " +
			"produced one measurement and it was attributed twice")
	}
}

// containsCode reports whether a finding code is present.
func containsCode(codes []string, want string) bool {
	for _, code := range codes {
		if code == want {
			return true
		}
	}
	return false
}

// unusedJSON keeps the encoding/json import honest if a future edit removes the
// only use of it above.
var _ = json.Marshal
