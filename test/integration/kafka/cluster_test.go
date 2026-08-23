//go:build integration

package kafka

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// Cluster reconfiguration, so every scenario is repeatable with one command
// rather than a paragraph of shell in a README.
//
// Failures are injected by changing what a broker *advertises*, never by
// changing svcdoctor. That is the whole point: the product claim is about what a
// real cluster reports, so the fixture has to be a real cluster reporting it.
//
// Only the EXTERNAL listener is touched. Inter-broker traffic uses INTERNAL, so
// a broker advertising an unreachable address to clients stays a healthy member
// of the cluster — which is exactly the production failure mode, and is why the
// bootstrap keeps working while the advertised endpoint does not.

const composeFile = "env/compose-sasl.yaml"

func compose(t *testing.T, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"compose", "-f", composeFile}, args...)...)
	cmd.Dir = "."
	cmd.Env = append(environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func environ() []string {
	return append([]string{}, "PATH=/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin", "HOME="+home())
}

func home() string {
	out, err := exec.Command("sh", "-c", "echo $HOME").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// reconfigure recreates one broker with new environment and waits for it to
// serve again. The overrides are compose variables, so the change is visible in
// compose-sasl.yaml rather than hidden in a test.
func reconfigure(t *testing.T, service string, overrides ...string) {
	t.Helper()
	compose(t, overrides, "up", "-d", "--force-recreate", service)
	waitReady(t)
}

// restore puts every broker back to the healthy configuration.
func restore(t *testing.T) {
	t.Helper()
	compose(t, nil, "up", "-d", "--force-recreate")
	waitReady(t)
}

// waitReady blocks until all three brokers are registered again.
//
// Waiting for one broker's listener to bind is not enough: a recreated broker
// re-registers with the KRaft quorum a moment later, and a run that started in
// that window saw a two-broker cluster and diagnosed it correctly — which made
// the *test* wrong, not svcdoctor. The readiness condition therefore has to be
// the condition the scenario depends on, which is the broker count Metadata
// reports.
func waitReady(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if registeredBrokers(t) == 3 {
			// The quorum agrees; give the external listeners a moment to bind.
			time.Sleep(1500 * time.Millisecond)
			if registeredBrokers(t) == 3 {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("cluster did not reach three registered brokers (last count %d)",
		registeredBrokers(t))
}

// registeredBrokers asks the cluster over its own internal listener, so the
// count does not depend on anything the scenario is currently breaking.
func registeredBrokers(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("docker", "exec", "svcd-sasl-1",
		"/opt/kafka/bin/kafka-broker-api-versions.sh",
		"--bootstrap-server", "broker-1:9094")
	cmd.Env = environ()
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	return strings.Count(string(out), "id: ")
}

// waitSCRAMReady blocks until a recreated broker can actually authenticate a
// SCRAM principal, which is a later moment than being registered.
//
// It is called by the SCRAM tests rather than from waitReady, deliberately. The
// advertised-failure scenarios call waitReady against a cluster they have just
// broken on purpose, and probing SCRAM there would run a full diagnosis — sweep
// included — against unreachable advertised addresses once a second. That turned
// four scenarios from seconds into minutes. Readiness belongs where the
// dependency is.
//
// # Why registration is not the readiness condition
//
// SCRAM verifiers live in the KRaft metadata log, and each broker's
// ScramPublisher applies them to its credential cache **asynchronously after
// startup**. A broker therefore registers with the quorum, binds its listener
// and answers ApiVersions and SaslHandshake — all while its SCRAM cache is still
// cold. Authentication against it fails, and the failure is a broker-side
// rejection that is indistinguishable from a wrong password.
//
// That is exactly how it presented during Phase 6.2: the SCRAM tests passed when
// run on their own and failed under `make integration-kafka`, because the suite
// force-recreates brokers in cluster_test.go and scram_test.go runs afterwards.
// It read as "SCRAM is broken" for an afternoon while SCRAM was correct.
//
// There is no supported command that reports when the cache has warmed —
// kafka-configs --describe returns as soon as the record is in the config view,
// which is earlier — so the readiness condition is the operation the scenario
// depends on: a real SCRAM authentication over the real listener.
func waitSCRAMReady(t *testing.T) {
	t.Helper()

	ensureSCRAMPrincipals(t)

	deadline := time.Now().Add(60 * time.Second)
	for {
		if scramAuthenticates(t) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no broker accepted the SCRAM principal within the readiness window; " +
				"the credential exists in the config view, so this is the ScramPublisher " +
				"cache rather than a missing user")
		}
		time.Sleep(time.Second)
	}
}

// ensureSCRAMPrincipals re-creates the SCRAM users, idempotently.
//
// # Why this is needed at all, which is not obvious
//
// compose-sasl.yaml mounts only ./certs and ./jaas.conf. **There is no named
// volume for the KRaft data directory**, so a broker's metadata log lives in its
// container's writable layer — and `up -d --force-recreate`, which restore() and
// reconfigure() both use, discards it. The cluster reformats, and every SCRAM
// credential created by the Makefile's kafka-scram-users step is gone.
//
// Nothing before Phase 6.2 noticed, because PLAIN credentials live in jaas.conf
// which is a bind mount and survives. SCRAM verifiers live in the metadata log,
// which does not.
//
// Adding a volume would fix it in one line and change what every other test
// depends on: those tests assume each `kafka-up` starts from an empty cluster,
// and `kafka-down -v` exists to guarantee it. Re-provisioning here is the
// narrower change — it makes the SCRAM tests independent of how many recreates
// ran before them, and it touches nothing else.
//
// kafka-configs is idempotent for this: adding a SCRAM config that already
// exists overwrites it with the same value.
func ensureSCRAMPrincipals(t *testing.T) {
	t.Helper()

	for _, principal := range []struct{ name, password string }{
		{scramIdentity, scramSecret},
		{scramEscapedIdentity, scramEscapedSecret},
	} {
		cmd := exec.Command("docker", "exec", "svcd-sasl-1",
			"/opt/kafka/bin/kafka-configs.sh",
			"--bootstrap-server", "broker-1:9094",
			"--alter", "--add-config",
			"SCRAM-SHA-256=[iterations=4096,password="+principal.password+"]",
			"--entity-type", "users", "--entity-name", principal.name)
		cmd.Env = environ()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("creating SCRAM principal %q: %v\n%s", principal.name, err, out)
		}
	}
}

// scramAuthenticates reports whether the SCRAM principal can authenticate right
// now, using the same wire path the suite exercises.
func scramAuthenticates(t *testing.T) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	endpoint, err := security.NewEndpoint(bootstrapHost, bootstrapPort)
	if err != nil {
		t.Fatalf("security.NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(
		endpoint, scramIdentity, security.NewSecret(scramSecret))
	if err != nil {
		t.Fatalf("security.NewCredential: %v", err)
	}

	vantage, err := domain.NewLocalVantage("validation-host.svcdoctor.test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	result, err := app.DiagnoseKafka(ctx, app.KafkaParams{
		Host: bootstrapHost, Port: bootstrapPort,
		Mechanism:   scramMechanism,
		Credential:  credential,
		Resolver:    dns.SystemResolver{},
		Dialer:      tcp.SystemDialer{},
		TLS:         &transport.TLSOptions{RootCAs: caPool(t)},
		StepTimeout: 5 * time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-readiness",
	})
	if err != nil {
		return false
	}
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() == servicekafka.StepSASLAuthenticate {
			return node.State() == domain.StatePass
		}
	}
	return false
}
