//go:build integration

package kafka

import (
	"os/exec"
	"strings"
	"testing"
	"time"
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
