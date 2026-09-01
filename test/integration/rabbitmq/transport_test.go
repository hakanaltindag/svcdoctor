//go:build integration

package rabbitmq

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// portClosed is a loopback port the fixture deliberately never binds.
const portClosed = 56699

// blackhole is TEST-NET-3 (RFC 5737). Packets to it are discarded rather than
// refused, which is what makes RAB-15 a local timeout instead of a refusal.
const blackhole = "203.0.113.1"

// RAB-14 — the host answers and the port does not: a TCP refusal.
//
// This is a proven target-side fact, and it must be distinguishable from RAB-15,
// where svcdoctor's own budget expired and nothing about the target was proven.
func TestRAB14TCPRefused(t *testing.T) {
	result := run(t, runOptions{port: portClosed, stepTimeout: 3 * time.Second})

	tcp := oneNodeAt(t, result, stepTCP)
	if tcp.State() != domain.StateFail {
		t.Fatalf("tcp = %s, want FAIL for a refused connection", tcp.State())
	}
	if got := tcp.FailureClass(); got == domain.FailureExecLocalTimeout {
		t.Error("a refusal was classified as svcdoctor's own timeout")
	}
	if hasNodeAt(t, result, stepStart) {
		t.Error("the protocol exchange continued past a failed connection")
	}
	if result.Incomplete() {
		t.Error("a refusal svcdoctor observed is a complete run, not an incomplete one")
	}
	if !hasCode(result, diagnosisrabbitmq.CodeConnectionStartNotCompleted) &&
		len(result.Report().Findings()) == 0 {
		t.Errorf("a refused connection produced no finding at all; got %v", codes(result))
	}
}

// RAB-15 — packets are dropped, so svcdoctor's own budget ends the run.
//
// A local deadline is not proof of remote failure. The run must be INCOMPLETE,
// the stage UNKNOWN rather than FAIL, and nothing may blame the target.
func TestRAB15LocalTimeoutIsNotARemoteFailure(t *testing.T) {
	result := run(t, runOptions{
		host: blackhole, port: 5672,
		timeout: 12 * time.Second, stepTimeout: 3 * time.Second,
	})

	tcp := oneNodeAt(t, result, stepTCP)
	if tcp.State() == domain.StateFail {
		t.Error("a dropped packet was reported as a proven connection failure")
	}
	if tcp.State() != domain.StateUnknown {
		t.Errorf("tcp = %s, want UNKNOWN", tcp.State())
	}
	if got := tcp.FailureClass(); got != domain.FailureExecLocalTimeout {
		t.Errorf("failure class = %s, want EXEC_LOCAL_TIMEOUT", got)
	}
	if !result.Incomplete() {
		t.Error("a run stopped by svcdoctor's own budget is incomplete")
	}
	lower := strings.ToLower(reportText(result))
	for _, blame := range []string{
		"the endpoint timed out", "the broker is slow", "the target is down",
		"endpoint is unreachable",
	} {
		if strings.Contains(lower, blame) {
			t.Errorf("svcdoctor's own timeout was described as a target problem: %q", blame)
		}
	}
}

// RAB-16 — the broker process is stopped while the host stays up.
//
// The dedicated container exists so stopping it cannot perturb a scenario
// running against another broker. It is restarted before the test returns,
// whatever happens.
func TestRAB16BrokerStopped(t *testing.T) {
	const container = "svcd-rabbit-stop"

	if out, err := exec.Command("docker", "stop", container).CombinedOutput(); err != nil {
		t.Fatalf("stopping %s: %v\n%s", container, err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "start", container).CombinedOutput(); err != nil {
			t.Errorf("restarting %s: %v\n%s", container, err, out)
		}
	})

	// Ground truth: the port no longer answers at all.
	if out, _ := exec.Command("docker", "inspect", container,
		"--format", "{{.State.Running}}").CombinedOutput(); strings.TrimSpace(string(out)) != "false" {
		t.Fatalf("ground truth: %s is still running", container)
	}

	result := run(t, runOptions{port: portStopped, stepTimeout: 3 * time.Second})

	if got := oneNodeAt(t, result, stepTCP).State(); got != domain.StateFail {
		t.Errorf("tcp = %s, want FAIL against a stopped broker", got)
	}
	if hasNodeAt(t, result, stepStart) {
		t.Error("a protocol exchange was recorded against a stopped broker")
	}
	if result.Incomplete() {
		t.Error("an observed refusal is a complete run")
	}
}

// RAB-18 — the management HTTP listener, targeted as AMQP.
//
// It speaks HTTP and never answers Connection.Start, so the protocol stage must
// fail without inventing a broker. The port is never semantic: nothing here may
// say "this looks like the management port" (ADR 0067 §3).
func TestRAB18ManagementPortTargetedAsAMQP(t *testing.T) {
	// Ground truth: it really is an HTTP server.
	//
	// The status is 401 rather than 200, because the fixture restores RabbitMQ's
	// loopback restriction on `guest` and that applies to the management API as
	// well. Either answer proves the point this scenario needs — the listener
	// speaks HTTP — so the assertion is on the protocol, not on the credential.
	out, _ := exec.Command("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
		"http://127.0.0.1:56673/api/overview").CombinedOutput()
	if code := strings.TrimSpace(string(out)); code != "200" && code != "401" {
		t.Fatalf("ground truth: the management port answered %q, want an HTTP status", code)
	}

	result := run(t, runOptions{port: portMgmt, stepTimeout: 5 * time.Second})

	if got := oneNodeAt(t, result, stepTCP).State(); got != domain.StatePass {
		t.Errorf("tcp = %s: the HTTP listener accepts connections", got)
	}
	start := oneNodeAt(t, result, stepStart)
	if start.State() == domain.StatePass {
		t.Fatal("an HTTP listener was reported as speaking AMQP 0-9-1")
	}
	if hasNodeAt(t, result, stepAuth) {
		t.Error("authentication was attempted against a peer that never spoke AMQP")
	}
	// # Where the ban applies, and where it cannot
	//
	// ADR 0067 section 3's rule is behavioural: "the port is never semantic — a
	// TLS plan comes from --tls and never from the port number." What must not
	// happen is svcdoctor *deciding* or *asserting* something from 15672.
	//
	// So the substring ban belongs on the surfaces that state facts — the
	// summary, the detail and the recorded attributes. It does **not** belong on
	// a recommendation, because the frozen recommendation deliberately lists the
	// candidates an operator should rule out, and one of them is the management
	// HTTP API. Banning the word there bans the product's own correct prose.
	//
	// This assertion used to cover recommendations too, and it passed only
	// because the scenario usually timed out: the rule that produces this text
	// fires on StateFail and skips a local-timeout UNKNOWN, so the report was
	// empty of findings and the ban had nothing to match. The v0.4.0 release
	// gate hit the fast path and the contradiction surfaced. A guard that passes
	// when the product learns *less* is not a guard.
	//
	// The recommendation is pinned exactly instead, which is stronger than a
	// substring ban on that surface: any drift toward a real claim fails here
	// and has to be read by a human.
	var claims strings.Builder
	for _, finding := range result.Report().Findings() {
		claims.WriteString(finding.Summary())
		claims.WriteString(" ")
		claims.WriteString(finding.Detail())
		claims.WriteString(" ")
	}
	for _, node := range result.Report().Graph().Nodes() {
		for key, value := range node.Attributes() {
			claims.WriteString(" " + string(key) + "=" + value.String())
		}
	}
	lower := strings.ToLower(claims.String())
	for _, wrong := range []string{"management", "http", "web ui", "port 15672"} {
		if strings.Contains(lower, wrong) {
			t.Errorf("svcdoctor inferred a service from a port number: %q", wrong)
		}
	}

	const frozenRecommendation = "Confirm the port carries AMQP 0-9-1 rather than the " +
		"management HTTP API, a TLS listener addressed as plaintext, or another protocol"
	for _, finding := range result.Report().Findings() {
		for _, r := range finding.Recommendations() {
			if r.Action() != frozenRecommendation {
				t.Errorf("an unexpected recommendation reached this scenario:\n  %s\n\n"+
					"Only the frozen enumeration is allowed here. Anything else has to be "+
					"read against ADR 0067 section 3 before it ships.", r.Action())
			}
		}
	}
}

// RAB-24 and RAB-25 — address literals are first-class targets.
//
// ADR 0059 is a graph-shape decision: an address is not a name, so a run given
// one resolves nothing and records **no dns.lookup node at all**. That is what
// makes a DNS finding structurally unreachable for a literal rather than
// suppressed, and it must hold for both families.
func TestRAB24And25AddressLiterals(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		port       uint16
	}{
		{"RAB-24 IPv4 literal", "127.0.0.1", portAMQP},
		{"RAB-25 IPv6 literal", "::1", 56679},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, runOptions{host: tc.host, port: tc.port})

			if hasNodeAt(t, result, stepDNS) {
				t.Error("an address literal produced a dns.lookup node; ADR 0059 records " +
					"none at all, which is what makes a DNS finding unreachable here")
			}
			if got := oneNodeAt(t, result, stepTCP).State(); got != domain.StatePass {
				t.Fatalf("tcp = %s, want PASS", got)
			}
			if got := oneNodeAt(t, result, stepStart).State(); got != domain.StatePass {
				t.Errorf("connection start = %s, want PASS", got)
			}
			for _, f := range result.Report().Findings() {
				if strings.HasPrefix(f.Code().String(), "DNS_") {
					t.Errorf("a DNS finding reached a literal target: %s", f.Code())
				}
			}
		})
	}
}
