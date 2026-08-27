//go:build integration

package rabbitmq

import (
	"strings"
	"testing"

	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// versions are the brokers docs/COMPATIBILITY.md is allowed to name.
//
// Every frozen wire fact is asserted against **each** of them rather than
// against one and assumed for the rest. Phase 8.0C measured all three offering
// different mechanism orders, which is exactly the kind of difference that
// silently becomes a dependency when only one version is tested.
var versions = []struct {
	name      string
	plainPort uint16
	tlsPort   uint16
	container string
}{
	{"3.13.7", port313, port313TLS, "svcd-rabbit-313"},
	{"4.0.9", port409, port409TLS, "svcd-rabbit-409"},
	{"4.2.0", portAMQP, portAMQPS, "svcd-rabbit"},
}

// The frozen negotiation window, asserted on every broker in the matrix.
//
// ADR 0070 fixes channel_max 1, frame_max 8192 and heartbeat 0. Phase 8.0C
// measured 4.2.0 **refusing** frame_max 4096, channel_max 0 and channel_max
// 2048 — silently, with no Close frame at all — so these are not free choices
// and a regression would look like an unexplained hang.
func TestFrozenTuneValuesAreAcceptedByEveryVersion(t *testing.T) {
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			truth := groundTruthJourney(t, "--port", itoa(v.tlsPort), "--tls",
				"--ca", "certs/server.crt", "--server-name", serverName,
				"--user", userApp, "--password", passApp)
			if !strings.HasPrefix(truth, "OPEN_OK") {
				t.Fatalf("ground truth: %q, want OPEN_OK", truth)
			}

			result := run(t, runOptions{port: v.tlsPort, username: userApp,
				password: passApp, tls: trustFixtureCA(t)})

			if got := oneNodeAt(t, result, stepOpen).State(); got != domain.StatePass {
				t.Fatalf("connection open = %s, want PASS: the frozen Tune-Ok was refused", got)
			}
			auth := oneNodeAt(t, result, stepAuth)
			for _, tc := range []struct {
				key  domain.AttributeKey
				want string
			}{
				{servicerabbitmq.AttrChannelMaxSelected, "1"},
				{servicerabbitmq.AttrFrameMaxSelected, "8192"},
				{servicerabbitmq.AttrHeartbeatSelected, "0"},
			} {
				if got := attrText(t, auth, tc.key); got != tc.want {
					t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
				}
			}
			// The polite epilogue completed, and it can never change a verdict.
			if got := attrText(t, oneNodeAt(t, result, stepOpen),
				servicerabbitmq.AttrGracefulClose); got != "true" {
				t.Errorf("graceful close = %q, want true", got)
			}
		})
	}
}

// `authentication_failure_close`, asserted as a consequence rather than a flag.
//
// Without the capability every one of these brokers sends **no AMQP frame at
// all** and simply closes the socket about three seconds later — measured with
// the ground-truth client, which reproduces exactly that when it omits the
// capability. So a run that reports CREDENTIALS_REJECTED, promptly and as a
// complete run, is proof svcdoctor advertised it (ADR 0068 §3).
func TestAuthenticationFailureCloseIsRequestedOnEveryVersion(t *testing.T) {
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			result := run(t, runOptions{port: v.tlsPort, username: userApp,
				password: "definitely-not-the-password", tls: trustFixtureCA(t)})

			if !hasCode(result, diagnosisrabbitmq.CodeCredentialsRejected) {
				t.Fatalf("got %v, want RABBITMQ_CREDENTIALS_REJECTED; a bare socket close "+
					"would have produced something weaker", codes(result))
			}
			if result.Incomplete() {
				t.Error("the refusal arrived as a frame, so the run is complete")
			}
			auth := oneNodeAt(t, result, stepAuth)
			if got := auth.FailureClass(); got == domain.FailureExecLocalTimeout {
				t.Error("the refusal was read as svcdoctor's own timeout, which is what " +
					"a missing authentication_failure_close looks like")
			}
			// The reply code itself lives on the Connection.Open node, because an
			// authentication refusal carries one sanitized sentence with no
			// distinction to extract. The failure class is the contract here, and
			// it is reachable only when a 403 Close frame actually arrived.
			if got := auth.FailureClass(); got != domain.FailureAuthCredentialsRejected {
				t.Errorf("failure class = %s, want AUTH_CREDENTIALS_REJECTED", got)
			}
		})
	}
}

// PLAIN is selected by name, never by position.
//
// The three brokers advertise different orders — `AMQPLAIN PLAIN`,
// `ANONYMOUS AMQPLAIN PLAIN` and `ANONYMOUS PLAIN AMQPLAIN`. If selection were
// positional, at most one of them would work (ADR 0068 §2).
func TestMechanismSelectionIgnoresOrderOnEveryVersion(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			truth := groundTruthJourney(t, "--port", itoa(v.tlsPort), "--tls",
				"--ca", "certs/server.crt", "--server-name", serverName,
				"--user", userApp, "--password", passApp)
			if i := strings.Index(truth, "mechs="); i >= 0 {
				rest := truth[i+len("mechs="):]
				if j := strings.Index(rest, " tune="); j >= 0 {
					seen[rest[:j]] = true
				}
			}

			result := run(t, runOptions{port: v.tlsPort, username: userApp,
				password: passApp, tls: trustFixtureCA(t)})

			auth := oneNodeAt(t, result, stepAuth)
			if got := attrText(t, auth, servicerabbitmq.AttrMechanismSelected); got != "PLAIN" {
				t.Errorf("mechanism selected = %q, want PLAIN", got)
			}
			// ANONYMOUS is observed and never selected, permanently.
			start := oneNodeAt(t, result, stepStart)
			mechs := attrText(t, start, servicerabbitmq.AttrMechanismsOffered)
			if strings.Contains(mechs, "ANONYMOUS") {
				if got := attrText(t, start, servicerabbitmq.AttrAnonymousOffered); got != "true" {
					t.Errorf("anonymous offered = %q, want true when the set contains it", got)
				}
			}
			if sorted := isSortedWords(mechs); !sorted {
				t.Errorf("mechanisms offered = %q, want svcdoctor's own sorted set", mechs)
			}
		})
	}

	if len(seen) < 2 {
		t.Errorf("the matrix observed %d distinct mechanism orders (%v); this guard is "+
			"vacuous unless the brokers actually disagree", len(seen), keysOf(seen))
	}
}

// The observed product and version are recorded and never acted on.
func TestProductIdentityIsObservedOnEveryVersion(t *testing.T) {
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			result := run(t, runOptions{port: v.tlsPort, username: userApp,
				password: passApp, tls: trustFixtureCA(t)})

			start := oneNodeAt(t, result, stepStart)
			if got := attrText(t, start, servicerabbitmq.AttrProduct); got != "RabbitMQ" {
				t.Errorf("product = %q, want RabbitMQ", got)
			}
			if got := attrText(t, start, servicerabbitmq.AttrVersion); got != v.name {
				t.Errorf("version = %q, want %q", got, v.name)
			}
		})
	}
}

// --- small helpers ----------------------------------------------------------

func itoa(p uint16) string {
	digits := ""
	if p == 0 {
		return "0"
	}
	for p > 0 {
		digits = string(rune('0'+p%10)) + digits
		p /= 10
	}
	return digits
}

func isSortedWords(s string) bool {
	words := strings.Fields(s)
	for i := 1; i < len(words); i++ {
		if words[i-1] > words[i] {
			return false
		}
	}
	return true
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
