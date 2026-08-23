package cli

import (
	"strings"
	"testing"

	adapterpostgres "github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// This file replaces TestPostgresStillAcceptsInertTLSFlags and
// TestKafkaStillRefusesInertTLSFlags, the two tripwires ADR 0058 section 14 left
// in place so its gaps could not drift without a decision. The decision is
// ADR 0060 and it closed the gap by making PostgreSQL agree with Kafka, so the
// tripwires are gone and these pin the contract they were guarding.

// tlsOnlyFlags is every flag that describes a handshake, with the message each
// must produce when the run performs none.
//
// Written out per flag rather than derived, because the message is the part an
// operator reads and a generated one is a string nobody reviewed.
var tlsOnlyFlags = []struct {
	name string
	args []string
	want string
}{
	{"ca-file", []string{"--tls-ca-file", "/nonexistent/ca.pem"},
		"--tls-ca-file has no effect with --tls disable"},
	{"server-name", []string{"--tls-server-name", "other.example"},
		"--tls-server-name has no effect with --tls disable"},
	{"insecure", []string{"--tls-insecure"},
		"--tls-insecure has no effect with --tls disable"},
}

// TestTLSOnlyFlagsAreRefusedWhenTLSIsDisabled is ADR 0060's central clause, for
// both services at once.
//
// # Both services, one loop, deliberately
//
// The defect this closed was two services holding one contract in two places and
// disagreeing about it. A test that checked them separately would let them
// diverge again in exactly the way that was not noticed the first time, so the
// same table drives both and a divergence is a failure rather than a gap.
func TestTLSOnlyFlagsAreRefusedWhenTLSIsDisabled(t *testing.T) {
	for _, service := range []struct {
		name string
		base []string
	}{
		{"postgres", []string{"diagnose", "postgres",
			"--host", "10.20.30.40", "--user", "svcdoctor", "--tls", "disable"}},
		{"kafka", []string{"diagnose", "kafka",
			"--host", "10.20.30.40", "--sasl-mechanism", "PLAIN", "--tls", "disable"}},
	} {
		for _, flag := range tlsOnlyFlags {
			t.Run(service.name+"/"+flag.name, func(t *testing.T) {
				h := newHarness(app.Result{}, nil)
				code := h.run(append(append([]string{}, service.base...), flag.args...)...)

				if code != ExitUsage {
					t.Fatalf("exit = %d, want %d (a TLS-only flag under --tls disable "+
						"describes a handshake that will not happen)", code, ExitUsage)
				}
				if got := h.stderr.String(); !strings.Contains(got, flag.want) {
					t.Errorf("stderr = %q, want it to contain %q", got, flag.want)
				}
				// Refused before anything was dialled: an invalid invocation is a
				// fact about the input, and spending a connection to discover it
				// would report svcdoctor's own input as the endpoint's behaviour.
				if h.stdout.String() != "" {
					t.Errorf("a refused invocation wrote to stdout: %q", h.stdout.String())
				}
				if h.calls+h.kafkaCalls != 0 {
					t.Error("a refused invocation reached the composition root")
				}
			})
		}
	}
}

// TestTLSOnlyFlagsAreAcceptedWhenTLSIsRequired is the other half, and the reason
// the refusal above is narrow.
//
// ADR 0060 tightened one combination. It did not deprecate a flag, and a run
// that actually performs a handshake still takes all three.
func TestTLSOnlyFlagsAreAcceptedWhenTLSIsRequired(t *testing.T) {
	h := newHarness(app.Result{}, nil)
	code := h.run("diagnose", "postgres",
		"--host", "10.20.30.40", "--user", "svcdoctor",
		"--tls", "require", "--tls-server-name", "db.internal", "--tls-insecure")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, h.stderr.String())
	}
	if got := h.captured.TLSOptions.ServerName; got != "db.internal" {
		t.Errorf("ServerName = %q, want the override", got)
	}
	if !h.captured.TLSOptions.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want the flag honoured")
	}
}

// TestDisablingTLSStillWorksWithoutTLSFlags guards the compatibility surface
// ADR 0060 section 5 promised not to touch.
//
// The tightening is exactly three combinations. `--tls disable` on its own is
// the ordinary plaintext invocation, it is what the overwhelming majority of
// affected runbooks contain, and it is unchanged.
func TestDisablingTLSStillWorksWithoutTLSFlags(t *testing.T) {
	h := newHarness(app.Result{}, nil)
	if code := h.run("diagnose", "postgres",
		"--host", "10.20.30.40", "--user", "svcdoctor", "--tls", "disable"); code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, h.stderr.String())
	}
	if h.captured.TLS != adapterpostgres.TLSDisabled {
		t.Errorf("TLS = %v, want TLSDisabled", h.captured.TLS)
	}
}

// TestTheRefusalNamesOneFlagAtATime pins the message shape.
//
// An operator who passed all three is told about one, fixes it, and is told
// about the next. Listing all three at once reads as though they interact.
func TestTheRefusalNamesOneFlagAtATime(t *testing.T) {
	h := newHarness(app.Result{}, nil)
	code := h.run("diagnose", "postgres",
		"--host", "10.20.30.40", "--user", "svcdoctor", "--tls", "disable",
		"--tls-ca-file", "/nonexistent/ca.pem",
		"--tls-server-name", "other.example", "--tls-insecure")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}

	got := h.stderr.String()
	if !strings.Contains(got, "--tls-ca-file has no effect") {
		t.Errorf("stderr = %q, want the first flag named", got)
	}
	for _, other := range []string{"--tls-server-name has no effect", "--tls-insecure has no effect"} {
		if strings.Contains(got, other) {
			t.Errorf("stderr = %q, want one flag per message, not %q", got, other)
		}
	}
}

// TestTheCAFileIsNotReadWhenTLSIsDisabled proves the refusal happens first.
//
// It matters because the two rejections have different messages and only one of
// them is the truth. A missing file under `--tls disable` must be reported as
// *the flag does not apply here*, not as *that file is unreadable*: the second
// invites an operator to go and create a trust file for a run that would ignore
// it.
func TestTheCAFileIsNotReadWhenTLSIsDisabled(t *testing.T) {
	h := newHarness(app.Result{}, nil)
	code := h.run("diagnose", "postgres",
		"--host", "10.20.30.40", "--user", "svcdoctor",
		"--tls", "disable", "--tls-ca-file", "/nonexistent/ca.pem")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if got := h.stderr.String(); strings.Contains(got, "no such file") {
		t.Errorf("stderr = %q, want the inapplicability, not the filesystem error", got)
	}
}
