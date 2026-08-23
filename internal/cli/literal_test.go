package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// Phase 6.7 — what the command line does with an address literal.
//
// The CLI is where the canonical spelling is decided, because the credential is
// built here and bound to an endpoint that canonicalizes on its own. If the two
// halves saw different spellings the run would refuse a credential the operator
// supplied correctly.

// TestALiteralTargetIsCanonicalizedBeforeTheRun pins that both halves — the
// parameters and the credential — receive one spelling.
func TestALiteralTargetIsCanonicalizedBeforeTheRun(t *testing.T) {
	for in, want := range map[string]string{
		"10.20.30.40":           "10.20.30.40",
		"2001:0db8:0:0:0:0:0:1": "2001:db8::1",
		"::ffff:192.0.2.1":      "192.0.2.1",
		"::1":                   "::1",
		"DB.Prod.Internal":      "DB.Prod.Internal", // a name is never rewritten
	} {
		t.Run(in, func(t *testing.T) {
			h := newHarness(app.Result{}, nil)
			if code := h.run("diagnose", "postgres",
				"--host", in, "--user", "svcdoctor", "--tls", "disable"); code != ExitOK {
				t.Fatalf("exit = %d, stderr = %s", code, h.stderr.String())
			}
			if h.captured.Host != want {
				t.Fatalf("params.Host = %q, want %q", h.captured.Host, want)
			}
		})
	}
}

// The credential is bound to the canonical spelling, so a non-canonical `--host`
// still authorizes the run it names.
func TestACredentialBindsToTheCanonicalLiteral(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if err := os.WriteFile(path, []byte("canary\n"), 0o600); err != nil {
		t.Fatalf("writing the password file: %v", err)
	}

	h := newHarness(app.Result{}, nil)
	code := h.run("diagnose", "kafka",
		"--host", "2001:0db8:0:0:0:0:0:1", "--port", "9093",
		"--sasl-mechanism", "PLAIN", "--user", "svcdoctor",
		"--password-file", path, "--tls", "disable")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, h.stderr.String())
	}

	endpoint := h.capturedKafka.Credential.Endpoint()
	if endpoint.Host() != "2001:db8::1" {
		t.Fatalf("the credential is bound to %q, want the canonical spelling", endpoint.Host())
	}
	if endpoint.String() != "[2001:db8::1]:9093" {
		t.Fatalf("the credential endpoint renders as %q, want a bracketed IPv6 endpoint",
			endpoint.String())
	}
	if h.capturedKafka.Host != endpoint.Host() {
		t.Fatalf("the run's host %q and the credential's %q disagree",
			h.capturedKafka.Host, endpoint.Host())
	}
}

// A host svcdoctor declines to measure is bad input: exit 2, the flag named, and
// no run performed.
func TestAZonedLiteralIsAnInvocationError(t *testing.T) {
	for _, service := range []string{"postgres", "kafka"} {
		t.Run(service, func(t *testing.T) {
			h := newHarness(app.Result{}, nil)
			args := []string{"diagnose", service, "--host", "fe80::1%en0", "--tls", "disable"}
			switch service {
			case "postgres":
				args = append(args, "--user", "svcdoctor")
			case "kafka":
				args = append(args, "--sasl-mechanism", "PLAIN")
			}

			if code := h.run(args...); code != ExitUsage {
				t.Fatalf("exit = %d, want %d", code, ExitUsage)
			}
			if h.calls != 0 || h.kafkaCalls != 0 {
				t.Fatal("a refused host still started a run")
			}
			stderr := h.stderr.String()
			if !strings.Contains(stderr, "--host") {
				t.Errorf("the error does not name the flag: %s", stderr)
			}
			if !strings.Contains(stderr, "zone") {
				t.Errorf("the error does not name the limitation: %s", stderr)
			}
			if h.stdout.String() != "" {
				t.Errorf("a refused invocation wrote to stdout: %s", h.stdout.String())
			}
		})
	}
}

// A string that only looks like an address is a name, and is passed through for
// the resolver to judge rather than refused here.
func TestAHostThatOnlyLooksLikeAnAddressIsAccepted(t *testing.T) {
	for _, host := range []string{"10.0.0.256", "010.0.0.1", "1.2.3"} {
		t.Run(host, func(t *testing.T) {
			h := newHarness(app.Result{}, nil)
			if code := h.run("diagnose", "postgres",
				"--host", host, "--user", "svcdoctor", "--tls", "disable"); code != ExitOK {
				t.Fatalf("exit = %d, stderr = %s", code, h.stderr.String())
			}
			if h.captured.Host != host {
				t.Fatalf("params.Host = %q, want the input verbatim", h.captured.Host)
			}
		})
	}
}

// `--tls-server-name` is orthogonal to `--host`: the connection target and the
// verified identity are two settings, and neither rewrites the other.
func TestAServerNameOverrideDoesNotChangeTheConnectionTarget(t *testing.T) {
	h := newHarness(app.Result{}, nil)
	code := h.run("diagnose", "kafka",
		"--host", "10.20.30.40", "--sasl-mechanism", "PLAIN",
		"--tls-server-name", "kafka.internal")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, h.stderr.String())
	}

	if h.capturedKafka.Host != "10.20.30.40" {
		t.Fatalf("params.Host = %q, want the address", h.capturedKafka.Host)
	}
	if got := h.capturedKafka.TLS.ServerName; got != "kafka.internal" {
		t.Fatalf("ServerName = %q, want the override", got)
	}
}
