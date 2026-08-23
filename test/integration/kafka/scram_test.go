//go:build integration

package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// Kafka SASL/SCRAM-SHA-256 against the real three-broker KRaft cluster.
//
// # Why this file cannot be replaced by unit tests
//
// The unit suites drive scripted peers that this repository also wrote, so they
// prove svcdoctor agrees with itself. SCRAM is the one mechanism where that is
// not enough: the proof is a function of the salt and iteration count the broker
// chose, of the exact bytes of the AuthMessage, and of an escaping rule that had
// never been exercised anywhere in this repository before Phase 6.2. A single
// byte wrong in any of them produces a broker that says "authentication failed",
// which is indistinguishable from a wrong password unless a real broker is on
// the other end saying yes to the correct one.
//
// The principals come from the Makefile's kafka-scram-users step. KRaft keeps
// SCRAM verifiers in the metadata log rather than in jaas.conf, so they are
// created after the quorum forms.
const (
	scramMechanism = "SCRAM-SHA-256"

	scramIdentity = "svcdoctor-scram"
	scramSecret   = "svcdoctor-scram-canary"

	// A principal whose name must be escaped as `a=2Cb=3Dc` to reach the broker
	// intact. RFC 5802 section 5.1 requires it, PostgreSQL never needed it
	// because it sends an empty username, and Phase 6.2a found no escaping code
	// of any kind in this repository.
	scramEscapedIdentity = "a,b=c"
	scramEscapedSecret   = "escaped-name-canary"
)

func scramOptions(t *testing.T) options {
	t.Helper()

	// The suite force-recreates brokers in cluster_test.go, and a recreated
	// broker warms its SCRAM credential cache asynchronously after it starts
	// answering. Without this wait the first SCRAM test authenticates against a
	// broker that has the verifier written but not yet loaded, and the failure
	// is indistinguishable from a wrong password.
	waitSCRAMReady(t)

	o := defaults(t)
	o.mechanism = scramMechanism
	o.identity, o.secret = scramIdentity, scramSecret
	return o
}

// TestRealSCRAMAuthenticationReachesMetadata is the Phase 6.2 integration gate.
//
// It proves the whole extracted core against a peer that did not come from this
// repository: the nonce svcdoctor drew, the salt and iteration count the broker
// chose, the PBKDF2 performed in the wire package, the proof assembled in
// internal/sasl/scram, and the broker's own signature verified back.
func TestRealSCRAMAuthenticationReachesMetadata(t *testing.T) {
	result := diagnose(t, scramOptions(t))

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("authentication nodes = %d, want exactly 1", len(auth))
	}
	if got := auth[0].State(); got != domain.StatePass {
		t.Fatalf("authentication state = %s, want PASS: a real broker accepted nothing", got)
	}

	metadata := nodesOf(result, servicekafka.StepMetadata)
	if len(metadata) != 1 || metadata[0].State() != domain.StatePass {
		t.Fatalf("metadata did not complete after SCRAM: %v", metadata)
	}

	if got := result.Report().Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("summary status = %s, want OK", got)
	}
	if codes := codesOf(result); len(codes) != 0 {
		t.Errorf("a healthy SCRAM run produced findings: %v", codes)
	}
}

// TestRealSCRAMWithAnEscapedUsername is the test the RFC vectors cannot stand in
// for.
//
// A vector proves svcdoctor escapes `,` and `=` the way the RFC says. Only a
// real broker proves the broker un-escapes them the same way — and that the
// escaped form is what the AuthMessage both sides sign was built from. Getting
// this wrong fails as "authentication failed", which reads exactly like a wrong
// password.
func TestRealSCRAMWithAnEscapedUsername(t *testing.T) {
	o := scramOptions(t)
	o.identity, o.secret = scramEscapedIdentity, scramEscapedSecret

	result := diagnose(t, o)

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("authentication nodes = %d, want exactly 1", len(auth))
	}
	if got := auth[0].State(); got != domain.StatePass {
		t.Fatalf("state = %s, want PASS. The principal %q must reach the broker as "+
			"a=2Cb=3Dc; an unescaped comma changes both the attribute list and the "+
			"AuthMessage, and the broker reports that as an authentication failure.",
			got, scramEscapedIdentity)
	}
}

// TestRealSCRAMWrongCredentialIsRejectedNotSilent proves the failing direction
// is attributed to the peer, and attributed correctly.
//
// The broker refuses the client proof, which reaches svcdoctor as a
// SaslAuthenticate error code rather than as a SCRAM `e=` token — so this also
// pins that the two routes to "the peer refused this credential" agree.
func TestRealSCRAMWrongCredentialIsRejectedNotSilent(t *testing.T) {
	o := scramOptions(t)
	o.secret = "definitely-not-the-scram-password"

	result := diagnose(t, o)

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("authentication nodes = %d, want exactly 1", len(auth))
	}
	if got := auth[0].State(); got != domain.StateFail {
		t.Fatalf("state = %s, want FAIL", got)
	}
	if got := auth[0].FailureClass(); got != domain.FailureAuthCredentialsRejected {
		t.Errorf("failure class = %s, want AUTH_CREDENTIALS_REJECTED", got)
	}

	if !hasCode(result, "KAFKA_CREDENTIALS_REJECTED") {
		t.Errorf("a rejected SCRAM credential produced no finding: %v", codesOf(result))
	}
	// It must never be reported as svcdoctor failing to prove the *broker*.
	// SCRAM authenticates both parties and the two directions are different
	// claims; conflating them was the PostgreSQL adapter's own defect until
	// Phase 4.6a.5.
	if hasCode(result, "KAFKA_PEER_VERIFICATION_FAILED") {
		t.Error("a rejected credential was reported as the broker failing verification")
	}
	if got := result.Report().Summary().Status(); got == domain.SummaryStatusOK {
		t.Error("a rejected credential left the summary OK")
	}
}

// TestRealSCRAMNonASCIICredentialIsACapabilityGap proves the printable-ASCII
// policy is a statement about svcdoctor and never an accusation.
//
// Nothing is sent. ADR 0056 section 5: PostgreSQL applies SASLprep and Kafka
// does not (KAFKA-6272), so the two need opposite behaviour for non-ASCII and
// svcdoctor refuses rather than guessing which.
func TestRealSCRAMNonASCIICredentialIsACapabilityGap(t *testing.T) {
	for _, tt := range []struct {
		name             string
		identity, secret string
	}{
		{"non-ascii password", scramIdentity, "pa ssword"},
		{"non-ascii identity", "svcdoctor\u00adscram", scramSecret},
		{"empty identity", "", scramSecret},
	} {
		t.Run(tt.name, func(t *testing.T) {
			o := scramOptions(t)
			o.identity, o.secret = tt.identity, tt.secret
			if tt.identity == "" {
				// An empty identity cannot build a credential, so this case is
				// the missing-input path rather than the capability one. Both
				// are svcdoctor-side and neither blames the cluster.
				result := diagnose(t, o)
				auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
				if len(auth) != 1 || auth[0].State() == domain.StatePass {
					t.Fatalf("an empty identity authenticated: %v", auth)
				}
				return
			}

			result := diagnose(t, o)
			auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
			if len(auth) != 1 {
				t.Fatalf("authentication nodes = %d, want exactly 1", len(auth))
			}
			if got := auth[0].State(); got != domain.StateUnknown {
				t.Fatalf("state = %s, want UNKNOWN: a gap in svcdoctor is not a target failure", got)
			}
			if got := auth[0].FailureClass(); got != domain.FailureExecUnsupportedBySvcdoctor {
				t.Errorf("failure class = %s, want EXEC_UNSUPPORTED_BY_SVCDOCTOR", got)
			}
			if hasCode(result, "KAFKA_CREDENTIALS_REJECTED") {
				t.Error("svcdoctor's own limitation was reported as the broker refusing a credential")
			}
		})
	}
}

// TestRealSCRAMPresentsOneCredentialToOneBroker re-runs the ADR 0050 proof for
// the new mechanism.
//
// SCRAM is two round trips rather than PLAIN's one, so "one credential-bearing
// attempt per run" is a stronger claim here than it was: the extra exchange must
// not become an extra attempt, and the advertised brokers Metadata returns must
// still receive nothing.
func TestRealSCRAMPresentsOneCredentialToOneBroker(t *testing.T) {
	result := diagnose(t, scramOptions(t))

	if got := len(nodesOf(result, servicekafka.StepSASLAuthenticate)); got != 1 {
		t.Errorf("authentication nodes = %d, want exactly 1 per run", got)
	}
	// The handshake is deliberately *not* pinned at one. It carries no
	// credential — a SaslHandshake request is a mechanism name and nothing else
	// — so the bootstrap sweep may run it on every resolved address, and on this
	// cluster localhost resolves to both 127.0.0.1 and ::1. What must be one is
	// the step that presents a secret, which is asserted above.
	if got := len(nodesOf(result, servicekafka.StepSASLHandshake)); got == 0 {
		t.Error("no handshake was recorded, so the authentication count proves nothing")
	}

	// The advertised sweep measures transport and stops. Any authentication or
	// handshake node beyond the single bootstrap one would mean discovery had
	// acquired credential authority.
	if got := len(nodesOf(result, servicekafka.StepBrokerAdvertised)); got == 0 {
		t.Fatal("the run recorded no advertisement, so this proves nothing about " +
			"whether discovery stayed credential-free")
	}
}

// TestRealSCRAMReportRedactsWithoutLeaking runs the shareable transformation
// over a real SCRAM run.
//
// The values below are the ones this mechanism newly puts in play: the
// principal, the password, the escaped form of the principal, and anything
// derived from either. None may survive into a shareable report, and none may
// appear even in the local one.
func TestRealSCRAMReportRedactsWithoutLeaking(t *testing.T) {
	result := diagnose(t, scramOptions(t))

	shareable, err := redaction.Redact(result.Report())
	if err != nil {
		t.Fatalf("redaction.Redact: %v", err)
	}

	for _, report := range []struct {
		name string
		body string
	}{
		{"local", mustJSON(t, result.Report())},
		{"shareable", mustJSON(t, shareable)},
	} {
		// Distinctive canaries only. The passwords and the escaped principal are
		// values that appear nowhere else; a hit is evidence rather than luck.
		for _, canary := range []string{scramSecret, scramEscapedSecret, "a=2Cb=3Dc"} {
			if strings.Contains(report.body, canary) {
				t.Errorf("the %s report contains %q", report.name, canary)
			}
		}
	}

	// The bootstrap host is the distinctive identity this composition carries,
	// and it must not survive the shareable transformation.
	if body := mustJSON(t, shareable); strings.Contains(body, bootstrapHost) {
		t.Errorf("the shareable report still names %q", bootstrapHost)
	}
}

func hasCode(r app.Result, code domain.FindingCode) bool {
	for _, f := range r.Report().Findings() {
		if f.Code() == code {
			return true
		}
	}
	return false
}
