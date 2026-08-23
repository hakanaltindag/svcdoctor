//go:build integration

package redpanda

import (
	"testing"

	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// TestSCRAMSHA256CompletesTheWholeJourney is the test ADR 0061 exists for.
//
// Against svcdoctor v0.2.0 this failed. Redpanda emits a 130-byte SCRAM salt,
// encoding to 176 base64 characters, and the shared core bounded the encoded
// form at 172 — so the message was refused before it was decoded, and reported
// as `PROTOCOL_MALFORMED_RESPONSE`. The message was legal RFC 5802 throughout.
//
// This asserts the whole journey rather than only the authentication step,
// because the bound sat in the middle of it: passing authentication while
// failing Metadata would mean the fix moved the problem rather than removing it.
func TestSCRAMSHA256CompletesTheWholeJourney(t *testing.T) {
	result := diagnose(t, defaults(t))

	for _, step := range []domain.Step{
		servicekafka.StepAPIVersions,
		servicekafka.StepSASLHandshake,
		servicekafka.StepSASLAuthenticate,
		servicekafka.StepMetadata,
	} {
		if !passingNode(result, step) {
			t.Errorf("%s did not pass against real Redpanda.\n\nfindings: %v",
				step, codesOf(result))
		}
	}

	if got := result.Report().Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("summary = %v, want OK; findings: %v", got, codesOf(result))
	}
	if result.Incomplete() {
		t.Error("the run did not finish, so nothing above is a statement about Redpanda")
	}
}

// TestSCRAMAuthenticationReceivesTheOversizedSalt proves the fix is the one that
// was intended, not an accident of some other change.
//
// The point is not merely that authentication passed — it is that it passed
// while carrying a salt above the bound that used to refuse it. If Redpanda ever
// shortened its salt this test would still pass and would have stopped proving
// anything, so the salt size is read off the evidence and checked.
func TestSCRAMAuthenticationReceivesTheOversizedSalt(t *testing.T) {
	result := diagnose(t, defaults(t))

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("%d authentication nodes, want exactly 1", len(auth))
	}
	if auth[0].State() != domain.StatePass {
		t.Fatalf("authentication %v (%v); findings: %v",
			auth[0].State(), auth[0].FailureClass(), codesOf(result))
	}

	// The salt itself is never evidence — it is peer-controlled material the
	// core drops after derivation, which is why this reads the mechanism
	// instead. It pins that the passing node above came from a SCRAM exchange
	// rather than from some other mechanism that merely reported success.
	mechanism, ok := auth[0].Attributes()[servicekafka.AttrSASLMechanism]
	if !ok {
		t.Fatalf("the authentication node records no SASL mechanism; attributes: %v",
			auth[0].Attributes())
	}
	if got := mechanism.String(); got != mechanismSCRAM {
		t.Errorf("authentication used %q, want %q", got, mechanismSCRAM)
	}
}

// TestWrongSCRAMCredentialIsAPeerRefusal keeps the negative direction honest.
//
// A wrong password must reach AUTH_CREDENTIALS_REJECTED — the peer refusing
// svcdoctor — and must not be confused with the capability class the bound
// refusal now uses. The two were adjacent before ADR 0061 and must stay apart.
func TestWrongSCRAMCredentialIsAPeerRefusal(t *testing.T) {
	o := defaults(t)
	o.secret = "definitely-not-the-redpanda-password"
	result := diagnose(t, o)

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("%d authentication nodes, want exactly 1", len(auth))
	}
	if got := auth[0].FailureClass(); got != domain.FailureAuthCredentialsRejected {
		t.Errorf("failure class = %v, want AUTH_CREDENTIALS_REJECTED", got)
	}
	if !hasCode(result, diagnosiskafka.CodeCredentialsRejected) {
		t.Errorf("findings = %v, want KAFKA_CREDENTIALS_REJECTED", codesOf(result))
	}
	if passingNode(result, servicekafka.StepMetadata) {
		t.Error("metadata was obtained after a rejected credential")
	}
}

// TestNoCredentialConfiguredSendsNothing pins that a run with no credential is
// a valid run, not a failure of the broker.
func TestNoCredentialConfiguredSendsNothing(t *testing.T) {
	o := defaults(t)
	o.identity, o.secret = "", ""
	result := diagnose(t, o)

	if !hasCode(result, diagnosiskafka.CodeCredentialNotConfigured) {
		t.Errorf("findings = %v, want KAFKA_CREDENTIAL_NOT_CONFIGURED", codesOf(result))
	}
	if got := result.Report().Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("summary = %v, want OK: a missing credential is svcdoctor's input, "+
			"not a defect in the broker", got)
	}
}
