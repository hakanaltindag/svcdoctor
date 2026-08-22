//go:build integration

package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Authentication against the real broker's PLAIN implementation.

// TestPlainAuthenticationSucceeds pins the healthy credential path and the
// mechanism discovery that precedes it.
func TestPlainAuthenticationSucceeds(t *testing.T) {
	r := pass(t, defaults(t))

	handshakes := r.nodes("kafka.sasl_handshake")
	if len(handshakes) == 0 {
		t.Fatal("no handshake evidence")
	}
	h := handshakes[0]
	if h.State() != domain.StatePass {
		t.Fatalf("handshake = %s (%s)", h.State(), h.FailureClass())
	}

	requested, ok := h.Attribute("kafka.sasl.requested_mechanism")
	if !ok {
		t.Fatal("handshake records no requested mechanism")
	}
	got, _ := requested.Str()
	if got != "PLAIN" {
		t.Errorf("requested mechanism = %q, want PLAIN", got)
	}

	offered, ok := h.Attribute("kafka.sasl.offered_mechanisms")
	if !ok {
		t.Fatal("handshake records no offered mechanisms")
	}
	list, _ := offered.StringList()
	if len(list) != 1 || list[0] != "PLAIN" {
		t.Errorf("offered mechanisms = %v, want exactly [PLAIN] as the broker is configured", list)
	}
	t.Logf("broker offers %v", list)

	auth := r.nodes("kafka.sasl_authenticate")
	if len(auth) != 1 {
		t.Fatalf("authenticate nodes = %d, want exactly 1: one caller-chosen session", len(auth))
	}
	if auth[0].State() != domain.StatePass {
		t.Fatalf("authenticate = %s (%s)", auth[0].State(), auth[0].FailureClass())
	}
}

// TestUnsupportedMechanismIsDiscovered asks for a mechanism the broker does not
// offer. The broker answers with its list, which is the whole point of the
// handshake step.
func TestUnsupportedMechanismIsDiscovered(t *testing.T) {
	o := defaults(t)
	o.mechanism = "SCRAM-SHA-512"
	o.stopAfterAuth = true
	r := pass(t, o)

	handshakes := r.nodes("kafka.sasl_handshake")
	if len(handshakes) == 0 {
		t.Fatal("no handshake evidence")
	}
	h := handshakes[0]
	if h.State() != domain.StateFail {
		t.Errorf("handshake = %s, want FAIL for a mechanism the broker does not offer", h.State())
	}
	if h.FailureClass() != domain.FailureAuthMechanismNotOffered {
		t.Errorf("class = %s, want AUTH_MECHANISM_NOT_OFFERED", h.FailureClass())
	}
	offered, ok := h.Attribute("kafka.sasl.offered_mechanisms")
	if !ok {
		t.Fatal("the refusal records no offered mechanisms; the useful half is missing")
	}
	list, _ := offered.StringList()
	t.Logf("broker refused SCRAM-SHA-512 and offered %v", list)
}

// TestWrongCredentialIsRejectedAndNeverLeaks is the security case.
func TestWrongCredentialIsRejectedAndNeverLeaks(t *testing.T) {
	const wrongSecret = "wrong-password-canary-9f3a2b"

	o := defaults(t)
	o.secret = wrongSecret
	o.stopAfterAuth = true
	r := pass(t, o)
	r.describe(t)

	auth := r.nodes("kafka.sasl_authenticate")
	if len(auth) != 1 {
		t.Fatalf("authenticate nodes = %d, want 1", len(auth))
	}
	if auth[0].State() != domain.StateFail {
		t.Fatalf("authenticate = %s, want FAIL for a wrong password", auth[0].State())
	}
	if auth[0].FailureClass() != domain.FailureAuthCredentialsRejected {
		t.Errorf("class = %s, want AUTH_CREDENTIALS_REJECTED", auth[0].FailureClass())
	}

	// The secret, the identity and the broker's own error text must be absent
	// from both report forms.
	local := mustJSON(t, r.report)
	shareable := mustJSON(t, r.shareable)
	for _, forbidden := range []string{wrongSecret, saslSecret, "wrong-password"} {
		if strings.Contains(local, forbidden) {
			t.Errorf("LOCAL_FULL report contains %q", forbidden)
		}
		if strings.Contains(shareable, forbidden) {
			t.Errorf("SHAREABLE report contains %q", forbidden)
		}
	}
	// The broker's SASL error message never leaves the wire package.
	for _, phrase := range []string{"Authentication failed", "credentials", "SaslAuthenticate"} {
		if strings.Contains(local, phrase) {
			t.Errorf("LOCAL_FULL report echoes broker error text %q", phrase)
		}
	}
	t.Logf("rejected cleanly: %s / %s", auth[0].State(), auth[0].FailureClass())
}
