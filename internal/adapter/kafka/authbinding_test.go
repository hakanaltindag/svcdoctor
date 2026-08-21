package kafka

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// These tests answer one question: which endpoint authorizes a credential?
//
// The answer is the logical name the operator asked about, and never the address
// it resolved to. That is what stops a DNS answer — which changes over time,
// differs per vantage point and can be attacker-influenced — from widening the
// set of hosts a password may be sent to. See ADR 0028 section 2.

// TestCredentialBoundToTheLogicalEndpointIsAccepted is the positive control.
func TestCredentialBoundToTheLogicalEndpointIsAccepted(t *testing.T) {
	target := verifiedTarget(t)

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	if !result.Authenticated() {
		t.Fatal("a credential bound to the endpoint under test was not accepted")
	}
	if got := target.broker.authRequestCount(); got != 1 {
		t.Errorf("broker received %d authentications, want 1", got)
	}
}

// TestEndpointNormalizationDoesNotNarrowAuthority covers the forms
// security.Endpoint declares equal. A credential typed with a capital letter or
// a trailing dot is the same credential for the same host, and refusing it would
// be svcdoctor inventing a distinction DNS does not make.
func TestEndpointNormalizationDoesNotNarrowAuthority(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{name: "exact", host: "primary.internal"},
		{name: "upper case", host: "PRIMARY.INTERNAL"},
		{name: "mixed case", host: "Primary.Internal"},
		{name: "trailing dot", host: "primary.internal."},
		{name: "mixed case and trailing dot", host: "PRIMARY.Internal."},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := verifiedTarget(t)

			result := authenticate(t, target, credentialFor(t, test.host, 9092), AuthParams{})

			if !result.Authenticated() {
				t.Errorf("a credential bound to %q was refused for %q, but they are one endpoint",
					test.host, authEndpoint)
			}
		})
	}
}

// TestOneCredentialAuthorizesEveryResolvedAddress is the acceptance criterion
// ADR 0028 section 2 names: one lookup producing five addresses produces five
// sessions that are all still the same authorized endpoint.
//
// If authority were taken from the resolved address instead, four of these five
// would fail — and the one that passed would be whichever address happened to be
// bound, which is exactly the accident this design removes.
func TestOneCredentialAuthorizesEveryResolvedAddress(t *testing.T) {
	addresses := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	target := verifiedTargetAt(t, addresses)

	if len(target.sessions) != len(addresses) {
		t.Fatalf("handshake sessions = %d, want %d", len(target.sessions), len(addresses))
	}

	credential := credentialFor(t, authHost, 9092)
	for _, session := range target.sessions {
		result, err := Authenticate(t.Context(), target.builder, session, credential, AuthParams{})
		if err != nil {
			t.Fatalf("%s: Authenticate: %v", session.Address(), err)
		}
		t.Cleanup(func() { _ = result.Close() })

		if !result.Authenticated() {
			t.Errorf("%s: one credential did not authorize this resolved address",
				session.Address())
		}
	}

	if got := target.broker.authRequestCount(); got != len(addresses) {
		t.Errorf("broker received %d authentications, want %d", got, len(addresses))
	}
}

// TestMismatchedCredentialIsRefused is the negative half of the matrix. Every
// case here must return an error, record no evidence, and send nothing.
func TestMismatchedCredentialIsRefused(t *testing.T) {
	tests := []struct {
		name string
		host string
		port uint16
	}{
		{
			name: "different logical hostname",
			host: "secondary.internal",
			port: 9092,
		},
		{
			name: "same hostname, different port",
			host: authHost,
			port: 9093,
		},
		{
			// The case that matters most: the name under test genuinely resolves
			// to this address, and that still does not authorize it.
			name: "bound to the resolved address instead of the name",
			host: authAddress,
			port: 9092,
		},
		{
			name: "a name that merely looks similar",
			host: "primary.internal.example.com",
			port: 9092,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := verifiedTarget(t)
			before := target.broker.appBytesRead()

			_, err := Authenticate(t.Context(), target.builder, target.session(t),
				credentialFor(t, test.host, test.port), AuthParams{})

			if !errors.Is(err, security.ErrEndpointMismatch) {
				t.Fatalf("error = %v, want one wrapping ErrEndpointMismatch", err)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("error = %v, want one wrapping ErrInvalidInput: "+
					"a mismatch is a caller defect, not a target fact", err)
			}

			// A mismatch is a programming error and must not be normalized into
			// evidence: a node saying "the wrong credential was offered" would
			// be svcdoctor reporting on its own caller.
			graph := freeze(t, target.builder)
			if _, ok := graph.Node(domain.EvidenceID(authNodeID)); ok {
				t.Error("a credential mismatch produced an evidence node")
			}

			// The strongest available statement: not "authentication failed",
			// but that the peer's protocol layer received nothing at all after
			// the handshake.
			target.broker.awaitIdle()
			if got := target.broker.authRequestCount(); got != 0 {
				t.Errorf("broker received %d authentications, want 0", got)
			}
			if after := target.broker.appBytesRead(); after != before {
				t.Errorf("%d protocol bytes reached the peer after the mismatch, want 0",
					after-before)
			}
		})
	}
}

// TestMismatchErrorCarriesNoSecret: the error names the two endpoints, because
// that is what a caller needs to fix the wiring, and nothing else.
func TestMismatchErrorCarriesNoSecret(t *testing.T) {
	target := verifiedTarget(t)

	_, err := Authenticate(t.Context(), target.builder, target.session(t),
		credentialFor(t, "secondary.internal", 9092), AuthParams{})
	if err == nil {
		t.Fatal("a mismatched credential was accepted")
	}

	for _, rendering := range []string{
		err.Error(),
		fmt.Sprintf("%v", err),
		fmt.Sprintf("%+v", err),
		fmt.Sprintf("%#v", err),
		fmt.Sprintf("%s", err),
	} {
		if strings.Contains(rendering, authSecret) {
			t.Errorf("a mismatch error leaks the secret: %s", rendering)
		}
	}
}

// TestCredentialAuthorityIgnoresTheResolvedAddressEntirely states the rule from
// the other side: two paths that differ only in resolved address are authorized
// identically, so nothing about resolution can change the decision.
func TestCredentialAuthorityIgnoresTheResolvedAddressEntirely(t *testing.T) {
	target := verifiedTargetAt(t, []string{"10.0.0.1", "10.0.0.2"})

	if len(target.sessions) != 2 {
		t.Fatalf("handshake sessions = %d, want 2", len(target.sessions))
	}

	// One credential bound to the name authorizes both.
	byName := credentialFor(t, authHost, 9092)
	// A credential bound to either address authorizes neither.
	byAddress := credentialFor(t, "10.0.0.1", 9092)

	for _, session := range target.sessions {
		result, err := Authenticate(t.Context(), target.builder, session, byName, AuthParams{})
		if err != nil || !result.Authenticated() {
			t.Fatalf("%s: the name-bound credential was refused: %v", session.Address(), err)
		}
		t.Cleanup(func() { _ = result.Close() })
	}

	// Rebuild, because the sessions above are consumed.
	fresh := verifiedTargetAt(t, []string{"10.0.0.1", "10.0.0.2"})
	for _, session := range fresh.sessions {
		_, err := Authenticate(t.Context(), fresh.builder, session, byAddress, AuthParams{})
		if !errors.Is(err, security.ErrEndpointMismatch) {
			t.Errorf("%s: an address-bound credential was accepted for %s",
				session.Address(), authEndpoint)
		}
	}
	fresh.broker.awaitIdle()
	if got := fresh.broker.authRequestCount(); got != 0 {
		t.Errorf("broker received %d authentications from address-bound credentials, want 0", got)
	}
}
