package security

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func mustEndpoint(t *testing.T, host string, port uint16) Endpoint {
	t.Helper()
	ep, err := NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("NewEndpoint(%q, %d): %v", host, port, err)
	}
	return ep
}

func TestNewCredentialRequiresEndpointBinding(t *testing.T) {
	_, err := NewCredential(Endpoint{}, "svc_app", NewSecret("pw"))
	if !errors.Is(err, ErrUnboundCredential) {
		t.Fatalf("err = %v, want ErrUnboundCredential", err)
	}
}

func TestNewCredentialAccessors(t *testing.T) {
	ep := mustEndpoint(t, "KAFKA.Internal", 9092)

	cred, err := NewCredential(ep, "svc_app", NewSecret("pw"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}

	if cred.IsZero() {
		t.Error("a constructed Credential must not be zero")
	}
	if !cred.Endpoint().Equal(ep) {
		t.Errorf("Endpoint() = %s, want %s", cred.Endpoint(), ep)
	}
	if cred.Identity() != "svc_app" {
		t.Errorf("Identity() = %q, want %q", cred.Identity(), "svc_app")
	}
}

// TestEmptyIdentityIsAllowed covers mechanisms with no username, such as a
// bare token.
func TestEmptyIdentityIsAllowed(t *testing.T) {
	ep := mustEndpoint(t, "kafka.internal", 9092)

	cred, err := NewCredential(ep, "", NewSecret("token"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	if cred.Identity() != "" {
		t.Errorf("Identity() = %q, want empty", cred.Identity())
	}
	if !strings.Contains(cred.String(), "<none>") {
		t.Errorf("String() should mark an absent identity, got %q", cred.String())
	}
}

func TestSecretForMatchingEndpoint(t *testing.T) {
	ep := mustEndpoint(t, "kafka.internal", 9092)

	cred, err := NewCredential(ep, "svc_app", NewSecret("pw"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}

	secret, err := cred.SecretFor(ep)
	if err != nil {
		t.Fatalf("SecretFor: %v", err)
	}
	if Reveal(secret) != "pw" {
		t.Error("SecretFor returned the wrong secret")
	}

	// An equivalently spelled endpoint is the same endpoint.
	equivalent := mustEndpoint(t, "KAFKA.Internal.", 9092)
	if _, err := cred.SecretFor(equivalent); err != nil {
		t.Errorf("SecretFor with an equivalent spelling failed: %v", err)
	}
}

// TestSecretForRejectsOtherEndpoints is the central credential-forwarding
// guard: a credential bound to the bootstrap endpoint cannot be used against a
// broker discovered from it.
func TestSecretForRejectsOtherEndpoints(t *testing.T) {
	bootstrap := mustEndpoint(t, "bootstrap.kafka.internal", 9092)

	cred, err := NewCredential(bootstrap, "svc_app", NewSecret("pw"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}

	tests := []struct {
		name string
		host string
		port uint16
	}{
		{"discovered broker", "broker-2.internal", 9092},
		{"same host different port", "bootstrap.kafka.internal", 9093},
		{"resolved address of the same name", "127.0.0.1", 9092},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := mustEndpoint(t, tt.host, tt.port)

			secret, err := cred.SecretFor(other)
			if !errors.Is(err, ErrEndpointMismatch) {
				t.Fatalf("err = %v, want ErrEndpointMismatch", err)
			}
			if !secret.IsEmpty() {
				t.Error("a rejected SecretFor must return the zero Secret")
			}
		})
	}
}

func TestSecretForOnZeroCredential(t *testing.T) {
	ep := mustEndpoint(t, "kafka.internal", 9092)

	var cred Credential
	if _, err := cred.SecretFor(ep); !errors.Is(err, ErrUnboundCredential) {
		t.Fatalf("err = %v, want ErrUnboundCredential", err)
	}
}

// TestMismatchErrorNamesBothEndpoints keeps the error actionable. Endpoints are
// already part of the report's target model, so naming them is safe; the secret
// is the only value that must not appear, which leak_test.go asserts.
func TestMismatchErrorNamesBothEndpoints(t *testing.T) {
	bound := mustEndpoint(t, "bootstrap.kafka.internal", 9092)
	other := mustEndpoint(t, "broker-2.internal", 9092)

	cred, err := NewCredential(bound, "svc_app", NewSecret("pw"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}

	_, err = cred.SecretFor(other)
	if err == nil {
		t.Fatal("expected an error")
	}

	msg := err.Error()
	for _, want := range []string{bound.String(), other.String()} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q should name %q", msg, want)
		}
	}
}

// TestCredentialMarshalsToEmptyObject pins the decision not to give Credential
// a json.Marshaler.
//
// Every field is unexported, so encoding/json emits "{}". Adding a marshaler
// would only widen the output surface of a type that has no place in a report.
// If someone later adds an exported field or a MarshalJSON, this test fails and
// the redaction consequences have to be considered deliberately.
func TestCredentialMarshalsToEmptyObject(t *testing.T) {
	ep := mustEndpoint(t, "kafka.internal", 9092)

	cred, err := NewCredential(ep, "svc_app", NewSecret("pw"))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}

	//nolint:staticcheck // SA9005: the empty result is the property under test.
	got, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != "{}" {
		t.Errorf("json.Marshal(Credential) = %s, want {}", got)
	}
}

func TestZeroCredentialFormatting(t *testing.T) {
	var cred Credential

	if !cred.IsZero() {
		t.Error("zero Credential should report IsZero")
	}
	if cred.String() != "<invalid credential>" {
		t.Errorf("String() = %q, want %q", cred.String(), "<invalid credential>")
	}
}
