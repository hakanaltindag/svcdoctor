package wire

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// This is the layer that turns a masked secret into bytes, so the tests here are
// about the exact shape of those bytes and about what does not come back.
//
// The exchange itself is exercised end to end through the adapter's tests, over
// real sockets and a fake broker. What is here is what only an in-package test
// can reach.

const (
	testIdentity = "svcdoctor-probe-user"
	//nolint:gosec // G101: a test canary, not a credential.
	testSecret = "Zq7XmK4pR9wL2vN8tJ6bH3sY5cD1gF0aQeUiOpAsDfGh"
)

// TestPLAINPayloadIsRFC4616 pins the wire format field by field.
//
// PLAIN is a formatted string, so a wrong separator count is a defect that
// compiles, passes a type check, and is rejected by a real broker with an error
// code that looks like bad credentials.
func TestPLAINPayloadIsRFC4616(t *testing.T) {
	payload := plainAuthBytes(testIdentity, testSecret)

	want := append([]byte{0}, testIdentity...)
	want = append(want, 0)
	want = append(want, testSecret...)

	if !bytes.Equal(payload, want) {
		t.Fatalf("payload = %q, want %q", payload, want)
	}

	fields := bytes.Split(payload, []byte{0})
	if len(fields) != 3 {
		t.Fatalf("payload has %d NUL-separated fields, want authzid, authcid and passwd",
			len(fields))
	}
	if len(fields[0]) != 0 {
		t.Errorf("authzid = %q, want empty", fields[0])
	}
	if string(fields[1]) != testIdentity {
		t.Errorf("authcid = %q, want %q", fields[1], testIdentity)
	}
	if string(fields[2]) != testSecret {
		t.Errorf("passwd = %q, want the secret", fields[2])
	}
}

// TestEmptyAuthzidIsPresentNotOmitted: the field is empty, and it is still
// there. A two-field message is not a PLAIN message.
func TestEmptyAuthzidIsPresentNotOmitted(t *testing.T) {
	payload := plainAuthBytes(testIdentity, testSecret)

	if len(payload) == 0 || payload[0] != 0 {
		t.Fatalf("payload starts with %q, want a leading NUL for the empty authzid", payload)
	}
	if got, want := bytes.Count(payload, []byte{0}), 2; got != want {
		t.Errorf("payload has %d NUL separators, want %d", got, want)
	}
}

// TestPLAINPayloadHandlesAnEmptySecret checks the degenerate case produces a
// well-formed message rather than a truncated one.
//
// Whether an empty password should be sent at all is the caller's question;
// this layer's job is to encode what it was given correctly.
func TestPLAINPayloadHandlesAnEmptySecret(t *testing.T) {
	payload := plainAuthBytes(testIdentity, "")

	want := append([]byte{0}, testIdentity...)
	want = append(want, 0)
	if !bytes.Equal(payload, want) {
		t.Errorf("payload = %q, want %q", payload, want)
	}
}

// TestSecretIsNotReadableFromTheReturnedFacts is the boundary statement: what
// comes back out of this package holds two integers and nothing derived from
// the credential.
func TestSecretIsNotReadableFromTheReturnedFacts(t *testing.T) {
	response := kmsg.NewPtrSASLAuthenticateResponse()
	response.SetVersion(saslAuthenticateRequestVersion)
	response.ErrorCode = 58
	message := "user " + testIdentity + " rejected"
	response.ErrorMessage = &message
	response.SASLAuthBytes = []byte(testSecret)
	response.SessionLifetimeMillis = 3_600_000

	normalized := normalizeSASLAuthenticate(response)

	if normalized.ErrorCode != 58 {
		t.Errorf("error code = %d, want 58", normalized.ErrorCode)
	}
	if normalized.SessionLifetimeMillis != 3_600_000 {
		t.Errorf("session lifetime = %d, want 3600000", normalized.SessionLifetimeMillis)
	}

	for _, rendering := range []string{
		fmt.Sprintf("%v", normalized),
		fmt.Sprintf("%+v", normalized),
		fmt.Sprintf("%#v", normalized),
	} {
		for _, canary := range []string{testSecret, testIdentity, "rejected"} {
			if strings.Contains(rendering, canary) {
				t.Errorf("the normalized value carries %q: %s", canary, rendering)
			}
		}
	}
}

// TestNormalizedValueHasNoFieldForBrokerProse states the exclusion structurally:
// there is no field an error message could occupy, so dropping it is not a
// filtering step somebody could forget.
func TestNormalizedValueHasNoFieldForBrokerProse(t *testing.T) {
	var value any = SASLAuthenticate{}

	if _, ok := value.(interface{ Message() string }); ok {
		t.Error("the normalized value exposes the broker's error message")
	}

	rendered := fmt.Sprintf("%#v", SASLAuthenticate{ErrorCode: 58, SessionLifetimeMillis: 1})
	for _, field := range []string{"ErrorMessage", "SASLAuthBytes", "Message", "AuthBytes"} {
		if strings.Contains(rendered, field) {
			t.Errorf("the normalized value has a %s field", field)
		}
	}
}

// TestSaslAuthenticateVersionIsOne pins the version choice, which is bounded on
// both sides: v0 has no session lifetime, and v2 is flexible and would be
// refused by this package's own framing guard.
func TestSaslAuthenticateVersionIsOne(t *testing.T) {
	if got := SASLAuthenticateVersion(); got != 1 {
		t.Fatalf("SaslAuthenticate version = %d, want 1", got)
	}

	request := kmsg.NewPtrSASLAuthenticateRequest()
	request.SetVersion(saslAuthenticateRequestVersion)
	response := kmsg.NewPtrSASLAuthenticateResponse()
	response.SetVersion(saslAuthenticateRequestVersion)

	if request.IsFlexible() || response.IsFlexible() {
		t.Error("the version this package sends is flexible; the framing does not support it")
	}

	// v2 exists and is deliberately not used.
	if request.MaxVersion() < 2 {
		t.Errorf("kmsg max version = %d, want at least 2: the version choice is meant to be a choice",
			request.MaxVersion())
	}
}

// TestAuthenticateCorrelationIsDistinct: one connection now carries three
// exchanges in sequence, and each response must be checkable against the request
// it answers.
func TestAuthenticateCorrelationIsDistinct(t *testing.T) {
	ids := map[uint32]string{
		correlationAPIVersions:      "api versions",
		correlationSASLHandshake:    "sasl handshake",
		correlationSASLAuthenticate: "sasl authenticate",
	}
	if len(ids) != 3 {
		t.Errorf("two request kinds share a correlation identifier: %v", ids)
	}
}

// TestExchangePLAINRefusesNoConnection covers the caller error that would
// otherwise surface as a nil dereference — and does so before anything is built
// from the secret.
func TestExchangePLAINRefusesNoConnection(t *testing.T) {
	_, err := Authenticate(
		context.Background(), nil, MechanismPLAIN, testIdentity, security.NewSecret(testSecret))
	if err == nil {
		t.Fatal("a nil connection was accepted")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Errorf("the error carries the secret: %v", err)
	}
}
