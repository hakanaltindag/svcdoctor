package kafka

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The leak matrix for the first phase that transmits a credential.
//
// Two canaries travel here. The secret is what svcdoctor sends, and it is
// allowed to appear in exactly one place: the payload the controlled peer
// received. The broker's error message is what the peer sends back, and it is
// allowed nowhere at all — it is deployment-authored prose that routinely names
// principals and internal hosts, and it is dropped at the wire boundary.

// brokerCanary is what the fake broker writes into its error message. It is
// shaped like the kind of thing a real broker says, because that is the point.
const brokerCanary = "Authentication failed for user svc-prod@REALM.INTERNAL on listener SASL_SSL://broker-7.prod.internal:9093"

// TestTheBrokerActuallyReceivesTheSecret is the precondition for every absence
// assertion below.
//
// A leak test whose canary never travelled proves nothing: it would pass just as
// happily against code that authenticates with an empty password. This is what
// makes the rest of this file mean something.
func TestTheBrokerActuallyReceivesTheSecret(t *testing.T) {
	target := verifiedTarget(t)
	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	payloads := target.broker.authPayloadsSeen()
	if len(payloads) != 1 {
		t.Fatalf("broker received %d authentications, want 1", len(payloads))
	}
	if !bytes.Contains(payloads[0], []byte(authSecret)) {
		t.Fatalf("the peer never received the secret, so the absence tests below prove nothing")
	}
	if !bytes.Contains(payloads[0], []byte(authIdentity)) {
		t.Fatal("the peer never received the identity")
	}
}

// TestSecretReachesNoAdapterSurface walks everything this package hands back or
// records and asserts the secret is in none of it.
func TestSecretReachesNoAdapterSurface(t *testing.T) {
	target := verifiedTarget(t, withSessionLifetime(60_000))
	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	session, ok := result.Session()
	if !ok {
		t.Fatal("the fixture credential was not accepted")
	}
	handshake := target.session(t)
	credential := credentialFor(t, authHost, 9092)
	graph := freeze(t, target.builder)

	renderings := map[string]string{
		"AuthResult %v":            fmt.Sprintf("%v", result),
		"AuthResult %+v":           fmt.Sprintf("%+v", result),
		"AuthResult %#v":           fmt.Sprintf("%#v", result),
		"AuthenticatedSession %v":  fmt.Sprintf("%v", session),
		"AuthenticatedSession %+v": fmt.Sprintf("%+v", session),
		"AuthenticatedSession %#v": fmt.Sprintf("%#v", session),
		"HandshakeSession %+v":     fmt.Sprintf("%+v", handshake),
		"HandshakeSession %#v":     fmt.Sprintf("%#v", handshake),
		"Credential %v":            fmt.Sprintf("%v", credential),
		"Credential %+v":           fmt.Sprintf("%+v", credential),
		"Credential %#v":           fmt.Sprintf("%#v", credential),
		"Credential String":        credential.String(),
		"Secret %v":                fmt.Sprintf("%v", security.NewSecret(authSecret)),
		"Secret %#v":               fmt.Sprintf("%#v", security.NewSecret(authSecret)),
		"Secret %q":                fmt.Sprintf("%q", security.NewSecret(authSecret)),
		"Secret %x":                fmt.Sprintf("%x", security.NewSecret(authSecret)),
		"Graph %v":                 fmt.Sprintf("%v", graph),
	}

	for _, evidence := range graph.Nodes() {
		encoded, err := evidence.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		renderings["evidence JSON "+evidence.ID().String()] = string(encoded)
		renderings["evidence String "+evidence.ID().String()] = evidence.String()
		renderings["evidence attributes "+evidence.ID().String()] =
			fmt.Sprintf("%+v", evidence.Attributes())
	}

	for where, rendering := range renderings {
		if strings.Contains(rendering, authSecret) {
			t.Errorf("%s leaks the secret:\n%s", where, rendering)
		}
	}
}

// TestBrokerErrorMessageNeverEscapesTheWireBoundary is the other direction: the
// peer says something, and svcdoctor must not repeat it.
//
// Kafka's SaslAuthenticate response carries an ErrorMessage written by the
// deployment. Evidence has no sanitization step for prose and a report is meant
// to be shareable, so the message is dropped where it arrives rather than
// carried upward and filtered later. The error code is the normalized fact.
func TestBrokerErrorMessageNeverEscapesTheWireBoundary(t *testing.T) {
	target := verifiedTarget(t, withAuthError(58), withAuthErrorMessage(brokerCanary))

	// The fixture must really put the canary on the wire, or this proves
	// nothing. Encoding the response the broker would send is the check.
	encoded := target.broker.saslAuthenticateResponse(1)
	if !bytes.Contains(encoded, []byte(brokerCanary)) {
		t.Fatal("the fixture broker does not actually send the canary in its error message")
	}

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})
	if result.Authenticated() {
		t.Fatal("a rejected credential was reported as accepted")
	}

	graph := freeze(t, target.builder)
	evidence := node(t, graph, authNodeID)

	// The code survives, because that is the fact the protocol defines.
	if got, _ := attribute(t, evidence, AttrErrorCode).Int(); got != 58 {
		t.Errorf("error code = %d, want 58 recorded as the normalized fact", got)
	}

	renderings := map[string]string{
		"AuthResult %+v":  fmt.Sprintf("%+v", result),
		"AuthResult %#v":  fmt.Sprintf("%#v", result),
		"evidence String": evidence.String(),
		"attributes":      fmt.Sprintf("%+v", evidence.Attributes()),
	}
	for _, n := range graph.Nodes() {
		out, err := n.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		renderings["evidence JSON "+n.ID().String()] = string(out)
	}

	// A fragment check as well as the whole string: a partial copy would be
	// just as much of a leak as the complete message.
	for _, canary := range []string{
		brokerCanary,
		"svc-prod@REALM.INTERNAL",
		"broker-7.prod.internal",
		"SASL_SSL",
	} {
		for where, rendering := range renderings {
			if strings.Contains(rendering, canary) {
				t.Errorf("%s leaks the broker error message fragment %q:\n%s",
					where, canary, rendering)
			}
		}
	}
}

// TestAuthenticatedSessionExposesNoCredentialAccessor: the credential did its
// work at the wire boundary and has no reason to outlive it, so there is no
// method through which it could be read back out.
func TestAuthenticatedSessionExposesNoCredentialAccessor(t *testing.T) {
	target := verifiedTarget(t)
	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	session, ok := result.Session()
	if !ok {
		t.Fatal("the fixture credential was not accepted")
	}

	var value any = session
	if _, ok := value.(interface{ Secret() security.Secret }); ok {
		t.Error("an authenticated session hands back a secret")
	}
	if _, ok := value.(interface{ Credential() security.Credential }); ok {
		t.Error("an authenticated session hands back a credential")
	}
	if _, ok := value.(interface{ Password() string }); ok {
		t.Error("an authenticated session hands back a password")
	}
	if _, ok := value.(interface{ Identity() string }); ok {
		t.Error("an authenticated session hands back an identity")
	}
}

// TestNoEvidenceNodeCarriesTheIdentity pins the conservative attribute decision.
//
// A username is real deployment identity and redaction's declared kinds cover
// hosts and addresses only, so a plain string holding one would survive into a
// shareable report unpseudonymized.
func TestNoEvidenceNodeCarriesTheIdentity(t *testing.T) {
	target := verifiedTarget(t)
	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	for _, evidence := range freeze(t, target.builder).Nodes() {
		encoded, err := evidence.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		if bytes.Contains(encoded, []byte(authIdentity)) {
			t.Errorf("%s records the authenticating identity:\n%s", evidence.ID(), encoded)
		}
	}
}

// TestRefusedAttemptLeaksNothingEither: the refusal path never handled a secret,
// and this asserts it rather than assuming it.
func TestRefusedAttemptLeaksNothingEither(t *testing.T) {
	for _, test := range refusalCases() {
		t.Run(test.name, func(t *testing.T) {
			target := test.target(t)
			result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

			graph := freeze(t, target.builder)
			renderings := []string{
				fmt.Sprintf("%+v", result),
				fmt.Sprintf("%#v", result),
				node(t, graph, authNodeID).String(),
			}
			for _, n := range graph.Nodes() {
				encoded, err := n.MarshalJSON()
				if err != nil {
					t.Fatalf("MarshalJSON: %v", err)
				}
				renderings = append(renderings, string(encoded))
			}

			for _, rendering := range renderings {
				for _, canary := range []string{authSecret, authIdentity} {
					if strings.Contains(rendering, canary) {
						t.Errorf("a refusal leaked %q:\n%s", canary, rendering)
					}
				}
			}
		})
	}
}

// TestGraphHoldsNoSecretShapedAttributeAnywhere is a whole-graph sweep rather
// than a per-node one, so a node added later by another step is covered too.
func TestGraphHoldsNoSecretShapedAttributeAnywhere(t *testing.T) {
	target := verifiedTarget(t)
	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	forbidden := []domain.AttributeKey{
		"kafka.sasl.password", "kafka.sasl.secret", "kafka.sasl.identity",
		"kafka.sasl.authzid", "kafka.sasl.auth_bytes", "kafka.sasl.error_message",
		"kafka.sasl.username", "kafka.sasl.password_length",
	}
	for _, evidence := range freeze(t, target.builder).Nodes() {
		for _, key := range forbidden {
			if _, ok := evidence.Attribute(key); ok {
				t.Errorf("%s records %s", evidence.ID(), key)
			}
		}
	}
}
