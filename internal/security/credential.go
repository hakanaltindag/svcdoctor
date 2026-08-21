package security

import (
	"errors"
	"fmt"
	"io"
)

// ErrEndpointMismatch is returned when a Credential is asked for its secret on
// an endpoint it was not bound to.
var ErrEndpointMismatch = errors.New("credential is bound to a different endpoint")

// ErrUnboundCredential is returned when a Credential would have no endpoint binding.
var ErrUnboundCredential = errors.New("credential must be bound to an endpoint")

// Credential is a secret bound to the endpoint it was resolved for.
//
// The binding is the point of the type. Every field is unexported, the only way
// to build one is NewCredential, which requires a valid Endpoint, and the only
// way to read the secret is SecretFor, which requires naming the endpoint the
// secret is about to be used against. Forwarding a credential to a
// topology-discovered host is therefore not something that can happen by
// passing a struct around; it takes a deliberate, visible endpoint mismatch.
//
// This type intentionally does not model authentication mechanisms. Mechanism
// vocabularies are service specific, and no adapter exists yet to say what the
// right shape is. See docs/SECURITY.md item 8.
//
// The zero Credential is invalid. Use NewCredential.
type Credential struct {
	endpoint Endpoint
	identity string
	secret   Secret
}

// NewCredential binds secret to endpoint.
//
// identity is the username or principal where the mechanism uses one, and may
// be empty for mechanisms that do not, such as a bare token.
func NewCredential(endpoint Endpoint, identity string, secret Secret) (Credential, error) {
	if endpoint.IsZero() {
		return Credential{}, ErrUnboundCredential
	}
	return Credential{endpoint: endpoint, identity: identity, secret: secret}, nil
}

// Endpoint returns the endpoint this credential is bound to.
func (c Credential) Endpoint() Endpoint { return c.endpoint }

// Identity returns the username or principal, which may be empty.
func (c Credential) Identity() string { return c.identity }

// IsZero reports whether c is the invalid zero Credential.
func (c Credential) IsZero() bool { return c.endpoint.IsZero() }

// SecretFor returns the secret if and only if c is bound to endpoint.
//
// There is deliberately no plain Secret accessor. Requiring the caller to name
// the endpoint means a credential cannot be silently reused against a different
// host, and a mismatch surfaces as an error rather than as a successful
// authentication attempt somewhere it was never authorized.
//
// A mismatch here is a programming error, not a diagnostic result. It must not
// be normalized into evidence.
func (c Credential) SecretFor(endpoint Endpoint) (Secret, error) {
	if c.IsZero() {
		return Secret{}, ErrUnboundCredential
	}
	if !c.endpoint.Equal(endpoint) {
		return Secret{}, fmt.Errorf("%w: bound to %s, requested %s",
			ErrEndpointMismatch, c.endpoint, endpoint)
	}
	return c.secret, nil
}

// String implements fmt.Stringer and never includes the secret.
//
// The endpoint and identity are included because both already appear in the
// report's target model; the secret is the only value that must not.
func (c Credential) String() string {
	if c.IsZero() {
		return "<invalid credential>"
	}
	identity := c.identity
	if identity == "" {
		identity = "<none>"
	}
	return fmt.Sprintf("Credential{endpoint: %s, identity: %s, secret: %s}",
		c.endpoint, identity, mask)
}

// GoString implements fmt.GoStringer so that %#v cannot reveal the secret.
func (c Credential) GoString() string {
	return fmt.Sprintf("security.Credential{endpoint: %q, identity: %q, secret: %s}",
		c.endpoint.String(), c.identity, c.secret.GoString())
}

// Format implements fmt.Formatter.
//
// Credential's own fields are safe, but the embedded Secret is not, and a
// struct printed with %+v is walked field by field. Closing every verb here
// keeps that safe regardless of how the value is printed.
func (c Credential) Format(f fmt.State, verb rune) {
	switch {
	case verb == 'v' && f.Flag('#'):
		_, _ = io.WriteString(f, c.GoString())
	default:
		_, _ = io.WriteString(f, c.String())
	}
}

// Credential deliberately implements neither json.Marshaler nor
// encoding.TextMarshaler. Every field is unexported, so encoding/json already
// emits "{}" for it. Adding a marshaler would only widen the output surface of
// a type that has no place in a report to begin with.
