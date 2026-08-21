package domain

import (
	"fmt"
	"strconv"
)

// FailureClass is a service-neutral normalization of why a step did not pass.
//
// It is factual, not interpretive. A FailureClass carries no severity, no
// confidence, and no recommendation, and it does not map to a finding. Turning
// classified facts into findings is diagnosis work and belongs elsewhere.
//
// The vocabulary is deliberately broad. Service-specific detail such as a Kafka
// error code or a PostgreSQL SQLSTATE is carried as a normalized attribute
// alongside the class, never as a member of this enumeration.
//
// Four distinctions in this vocabulary are load-bearing and must not be
// collapsed, per docs/ARCHITECTURE.md section 12:
//
//   - DNS, TCP, and TLS failures stay distinct, because first-broken-layer
//     accuracy depends on knowing which one actually broke.
//   - Authentication and authorization stay distinct, because "the peer refused
//     the material you presented" and "you authenticated and lack permission"
//     lead to different actions.
//   - A local execution timeout is not a remote failure. An exhausted local
//     budget means nothing was learned about the target.
//   - A capability svcdoctor does not support, and a privilege svcdoctor does
//     not hold, are gaps in svcdoctor rather than defects in the target.
//
// The zero FailureClass is FailureNone, which is valid: the report schema states
// that failureClass is meaningless on a PASS node.
type FailureClass uint8

const (
	// FailureNone means no failure was classified. It is the zero value and is
	// the correct value on a passing step.
	FailureNone FailureClass = iota

	// DNS.

	// FailureDNSNXDomain means the resolver positively evidenced that the name
	// does not exist. It is the stronger claim of the two and requires a
	// resolver that reports NXDOMAIN distinctly; a resolver that folds
	// non-existence into a generic not-found answer evidences only
	// FailureDNSNoAddress.
	FailureDNSNXDomain
	// FailureDNSNoAddress means the lookup yielded no usable address.
	//
	// It says nothing about whether the name exists. That is deliberate: it
	// covers a name that exists with no address record, a name that does not
	// exist, and the common case where the resolver does not distinguish the
	// two. The weaker claim is the one that is true in all three, and a
	// producer must not upgrade it to FailureDNSNXDomain without evidence of
	// non-existence.
	FailureDNSNoAddress
	// FailureDNSTimeout means the resolver did not answer in time.
	FailureDNSTimeout
	// FailureDNSResolverFailure means the resolver reported a failure.
	FailureDNSResolverFailure

	// TCP.

	// FailureTCPConnectionRefused means the peer actively refused the connection.
	FailureTCPConnectionRefused
	// FailureTCPConnectionTimeout means the connection attempt timed out remotely.
	FailureTCPConnectionTimeout
	// FailureTCPConnectionReset means the connection was reset by the peer.
	FailureTCPConnectionReset
	// FailureTCPNetworkUnreachable means the network could not be reached.
	FailureTCPNetworkUnreachable
	// FailureTCPHostUnreachable means the host could not be reached.
	FailureTCPHostUnreachable
	// FailureTCPConnectionFailed means the connection attempt failed in a way
	// svcdoctor could not classify further.
	//
	// It is the conservative floor of the TCP vocabulary, not a catch-all to
	// reach for: a producer uses it only after the specific classes above have
	// been ruled out. The failure is still positively evidenced — the attempt was
	// made and did not connect — so it remains a FAIL. What is unknown is why,
	// and a precise-sounding wrong class would be worse than an honest vague one.
	//
	// The case exists because error classification is platform-dependent. A
	// refused connection surfaces as a recognizable error on the platforms
	// svcdoctor inspects today, but a producer that cannot recognize one must
	// still record what it saw rather than guess.
	FailureTCPConnectionFailed

	// TLS.

	// FailureTLSHandshakeFailure means the TLS handshake failed.
	FailureTLSHandshakeFailure
	// FailureTLSCertificateExpired means the presented certificate has expired.
	FailureTLSCertificateExpired
	// FailureTLSCertificateNotYetValid means the certificate is not yet valid.
	FailureTLSCertificateNotYetValid
	// FailureTLSUnknownAuthority means the chain did not verify against the trust source.
	FailureTLSUnknownAuthority
	// FailureTLSHostnameMismatch means no certificate name matched the endpoint.
	FailureTLSHostnameMismatch
	// FailureTLSVersionMismatch means no TLS protocol version was agreed.
	FailureTLSVersionMismatch
	// FailureTLSClientCertificateRequired means the peer demanded a client certificate.
	FailureTLSClientCertificateRequired
	// FailureTLSClientCertificateRejected means the peer rejected the client certificate.
	FailureTLSClientCertificateRejected
	// FailureTLSPeerNotTLS means the peer's first response was not a TLS record,
	// so the endpoint does not speak TLS at all.
	//
	// It is deliberately distinct from FailureTLSHandshakeFailure, which means
	// TLS was spoken and did not succeed. "This port is not TLS" and "TLS broke"
	// lead to opposite actions: the first says the client is configured for the
	// wrong protocol, the second says the server's TLS is misconfigured. A
	// service-neutral fact, though it is what a plaintext-versus-encrypted port
	// mix-up looks like from the outside.
	FailureTLSPeerNotTLS

	// Protocol.

	// FailureProtocolUnexpectedResponse means the peer answered, but not as the protocol expects.
	FailureProtocolUnexpectedResponse
	// FailureProtocolUnsupportedVersion means the peer does not support a required protocol version.
	FailureProtocolUnsupportedVersion
	// FailureProtocolUnsupportedCapability means the peer does not offer a required capability.
	FailureProtocolUnsupportedCapability
	// FailureProtocolMalformedResponse means the response could not be decoded.
	FailureProtocolMalformedResponse
	// FailureProtocolPeerClosed means the peer closed the connection mid-exchange.
	FailureProtocolPeerClosed

	// Authentication.

	// FailureAuthMechanismUnsupported means svcdoctor cannot perform the mechanism.
	FailureAuthMechanismUnsupported
	// FailureAuthMechanismNotOffered means the peer does not offer the requested mechanism.
	FailureAuthMechanismNotOffered
	// FailureAuthCredentialsRejected means the peer refused the authentication
	// material it was presented.
	//
	// That is the whole of the claim, and the boundary is deliberate. It does
	// **not** state that the secret was wrong, that the principal does not
	// exist, that an account is disabled or locked, or that the peer's own
	// authentication backend was working when it answered. A refusal is
	// routinely returned for all of those, and services in scope deliberately
	// collapse them into one response so that a client cannot probe which is
	// true. A producer that could distinguish them would be recording a
	// service-specific fact as an attribute, not reaching for a narrower class.
	//
	// The root cause is therefore unknown at this layer. Naming a likely one is
	// a hypothesis, and a hypothesis is diagnosis work over frozen evidence.
	FailureAuthCredentialsRejected

	// Authorization.

	// FailureAuthzDenied means the identity authenticated but was denied the operation.
	FailureAuthzDenied
	// FailureAuthzScopeInsufficient means the granted scope does not cover the operation.
	FailureAuthzScopeInsufficient

	// Execution and policy.

	// FailureExecLocalTimeout means svcdoctor's own budget expired. It is not
	// evidence that the target failed.
	FailureExecLocalTimeout
	// FailureExecCancelled means the run was cancelled before a conclusion.
	FailureExecCancelled
	// FailureExecUnsupportedBySvcdoctor means svcdoctor cannot check this. It is
	// a gap in the tool, not a defect in the target.
	FailureExecUnsupportedBySvcdoctor
	// FailureExecInsufficientPrivilege means the check needs a privilege svcdoctor
	// does not hold. Not healthy, and not a target failure either.
	FailureExecInsufficientPrivilege
	// FailureExecSkippedByPolicy means a policy prevented the step, for example
	// the credential forwarding policy.
	FailureExecSkippedByPolicy
	// FailureExecSkippedPrerequisiteFailed means an earlier layer failed, so this
	// step was not attempted and no claim is made about it.
	FailureExecSkippedPrerequisiteFailed
	// FailureExecDepthLimit means a scope or depth rule stopped the expansion.
	FailureExecDepthLimit
)

// failureClassNames is indexed by FailureClass. Keep it aligned with the const
// block above; TestFailureClassNamesCoverAllClasses fails if the two drift.
var failureClassNames = [...]string{
	FailureNone: "NONE",

	FailureDNSNXDomain:        "DNS_NXDOMAIN",
	FailureDNSNoAddress:       "DNS_NO_ADDRESS",
	FailureDNSTimeout:         "DNS_TIMEOUT",
	FailureDNSResolverFailure: "DNS_RESOLVER_FAILURE",

	FailureTCPConnectionRefused:  "TCP_CONNECTION_REFUSED",
	FailureTCPConnectionTimeout:  "TCP_CONNECTION_TIMEOUT",
	FailureTCPConnectionReset:    "TCP_CONNECTION_RESET",
	FailureTCPNetworkUnreachable: "TCP_NETWORK_UNREACHABLE",
	FailureTCPHostUnreachable:    "TCP_HOST_UNREACHABLE",
	FailureTCPConnectionFailed:   "TCP_CONNECTION_FAILED",

	FailureTLSHandshakeFailure:          "TLS_HANDSHAKE_FAILURE",
	FailureTLSCertificateExpired:        "TLS_CERTIFICATE_EXPIRED",
	FailureTLSCertificateNotYetValid:    "TLS_CERTIFICATE_NOT_YET_VALID",
	FailureTLSUnknownAuthority:          "TLS_UNKNOWN_AUTHORITY",
	FailureTLSHostnameMismatch:          "TLS_HOSTNAME_MISMATCH",
	FailureTLSVersionMismatch:           "TLS_VERSION_MISMATCH",
	FailureTLSClientCertificateRequired: "TLS_CLIENT_CERTIFICATE_REQUIRED",
	FailureTLSClientCertificateRejected: "TLS_CLIENT_CERTIFICATE_REJECTED",
	FailureTLSPeerNotTLS:                "TLS_PEER_NOT_TLS",

	FailureProtocolUnexpectedResponse:    "PROTOCOL_UNEXPECTED_RESPONSE",
	FailureProtocolUnsupportedVersion:    "PROTOCOL_UNSUPPORTED_VERSION",
	FailureProtocolUnsupportedCapability: "PROTOCOL_UNSUPPORTED_CAPABILITY",
	FailureProtocolMalformedResponse:     "PROTOCOL_MALFORMED_RESPONSE",
	FailureProtocolPeerClosed:            "PROTOCOL_PEER_CLOSED",

	FailureAuthMechanismUnsupported: "AUTH_MECHANISM_UNSUPPORTED",
	FailureAuthMechanismNotOffered:  "AUTH_MECHANISM_NOT_OFFERED",
	FailureAuthCredentialsRejected:  "AUTH_CREDENTIALS_REJECTED",

	FailureAuthzDenied:            "AUTHZ_DENIED",
	FailureAuthzScopeInsufficient: "AUTHZ_SCOPE_INSUFFICIENT",

	FailureExecLocalTimeout:              "EXEC_LOCAL_TIMEOUT",
	FailureExecCancelled:                 "EXEC_CANCELLED",
	FailureExecUnsupportedBySvcdoctor:    "EXEC_UNSUPPORTED_BY_SVCDOCTOR",
	FailureExecInsufficientPrivilege:     "EXEC_INSUFFICIENT_PRIVILEGE",
	FailureExecSkippedByPolicy:           "EXEC_SKIPPED_BY_POLICY",
	FailureExecSkippedPrerequisiteFailed: "EXEC_SKIPPED_PREREQUISITE_FAILED",
	FailureExecDepthLimit:                "EXEC_DEPTH_LIMIT",
}

// Valid reports whether f is a defined class. FailureNone is valid.
func (f FailureClass) Valid() bool {
	return int(f) < len(failureClassNames)
}

// String returns the canonical symbolic name, or a Go-convention rendering of
// an out-of-range value. It never fails.
func (f FailureClass) String() string {
	if !f.Valid() {
		return "FailureClass(" + strconv.FormatUint(uint64(f), 10) + ")"
	}
	return failureClassNames[f]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal.
func (f FailureClass) MarshalJSON() ([]byte, error) {
	if !f.Valid() {
		return nil, fmt.Errorf("%w: FailureClass(%d)", ErrInvalidValue, uint8(f))
	}
	return []byte(strconv.Quote(failureClassNames[f])), nil
}
