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
//   - In a mechanism where both parties authenticate, the two directions stay
//     distinct: "the peer refused what I presented" and "the peer could not
//     prove itself to me" are different observations that lead to opposite
//     actions, and neither may be normalized into the other.
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
	// FailureAuthPeerVerificationFailed means the peer failed to prove its own
	// knowledge of the authentication material, in a mechanism where both
	// parties authenticate.
	//
	// **It is the opposite direction from FailureAuthCredentialsRejected**, and
	// the two must never share a class. That one says the peer refused what
	// svcdoctor presented. This one says svcdoctor refused what the *peer*
	// presented: in a mutual mechanism the peer must prove itself in turn, and
	// this class records that proof failing svcdoctor's own check. Reaching it
	// normally requires the peer to have already accepted what it was given,
	// so reporting it as a rejected credential inverts what happened.
	//
	// The observation proves exactly one thing: **the value the peer presented
	// failed svcdoctor's verification.** It does not state that the peer refused
	// svcdoctor's credential, that the credential is wrong, that the peer is
	// malicious, that anything sits on the path, that the peer is not the
	// service it claims to be, or that the root cause is known. A peer that does
	// not hold the credential, an intermediary answering in its place, and a
	// defective implementation produce the same observation.
	//
	// It is service-neutral: any mechanism that authenticates both parties has
	// this outcome, and the class carries no mechanism name and no protocol
	// detail. Which mechanism was performed belongs on the evidence node as an
	// attribute.
	//
	// "your credential was refused" sends a reader to a secret store; "this peer
	// could not prove itself" tells them to stop and establish what they are
	// talking to. Collapsing the two would send them to the wrong place, which
	// is the same argument the three classes above rest on.
	FailureAuthPeerVerificationFailed

	// Authorization.

	// FailureAuthzDenied means the identity authenticated but was denied the operation.
	FailureAuthzDenied
	// FailureAuthzScopeInsufficient means the granted scope does not cover the operation.
	FailureAuthzScopeInsufficient
	// FailureAuthzNotPermitted means the peer refused the connection on the
	// basis of who is connecting and from where, without evaluating any
	// authentication material.
	//
	// It is deliberately distinct from the two classes either side of it, and
	// the distinction is what a reader acts on.
	// FailureAuthCredentialsRejected says the peer refused the material it was
	// presented — and here none was presented, because the refusal arrived
	// before any authentication was requested. FailureAuthzDenied says an
	// identity authenticated and was denied an operation — and here nothing
	// authenticated.
	//
	// "your credential is wrong" sends a reader to a secret store; "you may not
	// attempt this from here" sends them to a host-based access rule or a
	// network policy. Collapsing the two would send them to the wrong place.
	//
	// It is service-neutral: PostgreSQL refuses this way through pg_hba.conf,
	// and the same shape of pre-authentication refusal exists elsewhere.
	FailureAuthzNotPermitted

	// Resources.

	// FailureResourceNotFound means the named resource an operation targeted is
	// not available as an existing resource, according to the peer.
	//
	// That is the whole of the claim, and every word of it is load-bearing.
	// **According to the peer**: the peer asserted the absence either with a code
	// whose own meaning is absence, or with a normalized peer statement of absence
	// that a producer reconstructed from the run's own input and matched exactly —
	// and a producer never infers this class from a generic error plus a plausible
	// position. **The named resource an operation targeted**: the name came from
	// the run's own input, so the class says something about what was asked for,
	// not about the peer's inventory in general.
	//
	// The second admissible form was added in Phase 8.1 (ADR 0069 section 6.3) and
	// **raises** the bar rather than lowering it. RabbitMQ reports a missing
	// virtual host with 530 NOT_ALLOWED, a code it also uses for five other
	// conditions, and distinguishes them only in the reply text. Reconstructing
	// that exact sentence from the vhost and username the run itself supplied, and
	// requiring byte equality, is stronger evidence than a numeric code emitted for
	// six conditions. What it does not admit is a substring search, a prefix scan
	// or any reading of peer bytes svcdoctor did not already predict.
	//
	// It is deliberately silent about cause. It does **not** state that the
	// resource never existed, that it was deliberately removed, that it was
	// renamed, that the peer's own catalog or storage is healthy, or that no
	// corruption occurred. A peer routinely answers the same way for several of
	// those, and svcdoctor cannot tell them apart from the wire. Naming a likely
	// cause is a hypothesis, and a hypothesis is diagnosis work over frozen
	// evidence.
	//
	// It is not authorization: nothing was denied, because there was nothing to
	// be denied on. It is not a protocol failure: the exchange was well formed
	// and the peer answered it.
	FailureResourceNotFound

	// FailureResourceLimitReached means the peer refused the operation because a
	// capacity bound it enforces was reached, and said so itself.
	//
	// That is the whole of the claim. **A capacity bound it enforces**: a
	// configured ceiling on how many of something may exist at once, not a
	// judgement about the identity asking. **Said so itself**: the peer named the
	// condition, and a producer never infers this class from a generic refusal
	// plus a plausible position — a refusal that merely *might* be a limit is
	// FailureProtocolUnexpectedResponse, and stays there.
	//
	// It is deliberately silent about cause. It does **not** state that the limit
	// is configured too low, that demand is abnormal, that a client is leaking
	// connections, that a pool is misconfigured, that the condition will still
	// hold a second later, or who consumed the capacity. The remedy differs for
	// every one of those and the evidence separates none of them. A second run a
	// moment later may succeed.
	//
	// **It is none of the three classes nearest it**, and the distinctions are
	// what a reader acts on:
	//
	//   - FailureAuthzDenied says an identity authenticated and was denied an
	//     operation. Here nothing about the identity was evaluated — the same
	//     ceiling refuses every principal, and the very same run would have been
	//     refused with any credential.
	//   - FailureAuthzNotPermitted says the peer refused on who is connecting and
	//     from where. A node-wide ceiling is about neither.
	//   - FailureProtocolUnexpectedResponse says the peer answered, but not as
	//     the protocol expects. Here the answer is a defined error path and is
	//     exactly what the protocol expects; the peer is working.
	//
	// "you have hit a ceiling" sends a reader to a capacity or configuration
	// decision; "you lack permission" sends them to a permissions table; "the
	// peer misbehaved" sends them to the peer's own health. Collapsing any two
	// would send them to the wrong place.
	//
	// It is service-neutral, and it has more than one producer by construction:
	// PostgreSQL reports it as SQLSTATE 53300 too_many_connections while
	// establishing a session (measured in Phase 7.3A), and RabbitMQ reports three
	// separate ceilings — node, virtual host and user — at Connection.Open
	// (measured in Phase 8.0C). See ADR 0069.
	FailureResourceLimitReached

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
	// FailureExecRequiredInputMissing means the step could not run because an
	// input that step required was not supplied to the run.
	//
	// That is the whole of the claim, and it is about the run rather than about
	// the peer. It does **not** state that the target is broken, that the missing
	// input is invalid or wrong anywhere else, that whoever started the run made
	// a mistake, that the step was attempted, or that the peer refused, answered
	// or observed anything at all. Nothing was sent.
	//
	// It is service-neutral and names no kind of input. A run that reaches an
	// authentication step without authentication material, and a future step that
	// needs a certificate, a token or a file it was never given, reach the same
	// condition; the step's own evidence says which input was wanted.
	//
	// **It is none of the three classes it sits beside**, and the distinctions
	// are what a reader acts on:
	//
	//   - FailureExecSkippedByPolicy: the input exists and a policy refused to
	//     use it. Something was available and was deliberately not used.
	//   - FailureExecUnsupportedBySvcdoctor: svcdoctor cannot perform the
	//     operation at all, whatever it was given.
	//   - FailureExecInsufficientPrivilege: the operation was attempted with an
	//     identity that was not enough.
	//
	// Here the operation is one svcdoctor can perform, no policy objected, and
	// the run had nothing to perform it with.
	FailureExecRequiredInputMissing
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

	FailureAuthMechanismUnsupported:   "AUTH_MECHANISM_UNSUPPORTED",
	FailureAuthMechanismNotOffered:    "AUTH_MECHANISM_NOT_OFFERED",
	FailureAuthCredentialsRejected:    "AUTH_CREDENTIALS_REJECTED",
	FailureAuthPeerVerificationFailed: "AUTH_PEER_VERIFICATION_FAILED",

	FailureAuthzDenied:            "AUTHZ_DENIED",
	FailureAuthzScopeInsufficient: "AUTHZ_SCOPE_INSUFFICIENT",
	FailureAuthzNotPermitted:      "AUTHZ_NOT_PERMITTED",

	FailureResourceNotFound:     "RESOURCE_NOT_FOUND",
	FailureResourceLimitReached: "RESOURCE_LIMIT_REACHED",

	FailureExecLocalTimeout:              "EXEC_LOCAL_TIMEOUT",
	FailureExecCancelled:                 "EXEC_CANCELLED",
	FailureExecUnsupportedBySvcdoctor:    "EXEC_UNSUPPORTED_BY_SVCDOCTOR",
	FailureExecInsufficientPrivilege:     "EXEC_INSUFFICIENT_PRIVILEGE",
	FailureExecRequiredInputMissing:      "EXEC_REQUIRED_INPUT_MISSING",
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
