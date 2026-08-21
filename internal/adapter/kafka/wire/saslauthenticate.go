package wire

import (
	"context"
	"net"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// saslAuthenticateRequestVersion is the version of SaslAuthenticate svcdoctor
// sends.
//
// Version 1 is the smallest version that carries the facts this step records,
// and the choice is bounded on both sides rather than being "the newest":
//
//   - v0 answers with an error code and an error message, which is already
//     enough to tell "rejected" from "broken". It has no session lifetime.
//   - v1 adds SessionLifetimeMillis, which is how long the broker considers the
//     authentication valid. That is a fact about the target's configuration
//     that nothing else in a run reports, and recording it costs one field.
//   - v2 is flexible. The framing in exchange.go reads a v0 response header and
//     refuses flexible messages, because a flexible response carries tagged
//     header fields this reader does not consume and would misparse the body by.
//     Sending v2 would mean changing the shared framing for one optional field
//     nothing reads, so it is not sent. The guard makes that a returned error
//     rather than a silent misparse.
//
// A broker too old for v1 answers UNSUPPORTED_VERSION, which is recorded as the
// fact it is next to the ApiVersions node that already says which SaslAuthenticate
// versions that broker supports. There is no automatic downgrade, for the reason
// the handshake gives: it would change what the evidence means without saying so.
const saslAuthenticateRequestVersion = 1

// SASLAuthenticate is what one SaslAuthenticate exchange observed, in plain Go
// values.
//
// # What it deliberately does not carry
//
// The response has two more fields, and neither leaves this package.
//
// SASLAuthBytes is the server's continuation of the SASL exchange. PLAIN is a
// single round trip, so there is nothing to continue and nothing there worth a
// caller's attention; a mechanism that needs it will read it here, where the
// bytes stay.
//
// ErrorMessage is broker-supplied prose. It is written by the deployment, not by
// the protocol, and it routinely names principals, listeners, realms and
// internal hosts. Nothing above this package can carry it safely — evidence
// attributes have no sanitization step and a report is meant to be shareable —
// so it is dropped at the boundary rather than carried and then filtered. The
// error code is the normalized fact, and it is the one the protocol defines.
// See ADR 0030.
type SASLAuthenticate struct {
	// ErrorCode is the broker's own error code, zero when it reported none.
	ErrorCode int16

	// SessionLifetimeMillis is how long the broker considers this
	// authentication valid. Zero means the broker stated no expiry.
	//
	// It is reported, never acted on. Re-authenticating when it elapses is
	// client behaviour, and ADR 0008 keeps client behaviour out of the measured
	// path.
	SessionLifetimeMillis int64
}

// SASLAuthenticateVersion reports which version of SaslAuthenticate was asked
// for, so that the recorded evidence can say what the exchange actually was.
func SASLAuthenticateVersion() int16 { return saslAuthenticateRequestVersion }

// ExchangePLAIN authenticates over conn with SASL/PLAIN and reads the response.
//
// The connection is borrowed, not owned; see exchange. It must already have
// completed a SaslHandshake naming PLAIN, which is what the caller's type
// guarantees.
//
// # This is where a secret becomes bytes
//
// It is the only function in svcdoctor that calls security.Reveal, and it is one
// call away from the socket by construction: this package holds no state between
// exchanges, has no evidence model in scope, and owns no connection. See ADR
// 0027 for why the boundary is here and ADR 0030 for what the caller must have
// checked before arriving.
//
// The caller obtains secret from Credential.SecretFor, so the endpoint binding
// has already been verified, and checks the channel policy before calling. This
// function performs neither check: duplicating them here would mean two places
// could disagree about whether a credential may be sent, and the wire boundary
// is the wrong one of the two to hold policy.
func ExchangePLAIN(
	ctx context.Context, conn net.Conn, identity string, secret security.Secret,
) (SASLAuthenticate, error) {
	request := kmsg.NewPtrSASLAuthenticateRequest()
	request.SetVersion(saslAuthenticateRequestVersion)
	request.SASLAuthBytes = plainAuthBytes(identity, secret)

	response := kmsg.NewPtrSASLAuthenticateResponse()
	response.SetVersion(saslAuthenticateRequestVersion)

	if err := exchange(ctx, conn, correlationSASLAuthenticate, request, response); err != nil {
		return SASLAuthenticate{}, err
	}
	return normalizeSASLAuthenticate(response), nil
}

// plainAuthBytes builds the SASL/PLAIN message.
//
// RFC 4616 defines it as three NUL-separated fields:
//
//	authzid NUL authcid NUL passwd
//
// # The authorization identity is empty, and that is the specified form
//
// An empty authzid means "act as the authenticating identity", which is what
// every ordinary Kafka client sends and what svcdoctor means. It is written as a
// leading NUL with nothing before it — the field is present and empty, not
// omitted, because omitting it would produce a two-field message the broker
// cannot parse.
//
// security.Credential models an identity and a secret and has no authorization
// identity, so there is nothing to put there even if a value were wanted.
// Overloading Identity to mean both would give one field two meanings, and
// inventing a second field for a value no caller can supply would be speculative.
// If a deployment ever needs a distinct authzid, that is a change to the
// credential model with a record attached, not a reinterpretation here.
//
// # Lifetime
//
// The plaintext exists as a local in this function and in the payload it
// returns. It is not stored, not logged, not returned to the caller, and not put
// into any error: the two values built here go into the request and out through
// the socket, and nothing else in this file can reach them.
//
// **No erasure is claimed, and none is performed.** By the time these bytes
// reach the socket, kmsg has copied them into the encoded frame it builds, so
// zeroing the slice here would leave that copy untouched while implying the
// value was gone — and the string returned by Reveal cannot be erased at all,
// because Go strings are immutable and the garbage collector may have moved it
// already. internal/security/doc.go has stated since Phase 1 that Go cannot
// guarantee erasure and that memory exposure is addressed by process hardening
// instead; a Zero call here would be theatre that contradicts it. See ADR 0030.
func plainAuthBytes(identity string, secret security.Secret) []byte {
	password := security.Reveal(secret)

	payload := make([]byte, 0, len(identity)+len(password)+2)
	payload = append(payload, 0)
	payload = append(payload, identity...)
	payload = append(payload, 0)
	payload = append(payload, password...)
	return payload
}

// normalizeSASLAuthenticate copies the response into plain values, which is what
// keeps every kmsg type inside this package — and, here, what keeps the broker's
// error message inside it too. The two fields below are the whole of what leaves.
func normalizeSASLAuthenticate(response *kmsg.SASLAuthenticateResponse) SASLAuthenticate {
	return SASLAuthenticate{
		ErrorCode:             response.ErrorCode,
		SessionLifetimeMillis: response.SessionLifetimeMillis,
	}
}
