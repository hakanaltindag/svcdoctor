package wire

import (
	"context"
	"net"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// saslHandshakeRequestVersion is the version of SaslHandshake svcdoctor sends.
//
// Version 1 is deliberate, and it is the opposite choice from ApiVersions above.
// The two versions are not two encodings of one question; they select two
// different authentication flows:
//
//   - v0 means the client must follow a supported mechanism with raw SASL
//     tokens, outside Kafka's request framing, so a failure surfaces as a closed
//     connection rather than as an error code.
//   - v1 means authentication continues as SaslAuthenticate requests, which
//     carry an error code and an error message of their own.
//
// ADR 0008 requires a controlled connection lifecycle and framed, attributable
// outcomes, and only v1 provides them. svcdoctor also does not negotiate down: a
// broker too old for v1 answers with an error code, which is recorded as the
// fact it is, next to the ApiVersions node that already says which SaslHandshake
// versions that broker supports. A silent downgrade would change what the
// evidence means without saying so.
const saslHandshakeRequestVersion = 1

// SASLHandshake is what one SaslHandshake exchange observed, in plain Go values.
//
// The request carries a mechanism name and nothing else: no identity, no
// password, no token. That is a protocol fact rather than a design choice here,
// and it is what makes mechanism discovery a credential-free step.
type SASLHandshake struct {
	// ErrorCode is the broker's own error code, zero when it reported none.
	ErrorCode int16

	// Mechanisms is what the peer said it offers, in the order it sent them.
	// Canonical ordering is the caller's business, because ordering is a report
	// concern.
	//
	// Kafka populates this when it rejects the requested mechanism, so that a
	// client can see what it should have asked for. Whether a broker also sends
	// it on success is a broker-version detail this package does not assert: it
	// reports what arrived.
	Mechanisms []string
}

// SASLHandshakeVersion reports which version of SaslHandshake was asked for, so
// that the recorded evidence can say what the exchange actually was.
func SASLHandshakeVersion() int16 { return saslHandshakeRequestVersion }

// ExchangeSASLHandshake asks conn's broker whether it offers mechanism.
//
// The connection is borrowed, not owned; see exchange. The mechanism string is
// sent verbatim, because it is what the caller wants an answer about: normalizing
// it here would answer a different question than the one that was asked.
func ExchangeSASLHandshake(
	ctx context.Context, conn net.Conn, mechanism string,
) (SASLHandshake, error) {
	request := kmsg.NewPtrSASLHandshakeRequest()
	request.SetVersion(saslHandshakeRequestVersion)
	request.Mechanism = mechanism

	response := kmsg.NewPtrSASLHandshakeResponse()
	response.SetVersion(saslHandshakeRequestVersion)

	if err := exchange(ctx, conn, correlationSASLHandshake, request, response); err != nil {
		return SASLHandshake{}, err
	}
	return normalizeSASLHandshake(response), nil
}

// normalizeSASLHandshake copies the response into plain values, which is what
// keeps every kmsg type inside this package.
func normalizeSASLHandshake(response *kmsg.SASLHandshakeResponse) SASLHandshake {
	mechanisms := make([]string, 0, len(response.SupportedMechanisms))
	mechanisms = append(mechanisms, response.SupportedMechanisms...)
	return SASLHandshake{ErrorCode: response.ErrorCode, Mechanisms: mechanisms}
}
