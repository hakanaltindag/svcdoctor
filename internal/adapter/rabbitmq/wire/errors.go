package wire

import "errors"

// The sentinels this package returns.
//
// They are the complete vocabulary a caller may branch on. None of them wraps a
// peer's bytes: an error value that carried reply text would be exactly the
// escape ADR 0069 section 2 forbids, and a formatted %v of a peer string is
// still a peer string.
var (
	// ErrMalformedFrame means the framing itself did not decode: a declared size
	// above the ceiling, a bad frame-end byte, a truncated field, or a shortstr
	// longer than the protocol allows.
	ErrMalformedFrame = errors.New("rabbitmq: malformed frame")

	// ErrUnexpectedFrame means a well-formed frame arrived that the frozen
	// journey does not expect at this point — a non-method frame, a frame on a
	// channel other than 0, or a method that is not the one being awaited.
	ErrUnexpectedFrame = errors.New("rabbitmq: unexpected frame")

	// ErrPeerClosed means the peer closed the connection mid-exchange.
	//
	// It is a statement about the peer and not about the target's health. Phase
	// 8.0C measured three separate RabbitMQ paths that reach it deliberately: an
	// authentication failure from a client that did not advertise
	// authentication_failure_close, an invalid Tune-Ok, and an unoffered
	// mechanism. All three close silently after roughly three seconds.
	ErrPeerClosed = errors.New("rabbitmq: peer closed the connection")

	// ErrNotAMQP091 means the peer did not answer the protocol header with a
	// Connection.Start.
	//
	// It covers a returned protocol header — which is a refusal, never an
	// instruction to retry with the version it names — and an answer that is not
	// AMQP at all, such as the HTTP response a management port gives.
	ErrNotAMQP091 = errors.New("rabbitmq: peer did not begin an AMQP 0-9-1 connection")

	// ErrPlainNotOffered means the peer's mechanism list does not contain PLAIN.
	//
	// svcdoctor implements PLAIN and does not fall back (ADR 0068 section 2). It
	// is a statement about svcdoctor's vocabulary, not about the peer being
	// wrong, and it is reached with zero credential bytes sent.
	ErrPlainNotOffered = errors.New("rabbitmq: the endpoint does not offer SASL PLAIN")

	// ErrSecureChallenge means the peer sent Connection.Secure.
	//
	// Unreachable against RabbitMQ's PLAIN, which never challenges. It is
	// written down rather than assumed because answering it would be a second
	// credential-bearing frame (ADR 0068 section 5). The caller stops here.
	ErrSecureChallenge = errors.New("rabbitmq: the endpoint issued an unexpected SASL challenge")

	// ErrTuneUnsupported means the negotiation window the peer offered cannot be
	// satisfied by the frozen Tune contract.
	//
	// Reachable only against a broker configured below the AMQP frame-min-size
	// floor, which no client can satisfy. ADR 0070 section 2.
	ErrTuneUnsupported = errors.New("rabbitmq: the endpoint's frame size window cannot be satisfied")

	// ErrRefused means the peer sent a Connection.Close instead of the frame the
	// journey expected. The normalized outcome carries which refusal it was.
	ErrRefused = errors.New("rabbitmq: the endpoint refused the connection")

	// ErrInvalidInput means svcdoctor was asked to send something the protocol
	// or the frozen contract does not permit. It is a defect in the caller, not
	// a fact about the peer.
	ErrInvalidInput = errors.New("rabbitmq: invalid input")
)

// Refusal is a Connection.Close, normalized.
//
// It is the whole of what a refusal contributes above this package. The reply
// code is the peer's own numeric field and is safe to carry; the Outcome is a
// constant from this package. **The reply text is not here and has no field.**
type Refusal struct {
	// ReplyCode is the AMQP reply code the peer sent, verbatim.
	ReplyCode uint16
	// Outcome is the normalized classification. It is never a peer's substring.
	Outcome CloseOutcome
	// PeerClassID and PeerMethodID are the peer's own attribution fields.
	//
	// They are **corroboration only**. Attribution authority is svcdoctor's own
	// handshake state, which a peer cannot forge (ADR 0069 section 1). Phase
	// 8.0C measured RabbitMQ sending 0/0 for an authentication refusal and
	// LavinMQ sending 10/11 for the same condition, which is exactly why neither
	// may drive a conclusion.
	PeerClassID  uint16
	PeerMethodID uint16
}
