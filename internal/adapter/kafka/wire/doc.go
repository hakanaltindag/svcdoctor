// Package wire is the only place in svcdoctor that knows the Kafka protocol
// library.
//
// It exists so that the coupling has a boundary with a name. Everything above it
// works with plain Go values: the types this package returns hold int16s and
// slices of them, never a kmsg struct, never a protocol error type, never a
// buffer. Replacing franz-go would rewrite this package and nothing else.
//
// # What it does
//
//	ExchangeAPIVersions(ctx, conn) -> APIVersions
//
// One request, one response, over a connection somebody else established and
// still owns. It does not dial, does not retry, does not reconnect, and does not
// switch peers: ADR 0008 requires a controlled connection lifecycle, because a
// library that quietly reconnected would attribute protocol facts to a socket
// nobody measured.
//
// That is also why only kmsg is imported and not kgo. kmsg encodes and decodes
// messages; kgo is a client that owns connections, refreshes metadata and retries.
// The parts of kgo that make it a good production client are exactly the parts
// that would destroy the evidence.
//
// # Framing
//
// kmsg writes the complete request, including the length prefix and the request
// header. This package reads the response's length prefix and correlation
// identifier — the two things the caller owns because it owns the socket — and
// hands the body back to kmsg. No protocol bytes are hand-written.
//
// # Errors
//
// Failures come back as sentinel errors that name what was observed, so the
// layer above can classify without reading error text: ErrPeerClosed,
// ErrNotKafka, ErrMalformedResponse. Anything else is the connection's own error.
package wire
