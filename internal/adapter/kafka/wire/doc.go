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
//	ExchangeAPIVersions(ctx, conn)                     -> APIVersions
//	ExchangeSASLHandshake(ctx, conn, mechanism)        -> SASLHandshake
//	ExchangePLAIN(ctx, conn, identity, secret)         -> SASLAuthenticate
//
// One request, one response, over a connection somebody else established and
// still owns. It does not dial, does not retry, does not reconnect, and does not
// switch peers: ADR 0008 requires a controlled connection lifecycle, because a
// library that quietly reconnected would attribute protocol facts to a socket
// nobody measured.
//
// # This is where a secret becomes bytes
//
// ExchangePLAIN holds svcdoctor's only call to security.Reveal, and this package
// is the only place a lint permits one (ADR 0027). The properties that make it
// the right home are structural rather than promised: it holds no state between
// exchanges, owns no connection, has no evidence or report model in scope, and
// everything it returns upward is a plain value.
//
// It checks no policy and no credential binding. Both happen in the adapter
// above, before this package is called at all, because a check duplicated in two
// layers is a check the two layers can disagree about. See ADR 0030.
//
// Nothing derived from a secret leaves. The broker's own ErrorMessage does not
// leave either: it is deployment-authored prose that routinely names principals
// and hosts, so it is dropped here rather than carried upward and filtered later.
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
