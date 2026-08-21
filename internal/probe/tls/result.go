package tls

import (
	cryptotls "crypto/tls"
	"net"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Result is one handshake attempt: what it proved, and what it produced.
//
// It is the TLS counterpart of the TCP probe's Result and follows the same
// ownership rules (ADR 0021), because a caller should not have to learn a second
// discipline for the next layer:
//
//	r, err := tls.Handshake(ctx, conn, params)
//	if err != nil { return err }
//	defer r.Close()
//
//	if tlsConn, ok := r.TakeConn(); ok {
//	    defer tlsConn.Close()
//	    // the protocol exchange speaks over the connection that was measured
//	}
//
// Close is safe in every path: it releases the connection only while this Result
// still owns it, does nothing after a transfer, and does nothing on a failed
// attempt.
//
// # One socket, one owner
//
// A TLS connection wraps the connection it was given, and closing the wrapper
// closes what is underneath. So there is never a moment where a raw and a
// wrapped value both need closing: from the instant Handshake is called, the
// wrapper is the resource, and this Result owns it until somebody takes it.
//
// The two similar Result types in internal/probe/tcp and here are deliberately
// not unified. They hold different things and mean different things, and the
// architecture asks for a shared abstraction only once one is proven rather than
// noticed. Two structs that look alike are not yet a pattern.
//
// # What it is not
//
// A Result never enters the domain model. domain.Evidence cannot hold a
// connection, so nothing serialized can own a live resource. There is no
// registry, no map keyed by evidence identifier and no package-level state: the
// connection is reachable only through the value the caller was handed.
//
// A Result is not safe for concurrent use.
type Result struct {
	evidence domain.Evidence

	// verified is whether this handshake established the peer's identity. It
	// travels with the connection rather than only in the evidence, because the
	// caller that owns the socket is the one that must decide what may be
	// written to it. See Verified.
	verified bool

	// conn is nil unless the handshake completed. taken and closed are what make
	// ownership single and terminal rather than advisory.
	conn   *cryptotls.Conn
	taken  bool
	closed bool
}

// Evidence returns the normalized fact this attempt produced.
//
// It is always present, whatever the outcome. It describes the address the
// handshake ran over and the identity it checked, and says nothing about the
// connection resource: that a socket is still open is a property of this Result,
// not a diagnostic fact about the peer.
func (r *Result) Evidence() domain.Evidence { return r.evidence }

// Verified reports whether this handshake established the peer's identity.
//
// It is the same fact the evidence records as tls.verified, computed once from
// the same observation, and it is exposed here for one reason: a caller that is
// about to decide what may be written to this connection needs the fact attached
// to *this* value, which is the thing that owns the connection. Reading it back
// out of the evidence instead would associate the fact with the socket by
// convention rather than by construction, and a security fact that travels
// beside its subject rather than with it is one refactor away from describing a
// different connection.
//
// It is false for a failed handshake and false when verification was disabled.
// Those two are different diagnostic facts — the evidence distinguishes them —
// but neither established who the peer is, and this method answers only that.
func (r *Result) Verified() bool { return r.verified }

// Connected reports whether a live TLS connection is available to take.
//
// This is a statement about the resource, not about the evidence. It becomes
// false once the connection has been taken or closed, while the evidence keeps
// saying PASS — because the handshake did succeed, and that stays true whatever
// later happened to the socket.
func (r *Result) Connected() bool {
	return r.conn != nil && !r.taken && !r.closed
}

// TakeConn transfers ownership of the TLS connection to the caller.
//
// It reports false when there is nothing to transfer: the handshake failed, the
// connection was already taken, or the Result was closed first. A caller that
// receives true owns the connection and must close it; this Result will not.
//
// The returned connection is the one the handshake ran over, wrapped. Everything
// worth knowing about the handshake is already in the evidence, so a caller
// should have no reason to inspect the connection's state — it needs a
// connection to speak a protocol over, and that is what this returns.
func (r *Result) TakeConn() (net.Conn, bool) {
	if !r.Connected() {
		return nil, false
	}
	r.taken = true
	return r.conn, true
}

// Close releases the connection if this Result still owns it.
//
// It is idempotent and safe on every Result, including one whose handshake
// failed and one whose connection has been taken. After a transfer it
// deliberately does nothing: the caller that took the connection owns it, and
// closing it here would break a connection somebody else is using.
//
// Closing the TLS connection closes the connection it wraps, so a caller never
// has to track the socket underneath.
func (r *Result) Close() error {
	if r.conn == nil || r.taken || r.closed {
		return nil
	}
	r.closed = true
	return r.conn.Close()
}
