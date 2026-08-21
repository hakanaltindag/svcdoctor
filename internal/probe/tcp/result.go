package tcp

import (
	"net"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Result is one connection attempt: what it proved, and what it produced.
//
// The two halves have different lifetimes and different owners, which is why
// they are not the same object. The evidence is an immutable value describing a
// moment that has passed, and it can outlive the process's interest in the
// connection. The connection is a live resource that somebody has to close.
//
// # Ownership
//
// A Result that connected owns the connection until a caller takes it:
//
//	r, err := tcp.Connect(ctx, dialer, endpoint, addr)
//	if err != nil { return err }
//	defer r.Close()
//
//	if conn, ok := r.TakeConn(); ok {
//	    defer conn.Close()
//	    // the next stage uses the connection that was actually measured
//	}
//
// There is exactly one owner at any moment and the transfer is explicit. Close
// is safe in every path — before a transfer it closes, after a transfer it does
// nothing, and a second call does nothing — so the deferred Close above is
// correct whether or not the connection is taken. Making the safe usage also the
// simple one is the point: a resource contract that requires the caller to
// remember which branch they are in is a leak waiting to be written.
//
// # Why this type exists at all
//
// The alternative — a probe that dials, measures and closes — would force the
// next stage to dial again. Every fact measured would then describe a connection
// the protocol exchange never used, and nothing would fail: the report would
// still look right. See ADR 0021.
//
// # What it is not
//
// A Result never enters the domain model. domain.Evidence cannot hold a net.Conn
// and neither can the graph or the report, so a live resource has no path into
// anything that gets serialized. There is no registry, no map keyed by evidence
// identifier and no package-level state: the connection is reachable only
// through the value the caller was handed.
//
// A Result is not safe for concurrent use. One attempt has one owner, and the
// transfer would mean nothing if two goroutines could both win it.
type Result struct {
	evidence domain.Evidence

	// conn is nil unless the attempt established one. taken and closed are what
	// make ownership single and terminal rather than advisory.
	conn   net.Conn
	taken  bool
	closed bool
}

// Evidence returns the normalized fact this attempt produced.
//
// It is always present, whatever the outcome, and it is what goes into the graph.
// It describes the address that was dialed and says nothing about the connection
// resource: that a socket is still open is a property of this Result, not a
// diagnostic fact about the target.
func (r *Result) Evidence() domain.Evidence { return r.evidence }

// Connected reports whether a live connection is available to take.
//
// This is a statement about the resource, not about the evidence. It becomes
// false once the connection has been taken or closed, while the evidence keeps
// saying PASS — because the attempt did succeed, and that stays true no matter
// what later happened to the socket.
func (r *Result) Connected() bool {
	return r.conn != nil && !r.taken && !r.closed
}

// TakeConn transfers ownership of the connection to the caller.
//
// It reports false when there is nothing to transfer: the attempt failed, the
// connection was already taken, or the Result was closed first. A caller that
// receives true owns the connection and must close it; this Result will not.
//
// The second call returns false rather than the same connection again. Two
// callers holding one connection is precisely the ambiguity this type exists to
// remove, and the alternative — handing it out twice and hoping — produces a
// double close or a use-after-close far from the code that caused it.
func (r *Result) TakeConn() (net.Conn, bool) {
	if !r.Connected() {
		return nil, false
	}
	r.taken = true
	return r.conn, true
}

// Close releases the connection if this Result still owns it.
//
// It is idempotent and safe on every Result, including one whose attempt failed
// and one whose connection has been taken. After a transfer it deliberately does
// nothing: the caller that took the connection owns it, and closing it here would
// break a connection somebody else is using.
//
// The error is the connection's, unwrapped, so a caller can inspect it.
func (r *Result) Close() error {
	if r.conn == nil || r.taken || r.closed {
		return nil
	}
	r.closed = true
	return r.conn.Close()
}
