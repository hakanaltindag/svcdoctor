package transport

import (
	"net"
	"net/netip"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// Continuation is one transport path that completed everything the caller asked
// for, together with the live connection it produced.
//
// It exists so that a caller can speak a protocol over a connection whose
// establishment was measured. Everything about the path is already in the
// evidence graph; this adds the resource and the identifier needed to keep
// going.
type Continuation struct {
	endpoint   string
	address    netip.AddrPort
	evidenceID domain.EvidenceID
	channel    security.Channel

	conn   net.Conn
	taken  bool
	closed bool
}

// Endpoint returns the logical label this path belongs to, such as
// "primary.internal:9092".
//
// A later layer needs it to scope its own evidence identifiers to the same
// endpoint the transport nodes used. It is reported here rather than passed
// again by the caller, so the two can never disagree and produce one run with
// two identifier scopes for one endpoint.
func (c *Continuation) Endpoint() string { return c.endpoint }

// Address returns the peer this path reached.
//
// It is reported rather than read off the socket because a connection's remote
// address is not always the address the evidence was recorded against — a proxy
// or a test double may say otherwise — and the two must agree.
func (c *Continuation) Address() netip.AddrPort { return c.address }

// Channel reports what this connection proved about the peer at the other end
// of it.
//
// It exists so that a layer about to write a secret does not have to work the
// answer out for itself. Every other way of asking is worse: inspecting the
// net.Conn re-derives a fact this layer already had and puts TLS semantics in a
// package that should have none, reading the graph makes an adapter depend on
// evidence structure, and looking at the run's configuration reports what was
// *asked for* rather than what happened.
//
// The value describes this connection and no other. It is set once, next to the
// connection, at the moment the chain decides to keep it, so a Continuation
// whose channel describes a different socket cannot be constructed from outside
// this package.
//
// It is a mechanism fact. Whether it is good enough to carry a credential is
// security.CredentialTransportPolicy's question. See ADR 0029.
func (c *Continuation) Channel() security.Channel { return c.channel }

// Evidence returns the identifier of the deepest node recorded for this path:
// the TLS node when TLS ran, otherwise the TCP node.
//
// A protocol layer parents its own evidence to it, so the graph shows the
// exchange happening over the transport that was measured.
func (c *Continuation) Evidence() domain.EvidenceID { return c.evidenceID }

// Available reports whether the connection is still here to take.
func (c *Continuation) Available() bool {
	return c.conn != nil && !c.taken && !c.closed
}

// TakeConn transfers ownership of this path's connection to the caller.
//
// It reports false when the connection has already been taken or closed. A
// caller that receives true owns the connection and must close it; neither this
// Continuation nor the Result will.
func (c *Continuation) TakeConn() (net.Conn, bool) {
	if !c.Available() {
		return nil, false
	}
	c.taken = true
	return c.conn, true
}

// Close releases this path's connection if it is still owned here.
//
// It is idempotent, and it does nothing after a transfer. A caller that has
// chosen one path can close the others individually, or close the Result and
// release them all at once.
func (c *Continuation) Close() error {
	if c.conn == nil || c.taken || c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// Result is what a chain run leaves the caller holding: the connections of every
// path that completed, and nothing else.
//
// It carries no graph. The chain wrote its evidence into the builder the caller
// supplied, because one endpoint is not one report and only the caller knows
// when a run is finished.
//
// # The chain chooses nothing
//
// Every path that completed what was asked is returned. The chain does not pick
// one, because there is no transport-level reason to prefer one working path
// over another, and any rule it applied would be a client policy dressed as a
// mechanism — canonical address order, for instance, would make IPv4 the
// continuation whenever both families work.
//
// Which path a protocol should speak over is a decision for the layer that knows
// what it is about to say. See ADR 0024.
//
// # Ownership
//
//	r, err := transport.Run(ctx, builder, params)
//	if err != nil { return err }
//	defer r.Close()                      // releases every path not taken
//
//	for _, path := range r.Continuations() {
//	    if conn, ok := path.TakeConn(); ok {
//	        defer conn.Close()           // the caller owns this one now
//	        break
//	    }
//	}
//
// The rules are the ones ADR 0021 fixed for the probes: a connection has exactly
// one owner at any moment, a transfer happens at most once, and Close is safe to
// defer unconditionally. A caller that wanted only the evidence closes the
// Result and every connection goes with it.
//
// A Result is not safe for concurrent use.
type Result struct {
	continuations []*Continuation
}

// Continuations returns every path that completed, in the canonical address
// order the DNS probe produced.
//
// **That order is evidence ordering, not a ranking.** It exists so a report is
// byte-stable for the same facts; the first entry is not a recommendation, and a
// caller that takes it is making its own choice rather than following one made
// here. A caller with no preference should say so, in its own layer, where the
// reason can be recorded.
//
// The returned slice is a copy, so a caller cannot reorder what the Result
// holds, but the Continuations themselves are shared: taking a connection
// through one of them takes it from the Result too.
func (r *Result) Continuations() []*Continuation {
	if len(r.continuations) == 0 {
		return nil
	}
	out := make([]*Continuation, len(r.continuations))
	copy(out, r.continuations)
	return out
}

// Close releases every connection the Result still owns.
//
// It is idempotent, safe when nothing was retained, and skips any path whose
// connection has already been taken. The first error is returned; every
// connection is closed regardless.
func (r *Result) Close() error {
	var firstErr error
	for _, continuation := range r.continuations {
		if err := continuation.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// add records a completed path and takes ownership of its connection.
//
// The channel is supplied here rather than derived later, so the connection and
// the fact describing it enter the Result in one statement and cannot be paired
// up wrongly afterwards.
func (r *Result) add(
	conn net.Conn,
	endpoint string,
	address netip.AddrPort,
	evidenceID domain.EvidenceID,
	channel security.Channel,
) {
	r.continuations = append(r.continuations, &Continuation{
		endpoint:   endpoint,
		address:    address,
		evidenceID: evidenceID,
		channel:    channel,
		conn:       conn,
	})
}
