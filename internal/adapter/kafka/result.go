package kafka

import (
	"net"
	"net/netip"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Session is one transport path whose ApiVersions exchange completed, together
// with the connection it ran over.
//
// "Completed" means the request was written, a well-formed response was read and
// it answered that request. A broker that replied with an error code completed
// its exchange: the evidence records the error, and the connection is still
// usable for whatever is asked next.
//
// The connection is still open on purpose. The next phases — SASL, then
// Metadata — continue on the same socket, because a protocol exchange over a
// connection nobody measured describes something the report does not contain
// (ADR 0021).
type Session struct {
	address    netip.AddrPort
	evidenceID domain.EvidenceID

	conn   net.Conn
	taken  bool
	closed bool
}

// Address returns the broker this session speaks to.
func (s *Session) Address() netip.AddrPort { return s.address }

// Evidence returns the identifier of the ApiVersions node for this session.
//
// A later Kafka step parents its own evidence to it, so the graph keeps showing
// which measured path each protocol fact came from.
func (s *Session) Evidence() domain.EvidenceID { return s.evidenceID }

// Available reports whether the connection is still here to take.
func (s *Session) Available() bool {
	return s.conn != nil && !s.taken && !s.closed
}

// TakeConn transfers ownership of this session's connection to the caller.
//
// A caller that receives true owns the connection and must close it; neither
// this Session nor the Result will.
func (s *Session) TakeConn() (net.Conn, bool) {
	if !s.Available() {
		return nil, false
	}
	s.taken = true
	return s.conn, true
}

// Close releases this session's connection if it is still owned here. It is
// idempotent and does nothing after a transfer.
func (s *Session) Close() error {
	if s.conn == nil || s.taken || s.closed {
		return nil
	}
	s.closed = true
	return s.conn.Close()
}

// Result is what a Kafka run leaves the caller holding: one session per path
// whose exchange completed.
//
// It carries no graph. The adapter wrote its evidence into the builder the
// caller supplied, for the same reason the transport chain does: one endpoint is
// not one report.
//
// # The adapter chooses nothing
//
// Every path that answered is here. Which broker a later step should talk to is
// a decision for the layer that knows what it is about to ask, and this package
// deliberately does not make it — exactly as the transport chain does not choose
// a continuation (ADR 0024).
//
//	r, err := kafka.Run(ctx, builder, paths, params)
//	if err != nil { return err }
//	defer r.Close()                    // releases every session not taken
//
//	for _, session := range r.Sessions() {
//	    if conn, ok := session.TakeConn(); ok {
//	        defer conn.Close()
//	    }
//	}
//
// A Result is not safe for concurrent use.
type Result struct {
	sessions []*Session
}

// Sessions returns every session, in the order the transport paths were given.
//
// That order comes from the transport chain's canonical address ordering. It is
// evidence ordering, not a ranking: the first entry is not a recommendation, and
// a caller that takes it is making its own choice.
//
// The slice is a copy; the Sessions themselves are shared, so taking a
// connection through one takes it from the Result too.
func (r *Result) Sessions() []*Session {
	if len(r.sessions) == 0 {
		return nil
	}
	out := make([]*Session, len(r.sessions))
	copy(out, r.sessions)
	return out
}

// Close releases every connection the Result still owns.
//
// It is idempotent, safe when nothing succeeded, and skips any session whose
// connection has been taken. The first error is returned; every connection is
// closed regardless.
func (r *Result) Close() error {
	var firstErr error
	for _, session := range r.sessions {
		if err := session.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// add records a completed session and takes ownership of its connection.
func (r *Result) add(conn net.Conn, address netip.AddrPort, evidenceID domain.EvidenceID) {
	r.sessions = append(r.sessions, &Session{
		address:    address,
		evidenceID: evidenceID,
		conn:       conn,
	})
}
