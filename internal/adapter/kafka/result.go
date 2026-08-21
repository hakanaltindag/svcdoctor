package kafka

import (
	"net"
	"net/netip"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
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
	ownedConn

	endpoint   string
	address    netip.AddrPort
	evidenceID domain.EvidenceID
	channel    security.Channel
}

// Endpoint returns the logical label this path belongs to, such as
// "primary.internal:9092".
//
// It is the endpoint the transport chain was asked about, carried through
// unchanged from transport.Continuation.Endpoint. A later Kafka step needs it
// twice over: to scope its own evidence identifiers to the same endpoint the
// transport nodes used, and — once credentials exist — to name the endpoint a
// credential must be bound to. Both must be the name a human asked about, never
// the address it resolved to. See ADR 0026.
func (s *Session) Endpoint() string { return s.endpoint }

// Address returns the broker this session speaks to.
func (s *Session) Address() netip.AddrPort { return s.address }

// Channel reports what the connection under this session proved about its peer,
// carried through unchanged from the transport path it continues.
//
// The adapter neither computes nor adjusts it, and must not: it never performed
// a handshake, so the only honest source of the fact is the layer that did.
//
// That is a contract this package keeps rather than a property Go enforces on
// it — a package owns its own fields, so nothing in the language stops this one
// from writing whatever it likes here. What does the work instead: the
// constructors below copy the value from the object being continued rather than
// taking it as a parameter, a lint forbids naming a security.Channel constant in
// this package, and the tests fail if a channel is forged or downgraded. See
// ADR 0029.
func (s *Session) Channel() security.Channel { return s.channel }

// Evidence returns the identifier of the ApiVersions node for this session.
//
// A later Kafka step parents its own evidence to it, so the graph keeps showing
// which measured path each protocol fact came from.
func (s *Session) Evidence() domain.EvidenceID { return s.evidenceID }

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
//
// Everything that describes the path — its endpoint, its address and what its
// connection proved — is copied from the transport path itself rather than
// passed alongside it. A caller therefore cannot supply a channel at all, so it
// cannot supply the wrong one: substituting a stronger value would mean editing
// this function, which is a visible change to a security-carrying constructor
// rather than a wrong argument at a call site. See ADR 0029.
func (r *Result) add(conn net.Conn, path *transport.Continuation, evidenceID domain.EvidenceID) {
	r.sessions = append(r.sessions, &Session{
		ownedConn:  ownedConn{conn: conn},
		endpoint:   path.Endpoint(),
		address:    path.Address(),
		evidenceID: evidenceID,
		channel:    path.Channel(),
	})
}

// HandshakeSession is one path whose broker accepted a SASL mechanism, together
// with the connection the handshake ran over.
//
// It is a distinct type from Session, and the distinction is the point: a
// connection that has completed a SaslHandshake is in a state where the only
// message the broker will accept is the continuation of that mechanism's
// exchange. Authentication therefore consumes a HandshakeSession and cannot be
// handed a Session, so "authenticate before the mechanism was agreed" is a
// compile error rather than a protocol error discovered on the wire.
//
// Only an accepted handshake produces one. See ADR 0026.
type HandshakeSession struct {
	ownedConn

	endpoint   string
	address    netip.AddrPort
	mechanism  string
	evidenceID domain.EvidenceID
	channel    security.Channel
}

// Endpoint returns the logical label this path belongs to, carried through from
// the Session it continued.
func (s *HandshakeSession) Endpoint() string { return s.endpoint }

// Address returns the broker this session speaks to.
func (s *HandshakeSession) Address() netip.AddrPort { return s.address }

// Channel reports what the connection under this session proved about its peer.
//
// This is the accessor authentication will consult, because a HandshakeSession
// is what authentication consumes. The fact has travelled from the handshake
// that established it, through the transport chain and both adapter steps,
// copied at each hop from the object being continued and unchanged by any of
// them. See Session.Channel for what enforces that.
func (s *HandshakeSession) Channel() security.Channel { return s.channel }

// Mechanism returns the SASL mechanism the broker accepted.
//
// It is reported here rather than passed again by a later caller, so that the
// mechanism authentication continues with cannot disagree with the one the
// broker actually agreed to.
func (s *HandshakeSession) Mechanism() string { return s.mechanism }

// Evidence returns the identifier of the SaslHandshake node for this session.
func (s *HandshakeSession) Evidence() domain.EvidenceID { return s.evidenceID }

// HandshakeResult is what a SASL handshake run leaves the caller holding: one
// session per path whose broker accepted the mechanism.
//
// # What is not here
//
// A path whose broker rejected the mechanism, or answered with any other error,
// is absent — its evidence is in the graph and its connection is closed. The
// reason is protocol state rather than the recorded state: an accepted handshake
// is the only outcome with a defined next message on that socket, and svcdoctor
// does not hold connections whose only continuation does not exist. See ADR 0026.
//
// A HandshakeResult is not safe for concurrent use.
type HandshakeResult struct {
	sessions []*HandshakeSession
}

// Sessions returns every session whose handshake was accepted, in the order the
// input sessions were given.
//
// That order is evidence ordering, not a ranking. Nothing here selects a path,
// which matters more than it did for ApiVersions: the next step after a
// handshake is the one that sends credentials, and a list that arrived in a
// meaningful-looking order would be an invitation to treat the first entry as a
// choice somebody made. Nobody made one. See ADR 0026.
func (r *HandshakeResult) Sessions() []*HandshakeSession {
	if len(r.sessions) == 0 {
		return nil
	}
	out := make([]*HandshakeSession, len(r.sessions))
	copy(out, r.sessions)
	return out
}

// Close releases every connection the HandshakeResult still owns.
//
// It is idempotent, safe when nothing was accepted, and skips any session whose
// connection has been taken. The first error is returned; every connection is
// closed regardless.
func (r *HandshakeResult) Close() error {
	var firstErr error
	for _, session := range r.sessions {
		if err := session.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// add records an accepted handshake and takes ownership of its connection.
//
// As above, the path's identity and channel are copied from the session being
// continued rather than passed in. The mechanism is a parameter because it is
// the one thing this step established and the previous one did not.
func (r *HandshakeResult) add(
	conn net.Conn, session *Session, mechanism string, evidenceID domain.EvidenceID,
) {
	r.sessions = append(r.sessions, &HandshakeSession{
		ownedConn:  ownedConn{conn: conn},
		endpoint:   session.Endpoint(),
		address:    session.Address(),
		mechanism:  mechanism,
		evidenceID: evidenceID,
		channel:    session.Channel(),
	})
}
