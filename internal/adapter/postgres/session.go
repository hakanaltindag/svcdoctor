package postgres

import (
	"net"
	"net/netip"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// ownedConn is the ADR 0021 ownership rules, once, for this package.
//
// It is a deliberate copy of the one in internal/adapter/kafka rather than a
// shared helper. The rules are a security property, and the two adapters are the
// only implementations; extracting them would create a generic connection
// framework on the evidence of two structs that look alike, which
// docs/ARCHITECTURE.md declines to call a pattern.
type ownedConn struct {
	conn   net.Conn
	taken  bool
	closed bool
}

// Available reports whether the connection is still here to take.
func (o *ownedConn) Available() bool {
	return o.conn != nil && !o.taken && !o.closed
}

// TakeConn transfers ownership of the connection to the caller.
//
// A caller that receives true owns the connection and must close it; nothing in
// this package will.
func (o *ownedConn) TakeConn() (net.Conn, bool) {
	if !o.Available() {
		return nil, false
	}
	o.taken = true
	return o.conn, true
}

// Close releases the connection if it is still owned here. It is idempotent and
// does nothing after a transfer.
func (o *ownedConn) Close() error {
	if o.conn == nil || o.taken || o.closed {
		return nil
	}
	o.closed = true
	return o.conn.Close()
}

// Session is one PostgreSQL connection whose transport encryption is settled.
//
// It is what SSL negotiation produces and what Startup consumes: the same socket
// the TCP probe measured, now either wrapped in TLS or known to be in the clear,
// together with the facts a later step needs about it.
//
// # Why it carries a channel and the node that proves it
//
// Phase 4.4 must decide whether a credential may cross this connection, and
// ADR 0029 requires that decision to read a fact travelling *with* the socket
// rather than one looked up in the evidence graph. Both halves are set here, in
// one statement, at the moment the connection's encryption is settled, so a
// Session whose channel describes a different socket cannot be constructed from
// outside this package.
//
// # A Session may be dead, and that is a state rather than an error
//
// When the plan required TLS and the server declined it, or a handshake failed,
// there is no usable connection but there is still a graph to write. Such a
// Session reports Available() == false and carries the identifier of the node
// that stopped it, so the next step can record a truthful SKIPPED node instead
// of the caller having to remember why.
//
// A Session is not safe for concurrent use.
type Session struct {
	endpoint string
	address  netip.AddrPort

	// evidenceID is the deepest node recorded for this connection: the TLS node
	// when a handshake ran, otherwise the SSL-negotiation node. A later
	// protocol step parents its own evidence to it.
	evidenceID domain.EvidenceID

	channel security.Channel

	// channelEvidence identifies the node that established what the channel is.
	//
	// Unlike a transport plaintext path, this is **always** set: a TLS path
	// names the handshake node, and a plaintext path names the SSL-negotiation
	// node, which positively records that no TLS was attempted here and why.
	// That is the blocker carrier ADR 0030 recorded as missing.
	channelEvidence domain.EvidenceID

	// blocker names the node that made this session unusable, when one did.
	blocker domain.EvidenceID

	ownedConn
}

// Endpoint returns the logical label this connection belongs to.
func (s *Session) Endpoint() string { return s.endpoint }

// Address returns the concrete peer this connection reached.
func (s *Session) Address() netip.AddrPort { return s.address }

// Evidence returns the identifier of the deepest node recorded for this
// connection, which a following protocol step uses as its parent.
func (s *Session) Evidence() domain.EvidenceID { return s.evidenceID }

// Channel reports what this connection proved about the peer at the other end.
//
// The value is copied from the layer entitled to state it: the TLS probe for a
// handshake, and this package for a connection it knows was left in the clear.
// It is never re-derived by inspecting the connection.
func (s *Session) Channel() security.Channel { return s.channel }

// ChannelEvidence returns the identifier of the node that established what this
// connection proved, and whether there is one.
//
// It reports true on every session this package produces, including plaintext
// ones. A caller refusing to write a secret can therefore always point at the
// fact that made the channel insufficient.
func (s *Session) ChannelEvidence() (domain.EvidenceID, bool) {
	return s.channelEvidence, s.channelEvidence != ""
}

// Blocker returns the node that made this session unusable, and whether one did.
func (s *Session) Blocker() (domain.EvidenceID, bool) {
	return s.blocker, s.blocker != ""
}

// StartupResult is a connection whose StartupMessage the server accepted far
// enough to demand authentication.
//
// It is the boundary Phase 4.3 stops at. It owns the same socket the whole
// negotiation ran over, carries the channel facts forward unchanged, and reports
// what the server asked for — without answering it.
//
// A StartupResult is not safe for concurrent use.
type StartupResult struct {
	endpoint string
	address  netip.AddrPort

	evidenceID      domain.EvidenceID
	channel         security.Channel
	channelEvidence domain.EvidenceID

	authMethod string
	mechanisms []string

	ownedConn
}

// Endpoint returns the logical label this connection belongs to.
func (r *StartupResult) Endpoint() string { return r.endpoint }

// Address returns the concrete peer this connection reached.
func (r *StartupResult) Address() netip.AddrPort { return r.address }

// Evidence returns the identifier of the startup node, which the authentication
// step will parent its evidence to.
func (r *StartupResult) Evidence() domain.EvidenceID { return r.evidenceID }

// Channel reports what this connection proved, carried forward unchanged.
func (r *StartupResult) Channel() security.Channel { return r.channel }

// ChannelEvidence returns the node that established the channel.
func (r *StartupResult) ChannelEvidence() (domain.EvidenceID, bool) {
	return r.channelEvidence, r.channelEvidence != ""
}

// AuthMethod returns the normalized name of the authentication the server
// demanded: "ok", "cleartext", "md5", "sasl", "gss", "sspi", "kerberos", or
// "unknown" for a code this repository does not recognize.
//
// It is a string rather than a wire type so that no protocol value crosses the
// adapter boundary, which is the same choice kafka.HandshakeSession makes for a
// SASL mechanism.
func (r *StartupResult) AuthMethod() string { return r.authMethod }

// SASLMechanisms returns a copy of the mechanisms the server advertised, in its
// stated preference order, or nil when the demanded method was not SASL.
//
// The list is channel-dependent on a real server — SCRAM-SHA-256-PLUS is offered
// only over TLS — so it says something about this connection as well as about
// the server.
func (r *StartupResult) SASLMechanisms() []string {
	if len(r.mechanisms) == 0 {
		return nil
	}
	out := make([]string, len(r.mechanisms))
	copy(out, r.mechanisms)
	return out
}

// AuthenticatedSession is a connection whose authentication is settled and whose
// session is not yet established.
//
// It is what Phase 4.4 produces and what the session step will consume: the same
// socket the whole run has used, past the point where a credential mattered and
// short of the point where a session is usable. **`AuthenticationOk` is not
// success** — a missing database, a revoked CONNECT privilege, an exhausted
// connection limit and a server still in recovery all arrive after it and before
// `ReadyForQuery` (ADR 0036 section 5). This type is the name for exactly that
// window.
//
// # Why it is a distinct type
//
// The same argument that made StartupResult distinct from Session, one step
// later, and it is protocol state rather than elegance: a StartupResult's socket
// is waiting for an answer to an authentication demand, and this one's is not.
// Returning a StartupResult from a successful authentication would say
// "authenticate on this again", which is false — a second SASL exchange on an
// authenticated connection is a protocol violation — and it would let a future
// session step be written against a connection that never presented a
// credential. Authenticate takes a *StartupResult and returns this, so the
// mistake does not typecheck.
//
// # What it deliberately does not carry
//
// No credential, no secret, no password, no nonce, no salt, no proof, no
// signature, and no graph. The credential did its work at the wire boundary and
// has no reason to outlive it, and there is no accessor through which any of
// them could be read back. The role is absent too: it is on the startup node
// already, as an identity attribute that redaction can pseudonymize.
//
// # The next byte belongs to the session step
//
// Authentication stopped at AuthenticationOk having read exactly that frame.
// Whatever the server sent in the same burst — ParameterStatus, BackendKeyData,
// ReadyForQuery — is still on this connection, unread.
//
// An AuthenticatedSession is not safe for concurrent use.
type AuthenticatedSession struct {
	endpoint string
	address  netip.AddrPort

	// evidenceID is the deepest node recorded for this connection: the
	// authentication node when one was recorded, otherwise the startup node,
	// which is the case for a server that demanded no authentication at all.
	evidenceID domain.EvidenceID

	channel         security.Channel
	channelEvidence domain.EvidenceID

	ownedConn
}

// newAuthenticatedSession carries the connection's facts forward unchanged.
//
// It copies from the StartupResult rather than taking them as parameters, so no
// call site can pair a connection with a channel that describes a different
// socket. That is the same arrangement transport.Result.add and
// kafka.HandshakeResult.add make, for the same reason (ADR 0029).
func newAuthenticatedSession(
	conn net.Conn, result *StartupResult, evidenceID domain.EvidenceID,
) *AuthenticatedSession {
	return &AuthenticatedSession{
		endpoint:        result.endpoint,
		address:         result.address,
		evidenceID:      evidenceID,
		channel:         result.channel,
		channelEvidence: result.channelEvidence,
		ownedConn:       ownedConn{conn: conn},
	}
}

// Endpoint returns the logical label this connection belongs to.
func (s *AuthenticatedSession) Endpoint() string { return s.endpoint }

// Address returns the concrete peer this connection reached.
func (s *AuthenticatedSession) Address() netip.AddrPort { return s.address }

// Evidence returns the identifier of the deepest node recorded for this
// connection, which the session step will parent its evidence to.
func (s *AuthenticatedSession) Evidence() domain.EvidenceID { return s.evidenceID }

// Channel reports what this connection proved, carried forward unchanged.
func (s *AuthenticatedSession) Channel() security.Channel { return s.channel }

// ChannelEvidence returns the node that established the channel.
func (s *AuthenticatedSession) ChannelEvidence() (domain.EvidenceID, bool) {
	return s.channelEvidence, s.channelEvidence != ""
}
