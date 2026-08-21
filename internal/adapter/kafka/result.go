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

	endpoint        string
	address         netip.AddrPort
	evidenceID      domain.EvidenceID
	channel         security.Channel
	channelEvidence domain.EvidenceID
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

// ChannelEvidence returns the node that established this session's channel, and
// whether there is one. It is carried through unchanged from the transport path,
// like the channel it describes.
func (s *Session) ChannelEvidence() (domain.EvidenceID, bool) {
	return s.channelEvidence, s.channelEvidence != ""
}

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
	channelEvidence, _ := path.ChannelEvidence()
	r.sessions = append(r.sessions, &Session{
		ownedConn:       ownedConn{conn: conn},
		endpoint:        path.Endpoint(),
		address:         path.Address(),
		evidenceID:      evidenceID,
		channel:         path.Channel(),
		channelEvidence: channelEvidence,
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

	endpoint        string
	address         netip.AddrPort
	mechanism       string
	evidenceID      domain.EvidenceID
	channel         security.Channel
	channelEvidence domain.EvidenceID
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

// ChannelEvidence returns the node that established this session's channel, and
// whether there is one.
//
// Authentication consults it when the policy refuses to send a credential, so
// that the refusal can point at the fact that caused it rather than assert it.
// It reports false on a plaintext path, where no node states that TLS is absent,
// and a refusal there truthfully carries no blocker. See ADR 0030.
func (s *HandshakeSession) ChannelEvidence() (domain.EvidenceID, bool) {
	return s.channelEvidence, s.channelEvidence != ""
}

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
	channelEvidence, _ := session.ChannelEvidence()
	r.sessions = append(r.sessions, &HandshakeSession{
		ownedConn:       ownedConn{conn: conn},
		endpoint:        session.Endpoint(),
		address:         session.Address(),
		mechanism:       mechanism,
		evidenceID:      evidenceID,
		channel:         session.Channel(),
		channelEvidence: channelEvidence,
	})
}

// AuthenticatedSession is one path whose broker accepted a credential, together
// with the connection the authentication ran over.
//
// It is a third type rather than a reused HandshakeSession, and the reason is
// protocol state rather than taste. A HandshakeSession's socket accepts exactly
// one message: the SaslAuthenticate continuing the mechanism the broker agreed
// to. An authenticated socket accepts every request the broker offers. Returning
// a HandshakeSession from a successful authentication would therefore say
// "authenticate on this again", which is false, and would let a later Metadata
// step be written against a connection that never presented a credential.
//
// This is the first Kafka step whose success produces a connection that is more
// usable than the one it consumed. Every other outcome produces none at all.
//
// It carries no secret and no identity. The credential did its work at the wire
// boundary and has no reason to outlive it; what survives is the fact that the
// broker accepted one, which is in the evidence. See ADR 0030.
type AuthenticatedSession struct {
	ownedConn

	endpoint        string
	address         netip.AddrPort
	mechanism       string
	evidenceID      domain.EvidenceID
	channel         security.Channel
	channelEvidence domain.EvidenceID
}

// Endpoint returns the logical label this path belongs to, carried through from
// the HandshakeSession it continued.
//
// It stays the name the operator asked about, never the address it resolved to,
// because it is the value that authorized the credential in the first place.
func (s *AuthenticatedSession) Endpoint() string { return s.endpoint }

// Address returns the broker this session speaks to.
func (s *AuthenticatedSession) Address() netip.AddrPort { return s.address }

// Channel reports what the connection under this session proved about its peer.
//
// It is necessarily ChannelTLSVerified under the only policy that exists, since
// nothing weaker reaches an authentication attempt. It is carried anyway rather
// than assumed, because a policy that can be chosen is a reopen condition and
// the fact should not have to be reintroduced when it is.
func (s *AuthenticatedSession) Channel() security.Channel { return s.channel }

// ChannelEvidence returns the node that established this session's channel, and
// whether there is one.
func (s *AuthenticatedSession) ChannelEvidence() (domain.EvidenceID, bool) {
	return s.channelEvidence, s.channelEvidence != ""
}

// Mechanism returns the SASL mechanism the authentication used.
//
// It is the one the broker accepted at the handshake, carried through rather
// than supplied again, so the mechanism that authenticated cannot disagree with
// the one that was negotiated.
func (s *AuthenticatedSession) Mechanism() string { return s.mechanism }

// Evidence returns the identifier of the SaslAuthenticate node for this session.
func (s *AuthenticatedSession) Evidence() domain.EvidenceID { return s.evidenceID }

// AuthResult is what one authentication attempt leaves the caller holding.
//
// # Why it exists when authentication is singular
//
// A step that returns at most one session does not obviously need a result type,
// and this one earns its place on two counts. It carries the identifier of the
// node that was recorded, which is the only thing a *refused* attempt produces —
// without it a caller that was refused would receive nothing at all and could not
// name the evidence it just caused. And it keeps `defer result.Close()` the same
// unconditional idiom it is for the two steps below it, so ownership does not
// change shape at the one step that handles a credential.
//
// # What is not here
//
// A session, unless the broker accepted the credential. A rejection, a policy
// refusal, a broken exchange and an expired budget all produce evidence and no
// continuation, because none of them leaves a socket with a defined next
// message. See ADR 0030.
//
// An AuthResult is not safe for concurrent use.
type AuthResult struct {
	evidenceID domain.EvidenceID
	session    *AuthenticatedSession
}

// Evidence returns the identifier of the SaslAuthenticate node this attempt
// recorded. It is present in every outcome, including a refusal.
func (r *AuthResult) Evidence() domain.EvidenceID { return r.evidenceID }

// Authenticated reports whether the broker accepted the credential.
//
// It is a statement about the exchange, and it stays true after the connection
// has been taken or closed — unlike Session, which reports what is still here.
func (r *AuthResult) Authenticated() bool { return r.session != nil }

// Session returns the authenticated session, and whether there is one.
//
// A caller that receives false was not authenticated and holds no connection:
// there is nothing to close and nothing to continue on.
func (r *AuthResult) Session() (*AuthenticatedSession, bool) {
	if r.session == nil {
		return nil, false
	}
	return r.session, true
}

// Close releases the connection the result still owns.
//
// It is idempotent, safe when nothing was authenticated, and does nothing once
// the connection has been taken.
func (r *AuthResult) Close() error {
	if r.session == nil {
		return nil
	}
	return r.session.Close()
}

// authenticated records a successful authentication and takes ownership of its
// connection.
//
// As with the two constructors above, everything describing the path is copied
// from the session being continued rather than passed alongside it, so no call
// site can supply a channel at all and therefore cannot supply a stronger one.
func (r *AuthResult) authenticated(
	conn net.Conn, session *HandshakeSession, evidenceID domain.EvidenceID,
) {
	channelEvidence, _ := session.ChannelEvidence()
	r.session = &AuthenticatedSession{
		ownedConn:       ownedConn{conn: conn},
		endpoint:        session.Endpoint(),
		address:         session.Address(),
		mechanism:       session.Mechanism(),
		evidenceID:      evidenceID,
		channel:         session.Channel(),
		channelEvidence: channelEvidence,
	}
}

// DiscoveredBroker is one broker a Metadata response advertised, normalized.
//
// # Two identities, deliberately not merged
//
// Kafka gives a broker a node identifier and an advertised address, and they are
// different kinds of thing:
//
//	NodeID     the broker identity this Metadata response reported. An integer
//	           the service chose; nothing a client connects to.
//	Endpoint   a network target somebody could connect to. It is configuration,
//	           and configuration is what a diagnostic tool is usually called in
//	           to examine.
//
// Neither is assumed unique or stable. One response cannot prove that a node
// identifier is unique across the cluster or survives a restart, and this
// package deliberately records responses where it is neither.
//
// Collapsing them into one key would erase exactly the facts this phase exists
// to surface. One node identifier at two addresses is a rolling reconfiguration
// or a listener mistake; two node identifiers at one address is a
// misconfiguration that will route clients to the wrong broker. Both stay
// visible, as separate evidence nodes. See ADR 0031.
//
// # An advertisement is not a reachability claim
//
// Nothing here has been probed. This value says the cluster *said* a broker
// exists at an address, and no more. Whether that address resolves, accepts a
// connection or speaks Kafka is a later phase's question, and this phase
// deliberately does not ask it.
type DiscoveredBroker struct {
	nodeID     int32
	host       string
	port       uint16
	usable     bool
	evidenceID domain.EvidenceID
}

// NodeID returns the broker identity this Metadata response reported.
//
// It is never an execution target. A caller that wants somewhere to connect
// wants Endpoint, and the two are separate methods so that using the wrong one
// is a visible mistake rather than a field access.
//
// It carries no uniqueness or stability guarantee: it is what one broker said,
// and two brokers claiming one identifier is a fact this package preserves
// rather than resolves.
func (b DiscoveredBroker) NodeID() int32 { return b.nodeID }

// Endpoint returns the advertised network target as "host:port", and whether the
// advertisement named a usable one.
//
// It reports false when the advertised host was empty or the port was outside
// the range a port can occupy. In that case there is no endpoint string to
// return, because a usable endpoint was never advertised and synthesizing one
// would invent a target the cluster never named. The advertisement is still in
// the graph as a FAIL node carrying what did arrive.
func (b DiscoveredBroker) Endpoint() (string, bool) {
	if !b.usable {
		return "", false
	}
	return joinHostPort(b.host, b.port), true
}

// Host returns the normalized advertised host, which may be empty when the
// advertisement was unusable.
func (b DiscoveredBroker) Host() string { return b.host }

// Port returns the advertised port, which is zero when the advertisement was
// unusable.
func (b DiscoveredBroker) Port() uint16 { return b.port }

// Evidence returns the identifier of the node recording this advertisement.
//
// It is what makes "which Metadata response caused svcdoctor to look at broker
// X?" answerable by walking the graph rather than by parsing an attribute: this
// node's parent is the exact Metadata exchange that carried it.
func (b DiscoveredBroker) Evidence() domain.EvidenceID { return b.evidenceID }

// MetadataResult is what one Metadata exchange leaves the caller holding: the
// topology the cluster described, and the connection it was described over.
//
// # It records, and it probes nothing
//
// Every broker here is an advertisement. This phase does not resolve, dial, or
// speak to any of them, and it sends no credential anywhere. Doing so would drag
// credential-forwarding policy, execution deduplication, recursion bounds and a
// severity decision about unreachable brokers into the phase that was supposed
// to produce their input. See ADR 0031.
//
// A MetadataResult is not safe for concurrent use.
type MetadataResult struct {
	evidenceID domain.EvidenceID
	brokers    []DiscoveredBroker
	session    *AuthenticatedSession
}

// Evidence returns the identifier of the Metadata exchange node. It is present
// in every outcome, including one where the exchange failed.
func (r *MetadataResult) Evidence() domain.EvidenceID { return r.evidenceID }

// Brokers returns every advertisement the response carried, in the order the
// broker sent them, with exact duplicates collapsed.
//
// **Contradictions are not collapsed.** Two entries naming one node identifier
// at two addresses are two brokers here, as are two node identifiers at one
// address. Only a byte-identical repetition of the same advertisement becomes
// one entry, and the exchange node records how many raw entries arrived so that
// even that collapse is visible rather than silent.
//
// The order is the broker's own. It is evidence ordering, not a ranking: nothing
// here selects a broker, and a caller that takes the first is making its own
// choice.
func (r *MetadataResult) Brokers() []DiscoveredBroker {
	if len(r.brokers) == 0 {
		return nil
	}
	out := make([]DiscoveredBroker, len(r.brokers))
	copy(out, r.brokers)
	return out
}

// Session returns the still-authenticated session, and whether there is one.
//
// A completed Metadata exchange leaves the connection exactly as it found it:
// authenticated, and able to carry any request the broker offers. Metadata reads
// the cluster's description and changes no protocol state, which is why this is
// the first Kafka step whose success hands back the same kind of session it
// consumed rather than a stronger one.
func (r *MetadataResult) Session() (*AuthenticatedSession, bool) {
	if r.session == nil {
		return nil, false
	}
	return r.session, true
}

// Close releases the connection the result still owns. It is idempotent, safe
// when the exchange failed, and does nothing once the connection has been taken.
func (r *MetadataResult) Close() error {
	if r.session == nil {
		return nil
	}
	return r.session.Close()
}

// continued records a completed exchange and takes ownership of its connection.
//
// The session is rebuilt from the one being continued rather than assembled from
// parameters, for the reason every constructor in this file gives: a caller
// cannot supply a channel, so it cannot supply a stronger one. The evidence
// identifier stays the authentication node's, because that is still what this
// connection proved — Metadata added a fact about the cluster, not about the
// connection.
func (r *MetadataResult) continued(conn net.Conn, session *AuthenticatedSession) {
	channelEvidence, _ := session.ChannelEvidence()
	r.session = &AuthenticatedSession{
		ownedConn:       ownedConn{conn: conn},
		endpoint:        session.Endpoint(),
		address:         session.Address(),
		mechanism:       session.Mechanism(),
		evidenceID:      session.Evidence(),
		channel:         session.Channel(),
		channelEvidence: channelEvidence,
	}
}
