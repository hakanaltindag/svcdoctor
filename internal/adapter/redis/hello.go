package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/redis/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// ErrInvalidInput reports that this package was called with something it cannot
// use. It is never a fact about the endpoint.
var ErrInvalidInput = errors.New("invalid redis adapter input")

// Params bounds one Redis exchange.
type Params struct {
	// ExchangeTimeout optionally bounds each individual command. The caller's
	// context bounds the run regardless, and whichever is earlier wins.
	ExchangeTimeout time.Duration
}

// Session is one connection that completed a HELLO exchange and can be
// continued.
//
// It owns a live socket. Close releases it, and every path out of this package
// either closes a session or hands its ownership on, exactly as ADR 0021
// requires.
type Session struct {
	endpoint string
	address  netip.AddrPort
	channel  security.Channel

	channelEvidence    domain.EvidenceID
	hasChannelEvidence bool

	evidenceID domain.EvidenceID
	hello      wire.Hello

	// authEvidence identifies the authentication node, once one exists. It is
	// the parent of the post-authentication HELLO, because the authentication is
	// what made that exchange possible.
	authEvidence domain.EvidenceID

	// authenticated reports that the endpoint accepted the credential. It never
	// means the credential is correct: a `nopass` user accepts every password
	// (redis/src/acl.c:1485).
	authenticated bool

	// authOutcome records which of the four authentication paths this session
	// took, so PING can name its own prerequisite without re-reading the graph.
	authOutcome authOutcome

	conn net.Conn
	rw   *wire.Conn
}

// Authenticated reports that the endpoint accepted the presented credential.
func (s *Session) Authenticated() bool { return s.authenticated }

// Endpoint is the logical endpoint this connection belongs to.
func (s *Session) Endpoint() string { return s.endpoint }

// Address is the concrete peer the connection reached.
func (s *Session) Address() netip.AddrPort { return s.address }

// Channel is what the transport chain proved about this connection.
func (s *Session) Channel() security.Channel { return s.channel }

// ChannelEvidence identifies the node that established the channel, when one
// exists. A plaintext path has no TLS node to point at.
func (s *Session) ChannelEvidence() (domain.EvidenceID, bool) {
	return s.channelEvidence, s.hasChannelEvidence
}

// Evidence identifies the HELLO node this session was established by.
func (s *Session) Evidence() domain.EvidenceID { return s.evidenceID }

// Hello is the normalized capability answer.
func (s *Session) Hello() wire.Hello { return s.hello }

// AuthRequired reports that the endpoint demanded authentication.
//
// It comes from the endpoint's own refusal of a credential-free command, which
// is why the composition root can use it to choose a path before any secret has
// been assembled.
func (s *Session) AuthRequired() bool { return s.hello.AuthRequired() }

// IsSentinel reports that the endpoint identified itself as a Redis Sentinel.
//
// A Sentinel answers PING, AUTH and HELLO — every command in the allowlist
// carries CMD_SENTINEL (redis/src/commands/*.json) and `server.c:3501` hides
// only the ones that do not. So without this guard a Sentinel completes the
// whole journey and reports as a healthy data endpoint while holding no keys.
// ADR 0065 section 7.
func (s *Session) IsSentinel() bool { return s.hello.Mode == wire.ModeSentinel }

// Close releases the connection.
func (s *Session) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// Result is what a HELLO pass over the transport paths produced.
type Result struct {
	sessions []*Session
}

// Sessions returns the connections that completed HELLO, in the order the paths
// arrived.
func (r *Result) Sessions() []*Session {
	if r == nil {
		return nil
	}
	return r.sessions
}

// Close releases every session this result still owns.
func (r *Result) Close() error {
	if r == nil {
		return nil
	}
	var first error
	for _, s := range r.sessions {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Run performs the credential-free HELLO on every completed transport path.
//
// A path whose HELLO did not produce a usable connection is recorded and closed;
// it does not appear in Sessions. A path whose HELLO was *refused* — NOAUTH,
// or a generic ERR from an endpoint that does not implement the command — still
// yields a session, because the connection is alive and the journey continues on
// it. Refusal is an answer.
func Run(
	ctx context.Context,
	builder *domain.GraphBuilder,
	paths []*transport.Continuation,
	params Params,
) (*Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: builder must not be nil", ErrInvalidInput)
	}

	out := &Result{}
	for _, path := range paths {
		if ctx.Err() != nil {
			// Stop starting new work. Paths not reached are simply not
			// measured: a node for one would claim an observation nobody made.
			return out, nil
		}
		session, err := helloOnPath(ctx, builder, path, params)
		if err != nil {
			return nil, err
		}
		if session != nil {
			out.sessions = append(out.sessions, session)
		}
	}
	return out, nil
}

// helloOnPath takes ownership of one connection and asks it who it is.
func helloOnPath(
	ctx context.Context,
	builder *domain.GraphBuilder,
	path *transport.Continuation,
	params Params,
) (*Session, error) {
	conn, ok := path.TakeConn()
	if !ok {
		// The chain handed back a path with no connection to continue. Nothing
		// was measured here and nothing is claimed.
		return nil, nil
	}

	rw := wire.NewConn(conn)
	startedAt := time.Now()
	hello, err := rw.SendHello(ctx, params.ExchangeTimeout)
	elapsed := time.Since(startedAt)

	obs := helloObservation{
		endpoint:  path.Endpoint(),
		address:   path.Address(),
		hello:     hello,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  elapsed,
	}

	evidence, buildErr := obs.evidence(probe.SweepScope{})
	if buildErr != nil {
		_ = conn.Close()
		return nil, buildErr
	}
	if addErr := builder.AddEvidence(evidence); addErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("recording %s evidence: %w", serviceredis.StepHello, addErr)
	}
	if addErr := builder.AddParent(evidence.ID(), path.Evidence()); addErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("linking %s to its transport node: %w", serviceredis.StepHello, addErr)
	}

	if err != nil {
		// The exchange did not produce an answer. The evidence is recorded; the
		// connection is not usable for anything further.
		_ = conn.Close()
		return nil, nil
	}

	channelEvidence, hasChannelEvidence := path.ChannelEvidence()
	return &Session{
		endpoint:           path.Endpoint(),
		address:            path.Address(),
		channel:            path.Channel(),
		channelEvidence:    channelEvidence,
		hasChannelEvidence: hasChannelEvidence,
		evidenceID:         evidence.ID(),
		hello:              hello,
		conn:               conn,
		rw:                 rw,
	}, nil
}

// identifyScope names the second HELLO's execution.
//
// ADR 0032 exists for exactly this: one run measuring the same endpoint and
// address twice at the same step needs the two identifiers to differ, and the
// scope is where that difference lives. Evidence is immutable (ADR 0003), so the
// first node is never amended.
var identifyScope = mustScope("post-auth")

func mustScope(label string) probe.SweepScope {
	scope, err := probe.NewSweepScope(label)
	if err != nil {
		panic("redis: invalid sweep scope literal: " + err.Error())
	}
	return scope
}

// Identify asks an authenticated connection who it is.
//
// # It is called only when the first HELLO was refused with NOAUTH
//
// That is not an optimization. When the first HELLO answered, the identity is
// already recorded and a second exchange would produce a duplicate node claiming
// the same thing twice. When it was refused, the identity does not exist yet and
// no other allowed command can supply it.
//
// # It carries no credential
//
// Same package constant, same zero-argument frame. The connection is already
// authenticated; the command is not what authenticates it.
func Identify(
	ctx context.Context, builder *domain.GraphBuilder, session *Session, params Params,
) error {
	if session == nil || session.rw == nil {
		return fmt.Errorf("%w: Identify needs an open session", ErrInvalidInput)
	}

	startedAt := time.Now()
	hello, err := session.rw.SendHello(ctx, params.ExchangeTimeout)
	elapsed := time.Since(startedAt)

	obs := helloObservation{
		endpoint:  session.endpoint,
		address:   session.address,
		hello:     hello,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  elapsed,
	}

	evidence, buildErr := obs.evidence(identifyScope)
	if buildErr != nil {
		return buildErr
	}
	if addErr := builder.AddEvidence(evidence); addErr != nil {
		return fmt.Errorf("recording %s evidence: %w", serviceredis.StepHello, addErr)
	}
	// The authentication is what made this exchange possible, so it is the
	// parent. Orchestration declares the cause and the producer records the edge.
	if addErr := builder.AddParent(evidence.ID(), session.authEvidence); addErr != nil {
		return fmt.Errorf("linking the post-authentication %s: %w", serviceredis.StepHello, addErr)
	}

	if err == nil {
		session.hello = hello
	}
	return nil
}

// helloObservation is what one HELLO exchange yielded, before it is evidence.
type helloObservation struct {
	endpoint  string
	address   netip.AddrPort
	hello     wire.Hello
	err       error
	ctxErr    error
	startedAt time.Time
	duration  time.Duration
}

func (o helloObservation) evidence(scope probe.SweepScope) (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(
		net.JoinHostPort(o.address.Addr().String(), fmt.Sprint(o.address.Port())))
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.ScopedEvidenceID(
			scope, serviceredis.StepHello, o.endpoint, o.address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerProtocol,
		Step:         serviceredis.StepHello,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Elapsed:      domain.Measured(o.duration),
	})
}

// classify decides what one HELLO exchange is allowed to claim.
//
// The order is the contract every producer in this repository follows: a
// completed exchange first, then the caller's own limits, then what the wire
// boundary observed.
func (o helloObservation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		switch {
		case o.hello.Answered():
			return domain.StatePass, domain.FailureNone
		case o.hello.AuthRequired():
			// The endpoint answered, and the answer is "not until you
			// authenticate". That is a real capability fact and not a failure of
			// this step — but it is not a pass either, because the identity this
			// step exists to collect was not collected.
			return domain.StateUnknown, domain.FailureNone
		case o.hello.Unsupported():
			// A server before 6.0, or a proxy. svcdoctor's own journey continues;
			// what it cannot do is claim a mode or an identity.
			return domain.StateUnknown, domain.FailureProtocolUnsupportedCapability
		case o.hello.Prefix == wire.PrefixDENIED:
			// Protected mode. The endpoint refuses and closes.
			return domain.StateFail, domain.FailureProtocolPeerClosed
		default:
			// Any other named condition, including an unrecognized prefix. The
			// endpoint refused and svcdoctor records what it named without
			// inferring why.
			return domain.StateUnknown, domain.FailureProtocolUnexpectedResponse
		}
	}

	switch {
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded), errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}

	switch {
	case errors.Is(o.err, wire.ErrPeerClosed):
		return domain.StateFail, domain.FailureProtocolPeerClosed
	case errors.Is(o.err, wire.ErrReplyTooLarge):
		// svcdoctor's own limit. The peer's reply was structurally legal, so
		// this must not read as a defect in the endpoint (ADR 0061 section 28).
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	case errors.Is(o.err, wire.ErrMalformedReply):
		return domain.StateFail, domain.FailureProtocolMalformedResponse
	case errors.Is(o.err, wire.ErrUnexpectedReply):
		return domain.StateFail, domain.FailureProtocolUnexpectedResponse
	case isTimeout(o.err):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	default:
		// **Not malformed.** ErrMalformedReply is returned only by svcdoctor's own
		// decoder, so anything reaching here came from the connection rather than
		// from framing: a TLS alert, a reset, a refused read.
		//
		// Measured in Phase 7.5 against a Redis 8.2.1 server running the default
		// `tls-auth-clients yes`. svcdoctor presents no client certificate, and
		// under TLS 1.3 the server's objection arrives as an alert on the first
		// read rather than during the handshake. Classifying that as malformed
		// framing accused the endpoint of a protocol defect for correctly
		// enforcing its own configuration — the truthfulness defect ADR 0061
		// section 28 corrected for SCRAM, in a second place.
		return domain.StateFail, domain.FailureProtocolPeerClosed
	}
}

// attributes records the facts this exchange yielded.
//
// Presence is decided per attribute rather than per outcome: a field the
// endpoint did not send is absent rather than empty, so a reader can tell "the
// endpoint said standalone" from "svcdoctor never found out".
func (o helloObservation) attributes() map[domain.AttributeKey]domain.AttrValue {
	attrs := map[domain.AttributeKey]domain.AttrValue{}

	if o.hello.Server != "" {
		attrs[serviceredis.AttrServer] = domain.StringAttr(o.hello.Server)
	}
	if o.hello.Version != "" {
		attrs[serviceredis.AttrServerVersion] = domain.StringAttr(o.hello.Version)
	}
	if o.hello.Proto != 0 {
		attrs[serviceredis.AttrProto] = domain.IntAttr(o.hello.Proto)
	}
	if o.hello.Mode != wire.ModeUnknown {
		attrs[serviceredis.AttrMode] = domain.StringAttr(o.hello.Mode)
	}
	if o.hello.Role != wire.RoleUnknown {
		attrs[serviceredis.AttrRole] = domain.StringAttr(o.hello.Role)
	}
	if o.err == nil && o.hello.Prefix != wire.PrefixNone {
		attrs[serviceredis.AttrErrorPrefix] = domain.StringAttr(string(o.hello.Prefix))
	}
	// Recorded only when the exchange produced an answer, so the key never
	// claims to know whether authentication is required on a step that failed.
	if o.err == nil && (o.hello.Answered() || o.hello.AuthRequired()) {
		attrs[serviceredis.AttrAuthRequired] = domain.BoolAttr(o.hello.AuthRequired())
	}

	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// isTimeout reports a net.Error deadline, which is how a per-step budget
// surfaces from a socket read.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
