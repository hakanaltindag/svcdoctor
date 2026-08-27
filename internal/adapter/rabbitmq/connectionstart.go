package rabbitmq

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// ErrInvalidInput means this package was asked for something it cannot do. It
// is a defect in the caller, never a fact about a peer.
var ErrInvalidInput = errors.New("rabbitmq: invalid input")

// MaxVHostBytes is the protocol maximum for a virtual host name.
//
// Re-exported from the wire package so that a composition root can refuse
// oversized operator input before a connection is opened, without importing the
// wire package itself.
const MaxVHostBytes = wire.MaxVHostBytes

// Params bounds one connection's exchanges.
type Params struct {
	// VHost is the virtual host the run will ask for. It is carried from the
	// start because Connection.Close normalization renders its candidates from
	// svcdoctor's own inputs rather than parsing peer text (ADR 0069 §3).
	VHost string
	// VHostDefaulted reports that the operator named none and `/` was used.
	VHostDefaulted bool
	// Username is the identity the credential belongs to, or empty.
	Username string
	// ExchangeTimeout bounds each individual exchange.
	ExchangeTimeout time.Duration
}

// Session is one connection that received Connection.Start and can be continued.
//
// It owns a live socket. Close releases it, and every path out of this package
// either closes a session or hands its ownership on (ADR 0021).
type Session struct {
	endpoint string
	address  netip.AddrPort
	channel  security.Channel

	evidenceID domain.EvidenceID
	start      wire.ServerStart
	params     Params

	// authEvidence identifies the authentication node once one exists. It is the
	// parent of the open node, because authentication is what made the open
	// possible.
	authEvidence  domain.EvidenceID
	authenticated bool

	conn net.Conn
	rw   *wire.Conn
}

// Endpoint is the logical endpoint this connection belongs to.
func (s *Session) Endpoint() string { return s.endpoint }

// Address is the concrete peer the connection reached.
func (s *Session) Address() netip.AddrPort { return s.address }

// Channel is what the transport chain proved about this connection.
func (s *Session) Channel() security.Channel { return s.channel }

// AuthRequired reports whether the endpoint demands credential-based
// authentication before it will do anything.
//
// **It is always true, and the constant is the adapter's answer rather than the
// composition root's assumption.** AMQP 0-9-1 has no credential-free capability
// exchange: every endpoint sends Connection.Start and then waits for a
// Connection.Start-Ok carrying a SASL response, so there is no observable state
// in which one does not demand authentication.
//
// That is a real difference from Redis, where an endpoint either refuses the
// credential-free capability command with NOAUTH or does not, and the adapter
// reports which. Here the protocol answers the question in advance — but the
// answer still belongs to the package that knows the protocol, so that a
// composition root cannot invent a partition ADR 0041 §8.1 requires evidence for.
func (s *Session) AuthRequired() bool { return true }

// Authenticated reports that the endpoint answered Connection.Tune.
//
// It never means the credential is correct in any wider sense: it means this
// endpoint accepted this credential at this instant (ADR 0068 §4).
func (s *Session) Authenticated() bool { return s.authenticated }

// Close releases the socket. Safe to call more than once.
func (s *Session) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// Result carries the sessions Start established.
type Result struct {
	sessions []*Session
}

// Sessions returns the connections that received Connection.Start.
func (r *Result) Sessions() []*Session {
	if r == nil {
		return nil
	}
	return r.sessions
}

// Start asks every completed transport path who it is.
//
// One node per path. A path that answers becomes a Session; a path that does not
// is recorded and its connection closed, because a connection that never spoke
// AMQP cannot be continued.
func Start(
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
			// Stop starting new work. A path not reached is simply not measured;
			// a node for one would claim an observation nobody made.
			return out, nil
		}
		session, err := startOnPath(ctx, builder, path, params)
		if err != nil {
			return nil, err
		}
		if session != nil {
			out.sessions = append(out.sessions, session)
		}
	}
	return out, nil
}

func startOnPath(
	ctx context.Context,
	builder *domain.GraphBuilder,
	path *transport.Continuation,
	params Params,
) (*Session, error) {
	conn, ok := path.TakeConn()
	if !ok {
		return nil, nil
	}

	rw := wire.NewConn(conn, params.VHost, params.Username)
	startedAt := time.Now()
	start, err := rw.Start(ctx, params.ExchangeTimeout)
	elapsed := time.Since(startedAt)

	obs := startObservation{
		endpoint:  path.Endpoint(),
		address:   path.Address(),
		start:     start,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  elapsed,
	}

	evidence, buildErr := obs.evidence()
	if buildErr != nil {
		_ = conn.Close()
		return nil, buildErr
	}
	if addErr := builder.AddEvidence(evidence); addErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("recording %s evidence: %w",
			servicerabbitmq.StepConnectionStart, addErr)
	}
	if addErr := builder.AddParent(evidence.ID(), path.Evidence()); addErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("linking %s to its transport node: %w",
			servicerabbitmq.StepConnectionStart, addErr)
	}

	if err != nil {
		_ = conn.Close()
		return nil, nil
	}

	return &Session{
		endpoint:   path.Endpoint(),
		address:    path.Address(),
		channel:    path.Channel(),
		evidenceID: evidence.ID(),
		start:      start,
		params:     params,
		conn:       conn,
		rw:         rw,
	}, nil
}

type startObservation struct {
	endpoint  string
	address   netip.AddrPort
	start     wire.ServerStart
	err       error
	ctxErr    error
	startedAt time.Time
	duration  time.Duration
}

func (o startObservation) evidence() (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(
		net.JoinHostPort(o.address.Addr().String(), strconv.Itoa(int(o.address.Port()))))
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			servicerabbitmq.StepConnectionStart, o.endpoint, o.address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerProtocol,
		Step:         servicerabbitmq.StepConnectionStart,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Elapsed:      domain.Measured(o.duration),
	})
}

// classify maps one exchange to a state and a class.
//
// **A returned protocol header is a refusal, not an instruction.** RabbitMQ
// answers unrecognized input with eight bytes of its own — and its default
// fallback is the AMQP 1.0 SASL header even for input that is not AMQP at all,
// so reading it as "the peer prefers 1.0" would invent an identity. It reaches
// PROTOCOL_UNSUPPORTED_VERSION and nothing more is claimed.
func (o startObservation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		return domain.StatePass, domain.FailureNone
	}

	switch {
	case errors.Is(o.err, wire.ErrInvalidInput):
		return domain.StateUnknown, domain.FailureExecRequiredInputMissing
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded),
		errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	case errors.Is(o.err, wire.ErrNotAMQP091):
		return domain.StateFail, domain.FailureProtocolUnsupportedVersion
	case errors.Is(o.err, wire.ErrPeerClosed):
		return domain.StateFail, domain.FailureProtocolPeerClosed
	case errors.Is(o.err, wire.ErrMalformedFrame):
		return domain.StateFail, domain.FailureProtocolMalformedResponse
	case errors.Is(o.err, wire.ErrUnexpectedFrame):
		return domain.StateFail, domain.FailureProtocolUnexpectedResponse
	case isTimeout(o.err):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	default:
		// Not malformed. The decoder's own sentinels are handled above, so
		// anything here came from the connection rather than from framing: a TLS
		// alert, a reset, a refused read.
		return domain.StateFail, domain.FailureProtocolPeerClosed
	}
}

func (o startObservation) attributes() map[domain.AttributeKey]domain.AttrValue {
	if o.err != nil {
		return nil
	}

	attrs := map[domain.AttributeKey]domain.AttrValue{
		servicerabbitmq.AttrAMQPVersion: domain.StringAttr(
			strconv.Itoa(int(o.start.VersionMajor)) + "-" + strconv.Itoa(int(o.start.VersionMinor))),
		servicerabbitmq.AttrMechanismsOffered: domain.StringAttr(o.start.Mechanisms),
		servicerabbitmq.AttrAnonymousOffered:  domain.BoolAttr(o.start.AnonymousOffered),
	}
	// Absence is a real observation: LavinMQ sends no cluster_name at all, and a
	// missing key says so rather than manufacturing an empty one.
	if o.start.Product != "" {
		attrs[servicerabbitmq.AttrProduct] = domain.StringAttr(o.start.Product)
	}
	if o.start.Version != "" {
		attrs[servicerabbitmq.AttrVersion] = domain.StringAttr(o.start.Version)
	}
	if o.start.Platform != "" {
		attrs[servicerabbitmq.AttrPlatform] = domain.StringAttr(o.start.Platform)
	}
	if o.start.ClusterName != "" {
		// Identity-classed: RabbitMQ defaults it to `rabbit@<hostname>`.
		attrs[servicerabbitmq.AttrClusterName] = domain.IdentityAttr(o.start.ClusterName)
	}
	return attrs
}

// isTimeout reports a net timeout that did not arrive as a context error.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
