package kafka

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
)

// StepSASLHandshake names the operation this step performs.
//
// It is exported for the same reason StepAPIVersions is: the string appears in
// every report and will be matched by automation.
const StepSASLHandshake domain.Step = "kafka.sasl_handshake"

// The attributes the handshake records. They live here for the reason given on
// the ApiVersions keys, and they will move with those when the first Kafka
// diagnosis rule needs them.
const (
	// AttrSASLRequestedMechanism is the mechanism svcdoctor asked about.
	//
	// It is half of what the answer means: "not offered" is only interpretable
	// next to what was requested. A mechanism name is a protocol fact, not a
	// secret and not an identity — it names an algorithm, and every value it can
	// take is drawn from a public registry.
	AttrSASLRequestedMechanism domain.AttributeKey = "kafka.sasl.requested_mechanism"

	// AttrSASLOfferedMechanisms lists what the broker said it offers, sorted.
	//
	// Sorted, because a report is byte-stable for the same facts and the broker's
	// order is its own configuration's iteration order rather than a preference.
	// Not deduplicated: a repeated entry is something the broker sent, and
	// collapsing it would hide a misconfiguration behind a tidier list.
	AttrSASLOfferedMechanisms domain.AttributeKey = "kafka.sasl.offered_mechanisms"
)

// SASLParams carries what the handshake needs beyond the sessions.
type SASLParams struct {
	// Mechanism is the SASL mechanism to ask the broker about, such as "PLAIN"
	// or "SCRAM-SHA-512". Required.
	//
	// It is caller-supplied because the protocol has no "list your mechanisms"
	// request: a client proposes one and the broker's answer carries the list.
	// svcdoctor therefore has to name a mechanism, and it asks about the one the
	// caller cares about rather than inventing a value nobody uses. Sending a
	// deliberately bogus name would harvest the same list, and was rejected: it
	// puts a lie on the wire and in the broker's logs to save the caller a
	// parameter (ADR 0026).
	//
	// A mechanism name is a protocol parameter, like a TLS server name. It is
	// not a credential, and naming one sends nothing secret.
	Mechanism string

	// ExchangeTimeout optionally bounds each exchange, derived from the caller's
	// context. Zero means only the caller's context bounds the work.
	ExchangeTimeout time.Duration
}

// validate rejects input the handshake cannot turn into a meaningful exchange.
func (p SASLParams) validate() error {
	switch {
	case p.Mechanism == "":
		return fmt.Errorf("%w: sasl mechanism must not be empty", ErrInvalidInput)
	case p.ExchangeTimeout < 0:
		return fmt.Errorf(
			"%w: exchange timeout %s must not be negative", ErrInvalidInput, p.ExchangeTimeout)
	}
	return nil
}

// SASLHandshake asks every session's broker whether it offers a mechanism.
//
// Evidence goes into builder, one L5 node per session, parented to the
// ApiVersions node of the same path. The returned HandshakeResult owns the
// connection of every path whose broker accepted the mechanism.
//
// # It sends no credentials
//
// A SaslHandshake request carries a mechanism name and nothing else. This step
// therefore discovers what a listener offers without presenting any identity or
// secret, which is what makes it safe to run on every path. Authentication is a
// separate step, with a separate decision about which paths may receive
// credentials, and it does not exist yet (ADR 0026).
//
// # Ownership
//
// The connection of each session is taken here, so afterwards the Result no
// longer holds it. An accepted handshake keeps its connection for the
// authentication that must continue on the same socket; every other outcome
// closes it, because an accepted mechanism is the only outcome the protocol
// gives a next message for.
//
// # Errors
//
// An error means the step could not run: unusable input, or an invariant failure
// such as a graph that rejected a node. Every protocol outcome is evidence.
func SASLHandshake(
	ctx context.Context,
	builder *domain.GraphBuilder,
	sessions []*Session,
	params SASLParams,
) (*HandshakeResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	result := &HandshakeResult{}
	completed := false
	defer func() {
		if !completed {
			_ = result.Close()
		}
	}()

	for _, session := range sessions {
		if session == nil {
			continue
		}
		if err := handshake(ctx, builder, session, params, result); err != nil {
			return nil, err
		}
	}

	completed = true
	return result, nil
}

// handshake runs one SaslHandshake exchange over one session.
//
// A session whose connection is no longer available is skipped without evidence,
// for the reason the ApiVersions step gives: there is nothing to say about an
// exchange there was never a means to attempt, and a node for it would be a
// synthetic fact.
func handshake(
	ctx context.Context,
	builder *domain.GraphBuilder,
	session *Session,
	params SASLParams,
	result *HandshakeResult,
) error {
	conn, ok := session.TakeConn()
	if !ok {
		return nil
	}

	observed := observeHandshake(ctx, conn, params)

	evidence, err := observed.evidence(session, params.Mechanism)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if err := record(builder, evidence, session.Evidence()); err != nil {
		_ = conn.Close()
		return err
	}

	// Only an accepted mechanism leaves a socket the protocol defines a next
	// message for. This is not "FAIL closes the connection": the ApiVersions step
	// keeps a connection whose broker answered with an error code, because any
	// request may still follow it. After a handshake the broker will accept only
	// that mechanism's continuation, so a rejected or unreadable handshake leaves
	// a connection with nothing that may be sent on it (ADR 0026).
	if !observed.accepted() {
		_ = conn.Close()
		return nil
	}

	result.add(conn, session, params.Mechanism, evidence.ID())
	return nil
}

// handshakeObservation is the producer-local record of one handshake exchange.
type handshakeObservation struct {
	response wire.SASLHandshake

	// err is what the exchange returned, and ctxErr is what the caller's context
	// reported at the same moment. Both are needed for the reason every probe
	// needs them: a deadline that belongs to svcdoctor must never be reported as
	// a claim about the peer.
	err    error
	ctxErr error

	startedAt time.Time
	duration  time.Duration
}

// observeHandshake performs the exchange and records what happened.
//
// This is the only function here that performs I/O or reads a clock; everything
// after it is a pure transformation.
func observeHandshake(ctx context.Context, conn net.Conn, params SASLParams) handshakeObservation {
	exchangeCtx := ctx
	if params.ExchangeTimeout > 0 {
		var cancel context.CancelFunc
		exchangeCtx, cancel = context.WithTimeout(ctx, params.ExchangeTimeout)
		defer cancel()
	}

	startedAt := time.Now()
	response, err := wire.ExchangeSASLHandshake(exchangeCtx, conn, params.Mechanism)
	duration := time.Since(startedAt)

	return handshakeObservation{
		response:  response,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  duration,
	}
}

// accepted reports whether the broker agreed to the mechanism.
func (o handshakeObservation) accepted() bool {
	return o.err == nil && o.response.ErrorCode == 0
}

// evidence normalizes the observation into the canonical model.
//
// The subject is the concrete peer, matching the transport and ApiVersions nodes
// for the same path, so a reader can follow one address from L1 to L5.
func (o handshakeObservation) evidence(
	session *Session, mechanism string,
) (domain.Evidence, error) {
	address := session.Address()

	subject, err := domain.NewEndpointSubject(address.String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			StepSASLHandshake, session.Endpoint(), address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         StepSASLHandshake,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(mechanism),
		StartedAt:    o.startedAt,
		Duration:     o.duration,
	})
}

// classify decides what the observation is allowed to claim.
//
// The order of the checks is the contract every producer here follows: a
// completed exchange is a fact, then the caller's context, then what the wire
// boundary observed.
func (o handshakeObservation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		if o.response.ErrorCode != 0 {
			return domain.StateFail, handshakeFailure(o.response.ErrorCode)
		}
		return domain.StatePass, domain.FailureNone
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
	case errors.Is(o.err, wire.ErrNotKafka):
		return domain.StateFail, domain.FailureProtocolUnexpectedResponse
	case errors.Is(o.err, wire.ErrMalformedResponse):
		return domain.StateFail, domain.FailureProtocolMalformedResponse
	}

	if isTimeout(o.err) {
		// A deadline nothing identified as the network's is svcdoctor's own.
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}
	return domain.StateFail, domain.FailureProtocolUnexpectedResponse
}

// handshakeFailure normalizes a broker error code from a handshake response.
//
// One code more than the shared mapping is translated here, and only because
// this response proves the generic fact by itself: UNSUPPORTED_SASL_MECHANISM
// means the broker does not offer the mechanism that was named, which is exactly
// what AUTH_MECHANISM_NOT_OFFERED says. The list of what it does offer arrives
// in the same response and is recorded beside it.
//
// The class is deliberately the peer-side one. AUTH_MECHANISM_UNSUPPORTED means
// svcdoctor cannot perform a mechanism, which is a gap in this tool; nothing
// here has tried to perform anything. Conflating the two would blame a broker
// for svcdoctor's limits, or the reverse.
//
// ILLEGAL_SASL_STATE is deliberately not mapped. It means a handshake was not
// expected at this point in the connection, which one listener produces because
// it does not do SASL at all and another because a handshake already happened.
// Two causes behind one code prove no single generic fact, so the code stays an
// attribute and the class stays conservative (ADR 0025 section 6, ADR 0026).
func handshakeFailure(code int16) domain.FailureClass {
	if code == errorCodeUnsupportedSASLMechanism {
		return domain.FailureAuthMechanismNotOffered
	}
	return protocolFailure(code)
}

// attributes records the facts the exchange yielded.
//
// Nothing here can carry a credential: the request held a mechanism name, and
// the response holds an error code and mechanism names. The identity and secret
// a later phase will send have no path into this node, because no field of this
// step ever holds them.
func (o handshakeObservation) attributes(mechanism string) map[domain.AttributeKey]domain.AttrValue {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		AttrSASLRequestedMechanism: domain.StringAttr(mechanism),
		AttrRequestAPIVersion:      domain.IntAttr(int64(wire.SASLHandshakeVersion())),
	}
	if o.err == nil {
		attributes[AttrErrorCode] = domain.IntAttr(int64(o.response.ErrorCode))
	}
	if offered := canonicalMechanisms(o.response.Mechanisms); len(offered) > 0 {
		attributes[AttrSASLOfferedMechanisms] = domain.StringListAttr(offered...)
	}
	return attributes
}

// canonicalMechanisms sorts what the broker offered, leaving duplicates alone.
//
// Sorting makes a report byte-stable for the same facts. It destroys nothing:
// Kafka's enabled mechanisms are a set, so the order they arrive in expresses no
// preference and is not guaranteed to repeat between runs.
func canonicalMechanisms(mechanisms []string) []string {
	if len(mechanisms) == 0 {
		return nil
	}
	sorted := slices.Clone(mechanisms)
	slices.Sort(sorted)
	return sorted
}
