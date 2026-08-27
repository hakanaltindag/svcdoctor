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
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// OpenParams bounds the terminal exchange.
type OpenParams struct {
	ExchangeTimeout time.Duration
}

// Open asks for the virtual host and records the terminal node.
//
// # What Open-Ok proves, exactly
//
// That the authenticated identity was allowed to open a connection in the
// requested virtual host **at this endpoint, at this instant**. Not that
// configure, write or read permission exists — none was evaluated, because
// RabbitMQ evaluates those at channel operations and svcdoctor opens no channel.
// Not that anything inside the vhost functions. Not that a cluster is healthy.
// ADR 0067 §5.
//
// # No channel follows it
//
// Channel.Open is tautological given Open-Ok: a channel needs no permission,
// touches no resource, and is refused only by a channel_max svcdoctor itself
// guarantees cannot be exceeded. It would add a whole second error class for no
// evidence (ADR 0067 §6).
//
// # The close epilogue cannot change the verdict
//
// Evidence is immutable and Open-Ok was recorded when it arrived (ADR 0003), so
// a failure while closing is an attribute rather than a finding. It is attempted
// because dropping the socket makes RabbitMQ log a warning, and svcdoctor must
// not manufacture warnings in an operator's log.
func Open(
	ctx context.Context, builder *domain.GraphBuilder, session *Session, params OpenParams,
) error {
	if session == nil || session.rw == nil {
		return fmt.Errorf("%w: Open needs an open session", ErrInvalidInput)
	}
	if builder == nil {
		return fmt.Errorf("%w: builder must not be nil", ErrInvalidInput)
	}

	obs := openObservation{
		endpoint:  session.endpoint,
		address:   session.address,
		vhost:     session.params.VHost,
		defaulted: session.params.VHostDefaulted,
		startedAt: time.Now(),
	}

	obs.err = session.rw.Open(ctx, params.ExchangeTimeout)
	obs.ctxErr = ctx.Err()

	if obs.err == nil {
		// Polite teardown. Recorded, never decisive.
		obs.graceful = session.rw.GracefulClose(ctx, params.ExchangeTimeout) == nil
		obs.hasGraceful = true
	} else {
		var refused *wire.RefusedError
		if errors.As(obs.err, &refused) {
			obs.refusal = refused.Refusal
			obs.hasRefusal = true
			// Release the broker's connection process immediately rather than
			// after its timer. It carries nothing.
			_ = session.rw.AckClose(ctx, params.ExchangeTimeout)
		}
	}
	obs.duration = time.Since(obs.startedAt)

	evidence, err := obs.evidence()
	if err != nil {
		return err
	}
	if err := builder.AddEvidence(evidence); err != nil {
		return fmt.Errorf("recording %s evidence: %w",
			servicerabbitmq.StepConnectionOpen, err)
	}

	// Parented to the authentication node, which is what made the open possible.
	// A run that never authenticated parents to the protocol node instead, so
	// the edge always names the step that actually preceded this one.
	parent := session.authEvidence
	if parent == "" {
		parent = session.evidenceID
	}
	if err := builder.AddParent(evidence.ID(), parent); err != nil {
		return fmt.Errorf("linking %s to its parent: %w",
			servicerabbitmq.StepConnectionOpen, err)
	}
	return nil
}

type openObservation struct {
	endpoint    string
	address     netip.AddrPort
	vhost       string
	defaulted   bool
	refusal     wire.Refusal
	hasRefusal  bool
	graceful    bool
	hasGraceful bool
	err         error
	ctxErr      error
	startedAt   time.Time
	duration    time.Duration
}

func (o openObservation) evidence() (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(
		net.JoinHostPort(o.address.Addr().String(), strconv.Itoa(int(o.address.Port()))))
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			servicerabbitmq.StepConnectionOpen, o.endpoint, o.address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         servicerabbitmq.StepConnectionOpen,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Elapsed:      domain.Measured(o.duration),
	})
}

// classify maps the terminal exchange to a state and a class.
//
// The 530 family is where the normalized outcome earns its place: the reply code
// alone covers six semantically different conditions, and svcdoctor's own
// handshake position tells it only that the refusal happened at Open. The
// sentinel — rendered from svcdoctor's own vhost and username and compared for
// byte equality — is what separates them, and an unmatched or truncated text
// degrades to the weakest true conclusion rather than guessing (ADR 0069).
func (o openObservation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		return domain.StatePass, domain.FailureNone
	}

	if o.hasRefusal {
		if o.refusal.ReplyCode == 530 {
			switch o.refusal.Outcome {
			case wire.CloseVHostNotFound:
				// The peer asserted the absence of the resource svcdoctor named.
				// ADR 0069 §6.3 widened FailureResourceNotFound's evidence clause
				// to admit exactly this: a reconstructed statement matched byte
				// for byte, which is stronger evidence than a code emitted for
				// six conditions.
				return domain.StateFail, domain.FailureResourceNotFound
			case wire.CloseVHostAccessRefused:
				return domain.StateFail, domain.FailureAuthzDenied
			case wire.CloseNodeConnectionLimit,
				wire.CloseVHostConnectionLimit,
				wire.CloseUserConnectionLimit:
				// A capacity ceiling the peer named itself. It says nothing about
				// whether the ceiling is too low, whether demand is abnormal, or
				// whether the condition still holds.
				return domain.StateFail, domain.FailureResourceLimitReached
			}
		}
		// Any other refusal, including 541 vhost-down — which was source-proven
		// and never live-measured, so ADR 0069 §6.2 authorizes no normalized
		// outcome for it — and any 530 whose text did not match or was truncated.
		return domain.StateFail, domain.FailureAuthzNotPermitted
	}

	switch {
	case errors.Is(o.err, wire.ErrInvalidInput):
		return domain.StateUnknown, domain.FailureExecRequiredInputMissing
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded),
		errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	case errors.Is(o.err, wire.ErrPeerClosed):
		// **This is where an invalid Tune-Ok lands**, because RabbitMQ answers
		// one with a silent close about three seconds later rather than with a
		// Close frame — measured in Phase 8.0C, and the falsification of a Phase
		// 8.0A prediction. Nothing here pretends a Close arrived.
		return domain.StateFail, domain.FailureProtocolPeerClosed
	case errors.Is(o.err, wire.ErrMalformedFrame):
		return domain.StateFail, domain.FailureProtocolMalformedResponse
	case errors.Is(o.err, wire.ErrUnexpectedFrame):
		return domain.StateFail, domain.FailureProtocolUnexpectedResponse
	case isTimeout(o.err):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	default:
		return domain.StateFail, domain.FailureProtocolPeerClosed
	}
}

func (o openObservation) attributes() map[domain.AttributeKey]domain.AttrValue {
	attrs := map[domain.AttributeKey]domain.AttrValue{
		// The operator's own input, identity-classed: a virtual host name is a
		// tenant name in a multi-tenant deployment.
		servicerabbitmq.AttrVHost: domain.IdentityAttr(o.vhost),
	}
	if o.defaulted {
		// ADR 0067 §3.1: a vhost-scoped refusal must be able to say the default
		// was used, which turns the one bad case into a self-explaining one.
		attrs[servicerabbitmq.AttrVHostDefaulted] = domain.BoolAttr(true)
	}
	if o.hasRefusal {
		attrs[servicerabbitmq.AttrCloseOutcome] = domain.StringAttr(o.refusal.Outcome.String())
		attrs[servicerabbitmq.AttrReplyCode] = domain.IntAttr(int64(o.refusal.ReplyCode))
		attrs[servicerabbitmq.AttrPeerCloseMethod] = domain.StringAttr(
			strconv.Itoa(int(o.refusal.PeerClassID)) + "/" +
				strconv.Itoa(int(o.refusal.PeerMethodID)))
	}
	if o.hasGraceful {
		attrs[servicerabbitmq.AttrGracefulClose] = domain.BoolAttr(o.graceful)
	}
	return attrs
}
