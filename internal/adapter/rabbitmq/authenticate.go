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
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// AuthParams describes the one credential-bearing exchange a run may perform.
type AuthParams struct {
	// Endpoint is the logical endpoint the credential is authorized for. It is
	// the operator's host:port and never a resolved address.
	//
	// **It is not host:port plus vhost, and that is forced by the protocol.**
	// Connection.Start-Ok carries the credential and Connection.Open names the
	// virtual host, in that order, so by the time svcdoctor learns anything about
	// the vhost the password has already been transmitted. A vhost-scoped
	// authority would have to gate a transmission that already happened, which
	// makes it unimplementable rather than merely undesirable (ADR 0068 §6).
	Endpoint security.Endpoint

	// Credential authenticates at that endpoint. It may be zero: a run
	// configured without one still records why it did not authenticate.
	Credential security.Credential

	// Username is the identity presented in the PLAIN response.
	Username string

	// Policy decides whether the credential may cross the channel this
	// connection established. The zero value requires verified TLS, so a caller
	// that never set it refuses rather than permits.
	Policy security.CredentialTransportPolicy

	// ExchangeTimeout bounds the exchange.
	ExchangeTimeout time.Duration
}

// Authenticate presents the credential, once, on one session.
//
// # One attempt, by construction rather than by counting
//
// This function takes a single session, holds no loop and no second candidate,
// and there is exactly one call site above it. A second attempt is not forbidden
// by a check that could be reset; it is unwritten. That is the shape ADR 0028
// chose for Kafka and PostgreSQL, ADR 0064 fixed for Redis, and ADR 0068 §5
// fixes here — where the protocol makes it exact rather than aspirational,
// because SASL PLAIN is single-shot and RabbitMQ never challenges it.
//
// # No retry, no fallback, no redial
//
// A refused, rejected or unattempted authentication ends the credentialed part
// of the run. svcdoctor does not try another mechanism, does not present the
// credential again, does not downgrade the channel and does not reconnect. A
// credential-bearing retry spends a second attempt against whatever counts them,
// and RabbitMQ counts them: a failed login writes an ERROR log line and
// increments an auth-attempt metric.
//
// # Connection.Tune is the success signal
//
// RabbitMQ never acknowledges authentication. Its reader sends Tune only on the
// branch where the user was accepted, so Tune's arrival *is* the proof — which
// is why its values land here as attributes rather than on a node of their own
// (ADR 0067 §4.1).
//
// # Three ways this returns without sending anything
//
// A run with no credential, a channel the policy refuses, and an endpoint that
// does not offer PLAIN. Each records a node saying which, because "svcdoctor did
// not authenticate" and "svcdoctor authenticated and it failed" are different
// facts and a reader must be able to tell them apart.
func Authenticate(
	ctx context.Context, builder *domain.GraphBuilder, session *Session, params AuthParams,
) error {
	if session == nil || session.rw == nil {
		return fmt.Errorf("%w: Authenticate needs an open session", ErrInvalidInput)
	}
	if builder == nil {
		return fmt.Errorf("%w: builder must not be nil", ErrInvalidInput)
	}

	obs := authObservation{
		endpoint:  session.endpoint,
		username:  params.Username,
		address:   session.address,
		offered:   session.start,
		startedAt: time.Now(),
	}

	// **Endpoint authority is decided before anything else**, including before
	// the transport policy.
	//
	// Whether a credential is even *for* this endpoint is a property of the
	// input; whether it may cross this connection is a property of the channel.
	// Deciding the channel first would let a misbound credential be recorded as
	// EXEC_SKIPPED_BY_POLICY on a plaintext run — a node asserting a policy
	// decision about a credential that was never admissible here at all — and
	// would leave the authority check unreachable on exactly the channel where
	// it is easiest to get wrong.
	//
	// **Nothing is recorded on a refusal.** Nothing was asked of the endpoint, so
	// a node would state a fact about a peer that was never addressed. The Redis
	// and PostgreSQL adapters refuse the same way for the same reason.
	var secret security.Secret
	if !params.Credential.IsZero() {
		var err error
		if secret, err = credentialSecret(params); err != nil {
			return err
		}
	}

	switch {
	case params.Credential.IsZero():
		obs.outcome = authNoCredential

	case !session.start.PlainOffered:
		// svcdoctor implements PLAIN and does not fall back (ADR 0068 §2). Zero
		// credential bytes are written, and the endpoint is not accused of
		// anything: it is behaving correctly and svcdoctor is the limited party.
		obs.outcome = authMechanismNotOffered

	case !params.Policy.PermitsCredentials(session.channel):
		// The channel did not satisfy the credential-transport policy. **Zero
		// credential bytes are written.** ADR 0068 §7: RabbitMQ inherits
		// RequireVerifiedTLS unchanged, with no RabbitMQ-shaped exception, and
		// neither a loopback address nor a private one grants any trust.
		obs.outcome = authWithheld

	default:
		obs.outcome = authAttempted
		tune, sendErr := session.rw.SendStartOk(
			ctx, params.ExchangeTimeout, params.Username, secret)
		obs.tune = tune
		obs.err = sendErr
		obs.ctxErr = ctx.Err()

		if sendErr == nil {
			// Answer the negotiation with the frozen values. A failure here is
			// still an authentication-node outcome, because authentication is
			// what this node measures and Tune already proved it.
			selected, selErr := wire.SelectTune(tune)
			obs.selected = selected
			obs.hasSelected = selErr == nil
			if selErr != nil {
				obs.err = selErr
			} else if tuneErr := session.rw.SendTuneOk(
				ctx, params.ExchangeTimeout, selected); tuneErr != nil {
				obs.err = tuneErr
			}
		}
	}
	obs.duration = time.Since(obs.startedAt)

	evidence, err := obs.evidence()
	if err != nil {
		return err
	}
	if err := builder.AddEvidence(evidence); err != nil {
		return fmt.Errorf("recording %s evidence: %w",
			servicerabbitmq.StepAuthentication, err)
	}
	if err := builder.AddParent(evidence.ID(), session.evidenceID); err != nil {
		return fmt.Errorf("linking %s to its protocol node: %w",
			servicerabbitmq.StepAuthentication, err)
	}

	session.authEvidence = evidence.ID()
	session.authenticated = obs.outcome == authAttempted && obs.err == nil
	return nil
}

// credentialSecret resolves the secret for the endpoint this run named.
//
// `SecretFor` refuses any endpoint but the one the credential names, which is
// what makes "a resolved address never widens credential authority" a check
// rather than a promise (ADR 0028 §2).
//
// # The refusal is returned, never absorbed
//
// Turning a mismatch into an empty secret and letting the wire package decline
// it would be wrong twice over: it would make this authority check invisible to
// a behavioural test, and the node it recorded would classify svcdoctor's own
// refusal as a peer failure, accusing an endpoint that was never asked for
// anything. The Redis adapter learned that the hard way and this follows it.
func credentialSecret(params AuthParams) (security.Secret, error) {
	secret, err := params.Credential.SecretFor(params.Endpoint)
	if err != nil {
		return security.Secret{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return secret, nil
}

// authOutcome says which of the four paths this node records.
type authOutcome uint8

const (
	authAttempted authOutcome = iota
	authNoCredential
	authWithheld
	authMechanismNotOffered
)

type authObservation struct {
	endpoint    string
	username    string
	address     netip.AddrPort
	outcome     authOutcome
	offered     wire.ServerStart
	tune        wire.Tune
	selected    wire.Selected
	hasSelected bool
	err         error
	ctxErr      error
	startedAt   time.Time
	duration    time.Duration
}

func (o authObservation) evidence() (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(
		net.JoinHostPort(o.address.Addr().String(), strconv.Itoa(int(o.address.Port()))))
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			servicerabbitmq.StepAuthentication, o.endpoint, o.address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         servicerabbitmq.StepAuthentication,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Elapsed:      domain.Measured(o.duration),
	})
}

func (o authObservation) classify() (domain.State, domain.FailureClass) {
	switch o.outcome {
	case authNoCredential:
		return domain.StateSkipped, domain.FailureExecRequiredInputMissing
	case authWithheld:
		return domain.StateSkipped, domain.FailureExecSkippedByPolicy
	case authMechanismNotOffered:
		// Not a FAIL. The broker is behaving correctly; svcdoctor implements one
		// mechanism and this endpoint does not offer it (ADR 0068 §2.1).
		return domain.StateUnknown, domain.FailureAuthMechanismNotOffered
	}

	if o.err == nil {
		return domain.StatePass, domain.FailureNone
	}

	var refused *wire.RefusedError
	if errors.As(o.err, &refused) && refused.Refusal.ReplyCode == 403 {
		// The endpoint refused the authentication context it was presented.
		//
		// It named no cause and neither does this. RabbitMQ returns a
		// byte-identical refusal for an unknown user, a wrong password, a user
		// refused by a host-based restriction and a backend that declined
		// without saying why — measured in Phase 8.0C — and equalises the timing
		// deliberately to prevent username enumeration.
		return domain.StateFail, domain.FailureAuthCredentialsRejected
	}

	switch {
	case errors.Is(o.err, wire.ErrInvalidInput):
		// svcdoctor's own refusal, raised before anything was written, so no
		// peer behaviour was observed and no class naming the peer may be used.
		return domain.StateUnknown, domain.FailureExecRequiredInputMissing
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded),
		errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	case errors.Is(o.err, wire.ErrSecureChallenge):
		// A challenge svcdoctor will not answer, because answering is a second
		// credential-bearing frame. Unreachable against RabbitMQ's PLAIN.
		return domain.StateFail, domain.FailureProtocolUnexpectedResponse
	case errors.Is(o.err, wire.ErrTuneUnsupported):
		return domain.StateUnknown, domain.FailureProtocolUnsupportedCapability
	case errors.Is(o.err, wire.ErrRefused):
		// A Close that was not a 403 while awaiting Tune. The endpoint refused
		// and svcdoctor infers no cause.
		return domain.StateFail, domain.FailureProtocolUnexpectedResponse
	case errors.Is(o.err, wire.ErrPeerClosed):
		// **Measured, and it is why the capability is mandatory.** A client that
		// does not advertise authentication_failure_close receives no frame at
		// all on a failed login — so this state is what a rejected credential
		// would collapse into without it (ADR 0068 §3). It is also what an
		// invalid Tune-Ok produces, and svcdoctor's own handshake position is
		// what tells the two apart.
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

func (o authObservation) attributes() map[domain.AttributeKey]domain.AttrValue {
	attrs := map[domain.AttributeKey]domain.AttrValue{}

	if o.outcome == authAttempted {
		attrs[servicerabbitmq.AttrMechanismSelected] = domain.StringAttr("PLAIN")
		// The identity svcdoctor presented, from the run's own input. Absent when
		// nothing was presented, which is how "no credential" stays
		// distinguishable from "authenticated as the empty string".
		if o.username != "" {
			attrs[servicerabbitmq.AttrIdentity] = domain.IdentityAttr(o.username)
		}
	}

	// The negotiation window, recorded only when Tune actually arrived. Tune's
	// arrival is authentication's success signal, so these keys appearing at all
	// is itself the evidence that the credential was accepted.
	if o.outcome == authAttempted && o.tuneArrived() {
		attrs[servicerabbitmq.AttrChannelMaxOffered] = domain.IntAttr(int64(o.tune.ChannelMax))
		attrs[servicerabbitmq.AttrFrameMaxOffered] = domain.IntAttr(int64(o.tune.FrameMax))
		attrs[servicerabbitmq.AttrHeartbeatOffered] = domain.IntAttr(int64(o.tune.Heartbeat))
	}
	if o.hasSelected {
		attrs[servicerabbitmq.AttrChannelMaxSelected] = domain.IntAttr(int64(o.selected.ChannelMax))
		attrs[servicerabbitmq.AttrFrameMaxSelected] = domain.IntAttr(int64(o.selected.FrameMax))
		attrs[servicerabbitmq.AttrHeartbeatSelected] = domain.IntAttr(int64(o.selected.Heartbeat))
	}

	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// tuneArrived reports whether the peer sent Connection.Tune.
//
// A refusal leaves the zero value, and a real broker never offers all three
// fields as zero: RabbitMQ refuses a zero channel_max and frame_max from a
// client, so a broker proposing them would be refusing every client of its own.
func (o authObservation) tuneArrived() bool {
	var refused *wire.RefusedError
	if errors.As(o.err, &refused) {
		return false
	}
	return o.tune != wire.Tune{}
}
