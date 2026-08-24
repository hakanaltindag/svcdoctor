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
	"github.com/hakanaltindag/svcdoctor/internal/security"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// AuthParams describes the one credential-bearing exchange a run may perform.
type AuthParams struct {
	// Endpoint is the logical endpoint the credential is authorized for. It is
	// the operator's host:port and never a resolved address.
	Endpoint security.Endpoint

	// Credential authenticates at that endpoint. It may be zero: an endpoint
	// that demands nothing is never asked for one, and a run configured without
	// one still records why it did not authenticate.
	Credential security.Credential

	// Username is the ACL user, or empty for the one-argument AUTH form.
	//
	// **Empty means empty.** `default` is never substituted: the two forms have
	// different observable behaviour against a `nopass` user, so substituting
	// would convert a true configuration finding into a false success
	// (ADR 0064 section 5).
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
// by a check that could be reset; it is unwritten. That is the same shape
// ADR 0028 chose for Kafka and PostgreSQL, and ADR 0064 section 4 fixes it for
// Redis.
//
// # No retry, no fallback, no re-dial
//
// A refused, rejected or unattempted authentication ends the credentialed part
// of the run. svcdoctor does not try the next address, does not present the
// credential again, does not downgrade the channel and does not reconnect. A
// credential-bearing retry spends a second attempt against whatever counts them,
// and Redis counts them: a failed AUTH writes an ACL LOG entry.
//
// # Three ways this returns without sending anything
//
// A run with no credential, a channel the policy refuses, and an endpoint that
// never asked. Each records a node saying which, because "svcdoctor did not
// authenticate" and "svcdoctor authenticated and it failed" are different facts
// and a reader must be able to tell them apart.
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
		address:   session.address,
		startedAt: time.Now(),
	}

	// **Endpoint authority is decided before anything else**, including before
	// the transport policy.
	//
	// Whether a credential is even *for* this endpoint is a property of the
	// input; whether it may cross this connection is a property of the channel.
	// Deciding the channel first would let a misbound credential be recorded as
	// `EXEC_SKIPPED_BY_POLICY` on a plaintext run — a node asserting a policy
	// decision about a credential that was never admissible here at all — and
	// would leave the authority check unreachable on exactly the channel where
	// it is easiest to get wrong.
	//
	// **Nothing is recorded on a refusal.** Nothing was asked of the endpoint,
	// so a node would state a fact about a peer that was never addressed.
	// `internal/adapter/postgres` refuses the same way for the same reason.
	var secret security.Secret
	if !params.Credential.IsZero() {
		var err error
		if secret, err = credentialSecret(params); err != nil {
			return err
		}
	}

	switch {
	case params.Credential.IsZero():
		// Nothing to present. The node exists so that this is distinguishable
		// from a run cancelled at the same point.
		obs.outcome = authNoCredential

	case !params.Policy.PermitsCredentials(session.channel):
		// The channel did not satisfy the credential-transport policy. **Zero
		// credential bytes are written.** ADR 0064 section 7: Redis inherits
		// `RequireVerifiedTLS` unchanged, with no Redis-shaped exception, and
		// neither a loopback address nor a private one grants any trust.
		obs.outcome = authWithheld

	default:
		obs.outcome = authAttempted
		auth, sendErr := session.rw.SendAuth(
			ctx, params.ExchangeTimeout, params.Username, secret)
		obs.auth = auth
		obs.err = sendErr
		obs.ctxErr = ctx.Err()
	}
	obs.duration = time.Since(obs.startedAt)

	evidence, err := obs.evidence()
	if err != nil {
		return err
	}
	if err := builder.AddEvidence(evidence); err != nil {
		return fmt.Errorf("recording %s evidence: %w", serviceredis.StepAuthentication, err)
	}
	if err := builder.AddParent(evidence.ID(), session.evidenceID); err != nil {
		return fmt.Errorf("linking %s to its capability node: %w",
			serviceredis.StepAuthentication, err)
	}

	session.authEvidence = evidence.ID()
	session.authenticated = obs.outcome == authAttempted && obs.err == nil && obs.auth.Accepted()
	session.authOutcome = obs.outcome
	return nil
}

// credentialSecret resolves the secret for the endpoint this run named.
//
// `SecretFor` refuses any endpoint but the one the credential names, which is
// what makes "a resolved address never widens credential authority" a check
// rather than a promise (ADR 0028 section 2).
//
// # The refusal is returned, never absorbed
//
// An earlier form of this helper turned a mismatch into an empty secret and let
// `SendAuth` decline it. That was wrong twice over. It made this authority check
// invisible to a behavioural test — the run continued and recorded a node either
// way — and the node it recorded classified svcdoctor's own refusal as
// `PROTOCOL_PEER_CLOSED`, accusing an endpoint that had not been asked for
// anything of closing the connection. The error is propagated so that the
// authority boundary is observable and no false claim about a peer is possible.
func credentialSecret(params AuthParams) (security.Secret, error) {
	secret, err := params.Credential.SecretFor(params.Endpoint)
	if err != nil {
		return security.Secret{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return secret, nil
}

// authOutcome says which of the three non-exchange paths, or the exchange, this
// node records.
type authOutcome uint8

const (
	authAttempted authOutcome = iota
	authNoCredential
	authWithheld
)

type authObservation struct {
	endpoint  string
	address   netip.AddrPort
	outcome   authOutcome
	auth      wire.Auth
	err       error
	ctxErr    error
	startedAt time.Time
	duration  time.Duration
}

func (o authObservation) evidence() (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(
		net.JoinHostPort(o.address.Addr().String(), fmt.Sprint(o.address.Port())))
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			serviceredis.StepAuthentication, o.endpoint, o.address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         serviceredis.StepAuthentication,
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
	}

	if o.err == nil {
		if o.auth.Accepted() {
			return domain.StatePass, domain.FailureNone
		}
		if o.auth.Rejected() {
			// The endpoint took a position on the credential. It named no
			// cause, and neither does this: WRONGPASS covers an unknown user, a
			// wrong password and a disabled user at one reply site
			// (redis/src/acl.c:1511).
			return domain.StateFail, domain.FailureAuthCredentialsRejected
		}
		// Some other named condition, including a generic ERR. The endpoint
		// refused; svcdoctor records what it named and infers nothing.
		return domain.StateFail, domain.FailureProtocolUnexpectedResponse
	}

	switch {
	case errors.Is(o.err, wire.ErrInvalidInput):
		// **svcdoctor's own refusal, not the endpoint's.** ErrInvalidInput is
		// raised before anything is written, so no peer behaviour was observed
		// and no class naming the peer may be used. UNKNOWN is the honest state:
		// the run did not measure this step. The operation is one svcdoctor can
		// perform, no policy objected, and it had nothing usable to perform it
		// with — which is exactly EXEC_REQUIRED_INPUT_MISSING.
		//
		// Unreachable while Authenticate returns on a credential-authority
		// refusal above, and kept because "unreachable" is a property of today's
		// callers rather than of this classifier.
		return domain.StateUnknown, domain.FailureExecRequiredInputMissing
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded), errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	case errors.Is(o.err, wire.ErrPeerClosed):
		return domain.StateFail, domain.FailureProtocolPeerClosed
	case errors.Is(o.err, wire.ErrReplyTooLarge):
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

func (o authObservation) attributes() map[domain.AttributeKey]domain.AttrValue {
	if o.outcome != authAttempted || o.err != nil || o.auth.Prefix == wire.PrefixNone {
		return nil
	}
	return map[domain.AttributeKey]domain.AttrValue{
		serviceredis.AttrErrorPrefix: domain.StringAttr(string(o.auth.Prefix)),
	}
}
