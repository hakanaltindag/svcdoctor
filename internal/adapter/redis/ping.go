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
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// Ping performs the terminal usability probe.
//
// # What a PASS on this node authorizes, and nothing more
//
// That a RESP client, from this vantage, over this connection's channel,
// authenticated as whatever it authenticated as, issued PING to this endpoint at
// this address and received PONG. ADR 0063 section 4 fixes the wording and
// forbids "Redis is healthy", "the backend is available", "the cluster is
// healthy", "replication is healthy" and "your application will work".
//
// The endpoint scoping is not decoration. A proxy — Azure Managed Redis under
// its Enterprise clustering policy, Envoy, twemproxy, ElastiCache serverless —
// can answer PING while what is behind it cannot serve anything. This is the
// pgBouncer lesson, and PostgreSQL BASIC already froze the same wording after
// measuring a pooler serving a complete passing session with its backend
// stopped.
//
// # Why this command and not a cheaper one
//
// PING carries none of CMD_NO_AUTH, CMD_LOADING or CMD_STALE, so it is the only
// command in the allowlist gated on authentication, ACL authorization,
// dataset-loading state and stale-replica state at once. HELLO and AUTH are
// exempt from the ACL command check entirely.
//
// # It is skipped when its prerequisite did not hold
//
// A run that presented no credential to an endpoint that demands one, a run
// whose credential was withheld by policy, and a run whose credential was
// rejected all record a SKIPPED node blocked by the authentication node. That is
// the layered short-circuit the project requires: the blocker owns the failure,
// and no downstream claim is fabricated.
func Ping(
	ctx context.Context, builder *domain.GraphBuilder, session *Session, params Params,
) error {
	if session == nil || session.rw == nil {
		return fmt.Errorf("%w: Ping needs an open session", ErrInvalidInput)
	}
	if builder == nil {
		return fmt.Errorf("%w: builder must not be nil", ErrInvalidInput)
	}

	obs := pingObservation{
		endpoint:  session.endpoint,
		address:   session.address,
		startedAt: time.Now(),
		blocked:   pingBlocked(session),
	}

	if !obs.blocked {
		ping, err := session.rw.SendPing(ctx, params.ExchangeTimeout)
		obs.ping = ping
		obs.err = err
		obs.ctxErr = ctx.Err()
	}
	obs.duration = time.Since(obs.startedAt)

	evidence, err := obs.evidence()
	if err != nil {
		return err
	}
	if err := builder.AddEvidence(evidence); err != nil {
		return fmt.Errorf("recording %s evidence: %w", serviceredis.StepPing, err)
	}

	parent := session.evidenceID
	if session.authEvidence != "" {
		parent = session.authEvidence
	}
	if err := builder.AddParent(evidence.ID(), parent); err != nil {
		return fmt.Errorf("linking %s to its parent: %w", serviceredis.StepPing, err)
	}
	if obs.blocked {
		if err := builder.AddBlockedBy(evidence.ID(), session.authEvidence); err != nil {
			return fmt.Errorf("recording what blocked %s: %w", serviceredis.StepPing, err)
		}
	}
	return nil
}

// pingBlocked reports that the authentication step did not leave a connection
// this probe may use.
//
// An endpoint that never demanded authentication is **not** blocked: no
// credential was needed, none was presented, and PING is exactly as meaningful
// there as it is on an authenticated connection.
func pingBlocked(session *Session) bool {
	if session.authEvidence == "" {
		return false
	}
	if session.authenticated {
		return false
	}
	if session.authOutcome == authNoCredential && !session.AuthRequired() {
		// A run with no credential against an endpoint that asked for none.
		return false
	}
	return true
}

type pingObservation struct {
	endpoint  string
	address   netip.AddrPort
	blocked   bool
	ping      wire.Ping
	err       error
	ctxErr    error
	startedAt time.Time
	duration  time.Duration
}

func (o pingObservation) evidence() (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(
		net.JoinHostPort(o.address.Addr().String(), fmt.Sprint(o.address.Port())))
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	elapsed := domain.Measured(o.duration)
	if o.blocked {
		// Nothing was attempted, so there is no duration to report. Writing a
		// near-zero measurement would claim an instantaneous probe.
		elapsed = domain.Unmeasured()
	}

	return domain.NewEvidence(domain.EvidenceInput{
		ID:           probe.EvidenceID(serviceredis.StepPing, o.endpoint, o.address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         serviceredis.StepPing,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Elapsed:      elapsed,
	})
}

// classify decides what one PING is allowed to claim.
//
// # NOPERM is UNKNOWN, never FAIL
//
// The endpoint authenticated the connection and then declined to run this
// command for this identity. The service did not fail; svcdoctor's measurement
// was blocked. Reporting it as a target failure would tell an operator their
// Redis is broken when their ACL is working exactly as configured. It is the
// same rule the project already applies to missing privilege everywhere else.
//
// # LOADING, MASTERDOWN and BUSY land on the honest weak class
//
// Each is an authoritative statement by the endpoint about its own readiness,
// and each is a different remedy — but none of them gets a class of its own.
// `internal/adapter/postgres/establish.go` does exactly this for `53300` and
// `57P03`, on the stated ground that one producer and no authorizing record is
// not enough to grow a service-neutral vocabulary. The prefix is recorded beside
// the class so a rule can state what the endpoint named.
func (o pingObservation) classify() (domain.State, domain.FailureClass) {
	if o.blocked {
		return domain.StateSkipped, domain.FailureExecSkippedPrerequisiteFailed
	}

	if o.err == nil {
		switch {
		case o.ping.Pong():
			return domain.StatePass, domain.FailureNone
		case o.ping.Prefix == wire.PrefixNOPERM:
			return domain.StateUnknown, domain.FailureAuthzDenied
		default:
			return domain.StateUnknown, domain.FailureProtocolUnexpectedResponse
		}
	}

	switch {
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

func (o pingObservation) attributes() map[domain.AttributeKey]domain.AttrValue {
	if o.blocked || o.err != nil || o.ping.Prefix == wire.PrefixNone {
		return nil
	}
	return map[domain.AttributeKey]domain.AttrValue{
		serviceredis.AttrErrorPrefix: domain.StringAttr(string(o.ping.Prefix)),
	}
}
