package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	probetls "github.com/hakanaltindag/svcdoctor/internal/probe/tls"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// StepSSLRequest names the SSL negotiation this adapter performs.
//
// It is an alias. The definition moved to internal/service/postgres in Phase
// 4.6b, because internal/diagnosis/postgres anchors a rule at this step and
// depguard denies diagnosis this package. The name stays here so that callers
// and tests are unaffected by where the constant lives (ADR 0040 section 22).
const StepSSLRequest = servicepostgres.StepSSLRequest

// The attributes the SSL negotiation records.
const (
	// AttrSSLOffered is whether the server agreed to encrypt this connection.
	// It is always recorded when svcdoctor asked, because "the server said no"
	// is a statement rather than an absence.
	//
	// An alias: a diagnosis rule requires this attribute to tell a declined
	// negotiation from one that was never answered, so the definition lives in
	// internal/service/postgres.
	AttrSSLOffered = servicepostgres.AttrSSLOffered

	// AttrTLSPlan is what the run asked for: "required" or "disabled".
	//
	// It is recorded only on a node that did not ask, where it is the whole
	// explanation for why nothing was negotiated. On a node that did ask, the
	// answer is the fact and the request is not.
	AttrTLSPlan domain.AttributeKey = "postgres.tls.plan"
)

// Negotiate settles transport encryption for one measured connection.
//
// It takes the connection from path, performs the PostgreSQL SSL negotiation the
// plan calls for, and — when the server accepts — hands the same socket to the
// generic TLS probe. Evidence goes into builder; the returned Session owns the
// connection that survives.
//
// # One socket, from beginning to end
//
// The connection this receives is the one the TCP probe measured, and it is the
// one every later step speaks over. Nothing here dials, resolves, or retries:
// there is no dialer, no resolver and no address to reconnect to in this
// package. The SSLRequest, the TLS handshake and the StartupMessage that follows
// all run over the same file descriptor, which is what makes the graph's parent
// edges causal rather than decorative (ADR 0021, ADR 0036 section 1).
//
// # Ownership
//
// The connection is taken from the Continuation, so after this call the
// transport Result no longer holds it. Every failing path closes it here. A
// successful path leaves it open and owned by the returned Session.
//
// # Errors
//
// An error means the adapter could not run: unusable input, or an invariant
// failure such as a graph that rejected a node. Every negotiation outcome —
// declined, errored, not PostgreSQL, timed out — is evidence.
func Negotiate(
	ctx context.Context,
	builder *domain.GraphBuilder,
	path *transport.Continuation,
	params Params,
) (*Session, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if path == nil {
		return nil, fmt.Errorf("%w: transport path must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	conn, ok := path.TakeConn()
	if !ok {
		return nil, fmt.Errorf("%w: transport path has no connection to continue on", ErrInvalidInput)
	}

	t := target{
		endpoint: path.Endpoint(),
		address:  path.Address(),
		parent:   path.Evidence(),
	}

	if params.TLS == TLSDisabled {
		return negotiateSkipped(builder, conn, t, params)
	}
	return negotiateTLS(ctx, builder, conn, t, params)
}

// negotiateSkipped records that svcdoctor chose not to ask, and keeps the
// plaintext connection.
//
// No SSLRequest is written. A server that answers 'S' has already given the
// socket to its TLS layer, so asking and then not upgrading would destroy the
// connection — measured against PostgreSQL 18.6, which closes it and logs
// "could not accept SSL connection: wrong version number". libpq does not ask
// under `disable` either. See TLSDisabled.
//
// The node is SKIPPED rather than absent, and that is what makes a plaintext
// channel provable: it states positively that no TLS was attempted on this
// connection, and why.
func negotiateSkipped(
	builder *domain.GraphBuilder, conn net.Conn, t target, params Params,
) (*Session, error) {
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           sslRequestID(t),
		Subject:      mustSubject(t.address),
		Layer:        domain.LayerTLS,
		Step:         StepSSLRequest,
		State:        domain.StateSkipped,
		FailureClass: domain.FailureExecSkippedByPolicy,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			AttrTLSPlan: domain.StringAttr(params.TLS.String()),
		},
		StartedAt: time.Now(),
		Duration:  0,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("building %s evidence: %w", StepSSLRequest, err)
	}
	if err := record(builder, evidence, t.parent); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &Session{
		endpoint:   t.endpoint,
		address:    t.address,
		evidenceID: evidence.ID(),
		// This package observed that the connection was left in the clear, so
		// it is the layer entitled to say so (ADR 0029, as amended in Phase
		// 4.2). It may not name a TLS constant, and does not.
		channel:         security.ChannelPlaintext,
		channelEvidence: evidence.ID(),
		ownedConn:       ownedConn{conn: conn},
	}, nil
}

// negotiateTLS asks the server to encrypt, and upgrades the same socket when it
// agrees.
func negotiateTLS(
	ctx context.Context,
	builder *domain.GraphBuilder,
	conn net.Conn,
	t target,
	params Params,
) (*Session, error) {
	stepCtx, cancel := stepContext(ctx, params.StepTimeout)
	startedAt := time.Now()
	response, err := wire.SendSSLRequest(stepCtx, conn)
	duration := time.Since(startedAt)
	cancel()

	state, failure, offered := classifySSLResponse(ctx, response, err)

	attributes := map[domain.AttributeKey]domain.AttrValue{}
	if err == nil {
		// Only a real answer produces this fact. An exchange that never got one
		// must not record "the server declined", which is a different claim
		// from "svcdoctor never found out".
		attributes[AttrSSLOffered] = domain.BoolAttr(offered)
	}

	evidence, buildErr := domain.NewEvidence(domain.EvidenceInput{
		ID:           sslRequestID(t),
		Subject:      mustSubject(t.address),
		Layer:        domain.LayerTLS,
		Step:         StepSSLRequest,
		State:        state,
		FailureClass: failure,
		Attributes:   attributes,
		StartedAt:    startedAt,
		Duration:     duration,
	})
	if buildErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("building %s evidence: %w", StepSSLRequest, buildErr)
	}
	if recErr := record(builder, evidence, t.parent); recErr != nil {
		_ = conn.Close()
		return nil, recErr
	}

	if state != domain.StatePass {
		// Nothing usable survives. The TLS node that would have run is recorded
		// as skipped and blocked by this one, so the graph reads the same way
		// whether the negotiation failed or was never answered.
		_ = conn.Close()
		if err := recordSkippedTLS(builder, t, evidence.ID()); err != nil {
			return nil, err
		}
		return &Session{
			endpoint:   t.endpoint,
			address:    t.address,
			evidenceID: evidence.ID(),
			blocker:    evidence.ID(),
		}, nil
	}

	return upgrade(ctx, builder, conn, t, params, evidence.ID())
}

// upgrade hands the negotiated socket to the generic TLS probe.
//
// The probe owns the connection unconditionally from the moment it is called, in
// every outcome including a returned error, so there is no path here that both
// holds a connection and returns.
func upgrade(
	ctx context.Context,
	builder *domain.GraphBuilder,
	conn net.Conn,
	t target,
	params Params,
	sslNode domain.EvidenceID,
) (*Session, error) {
	stepCtx, cancel := stepContext(ctx, params.StepTimeout)
	result, err := probetls.Handshake(stepCtx, conn, params.tlsParams(t))
	cancel()
	if err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	defer func() { _ = result.Close() }()

	tlsEvidence := result.Evidence()
	// The handshake happened because the server answered 'S', so the TLS node
	// derives from the negotiation node rather than from the TCP node. Parenting
	// it to TCP would lose the fact that PostgreSQL asked for the upgrade, which
	// is most of why the negotiation is a node at all.
	if err := record(builder, tlsEvidence, sslNode); err != nil {
		return nil, err
	}

	if !result.Connected() {
		return &Session{
			endpoint:   t.endpoint,
			address:    t.address,
			evidenceID: tlsEvidence.ID(),
			blocker:    tlsEvidence.ID(),
		}, nil
	}

	// The channel is copied from the probe that performed the handshake. This
	// package cannot name a TLS constant and does not try to; a lint enforces
	// that, and re-deriving the classification would give one fact two
	// authorities (ADR 0029).
	channel := result.Channel()
	wrapped, _ := result.TakeConn()

	return &Session{
		endpoint:        t.endpoint,
		address:         t.address,
		evidenceID:      tlsEvidence.ID(),
		channel:         channel,
		channelEvidence: tlsEvidence.ID(),
		ownedConn:       ownedConn{conn: wrapped},
	}, nil
}

// classifySSLResponse decides what the negotiation is allowed to claim.
//
// The order is the repository's, and it is the same one the TLS probe uses: a
// completed exchange is a completed measurement, otherwise the caller's context
// is consulted before the wire error, because svcdoctor's own budget expiring
// means nothing was learned about the peer.
//
// A declined negotiation is a **failure of the step** because the step exists to
// obtain encryption the run required. That is the plan speaking, not the wire:
// the same 'N' byte under TLSDisabled never reaches here, and the wire package
// has no idea a plan exists.
func classifySSLResponse(
	ctx context.Context, response wire.SSLResponse, err error,
) (domain.State, domain.FailureClass, bool) {
	if err == nil {
		switch response {
		case wire.SSLAccepted:
			return domain.StatePass, domain.FailureNone, true
		case wire.SSLDeclined:
			return domain.StateFail, domain.FailureProtocolUnsupportedCapability, false
		case wire.SSLErrored:
			// An error-shaped answer from a peer nobody has authenticated. The
			// message is never read, so all svcdoctor knows is that the server
			// refused to negotiate (CVE-2024-10977).
			return domain.StateFail, domain.FailureProtocolUnexpectedResponse, false
		default:
			return domain.StateFail, domain.FailureProtocolUnexpectedResponse, false
		}
	}

	switch {
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled, false
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout, false
	}

	return domain.StateFail, wireFailureClass(err), false
}

// recordSkippedTLS records that a handshake was wanted and never ran.
//
// It uses the identifier and subject the TLS probe itself would have produced,
// so a skipped node sits exactly where the executed one would have, and a later
// run against a working server mints the same identifier for the same step.
func recordSkippedTLS(builder *domain.GraphBuilder, t target, blocker domain.EvidenceID) error {
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: probe.ScopedEvidenceID(
			t.scope, probetls.StepHandshake, t.endpoint, t.address.Addr().String()),
		Subject:      mustSubject(t.address),
		Layer:        domain.LayerTLS,
		Step:         probetls.StepHandshake,
		State:        domain.StateSkipped,
		FailureClass: domain.FailureExecSkippedPrerequisiteFailed,
		StartedAt:    time.Now(),
		Duration:     0,
	})
	if err != nil {
		return fmt.Errorf("building skipped %s evidence: %w", probetls.StepHandshake, err)
	}
	if err := record(builder, evidence, blocker); err != nil {
		return err
	}
	if err := builder.AddBlockedBy(evidence.ID(), blocker); err != nil {
		return fmt.Errorf("recording blocked-by for %s: %w", evidence.ID(), err)
	}
	return nil
}

// tlsParams builds the handshake parameters for this connection.
func (p Params) tlsParams(t target) probetls.Params {
	serverName := p.TLSOptions.ServerName
	if serverName == "" {
		serverName = hostOf(t.endpoint)
	}
	return probetls.Params{
		Endpoint:           t.endpoint,
		Scope:              t.scope,
		Address:            t.address,
		ServerName:         serverName,
		RootCAs:            p.TLSOptions.RootCAs,
		MinVersion:         p.TLSOptions.MinVersion,
		MaxVersion:         p.TLSOptions.MaxVersion,
		InsecureSkipVerify: p.TLSOptions.InsecureSkipVerify,
	}
}

// hostOf strips the port from an endpoint label, bracketed IPv6 included.
//
// It does not use net.SplitHostPort: a label that does not parse is passed
// through whole rather than rejected, because an endpoint is opaque here and a
// parsing failure must not decide what svcdoctor is willing to diagnose.
func hostOf(endpoint string) string {
	if strings.HasPrefix(endpoint, "[") {
		if end := strings.LastIndex(endpoint, "]"); end > 0 {
			return endpoint[1:end]
		}
		return endpoint
	}
	if idx := strings.LastIndex(endpoint, ":"); idx >= 0 &&
		!strings.Contains(endpoint[:idx], ":") {
		return endpoint[:idx]
	}
	return endpoint
}

// sslRequestID mints the identifier of the negotiation node.
//
// Two components, endpoint then address, which is the arity every two-component
// step in this repository uses and which TestStepArityIsFixed relies on. Neither
// the role nor the database is a component: an identifier is bookkeeping, and
// logical identity must not enter one merely to make it unique.
func sslRequestID(t target) domain.EvidenceID {
	return probe.ScopedEvidenceID(t.scope, StepSSLRequest, t.endpoint, t.address.Addr().String())
}

// mustSubject builds the endpoint subject for an address.
//
// An address always produces a valid subject: it is non-empty, has no
// whitespace, and contains no control characters. The error is folded rather
// than propagated so callers are not threaded through a case that cannot occur.
func mustSubject(addr netip.AddrPort) domain.Subject {
	subject, err := domain.NewEndpointSubject(addr.String())
	if err != nil {
		// Unreachable for any address netip can produce.
		return domain.Subject{}
	}
	return subject
}

// stepContext bounds one exchange.
func stepContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// record adds one node and its parent edge.
func record(builder *domain.GraphBuilder, evidence domain.Evidence, parent domain.EvidenceID) error {
	if err := builder.AddEvidence(evidence); err != nil {
		return fmt.Errorf("recording %s evidence: %w", evidence.Step(), err)
	}
	if parent == "" {
		return nil
	}
	if err := builder.AddParent(evidence.ID(), parent); err != nil {
		return fmt.Errorf("recording parent of %s: %w", evidence.ID(), err)
	}
	return nil
}

// wireFailureClass maps a wire sentinel onto the service-neutral vocabulary.
//
// Every branch is errors.Is against a typed sentinel. **No error's text is
// examined**, here or anywhere in this package: the peer chooses some of those
// bytes, and a classifier that read them would be making confident claims about
// a string an attacker picked.
func wireFailureClass(err error) domain.FailureClass {
	switch {
	case errors.Is(err, wire.ErrPeerClosed):
		return domain.FailureProtocolPeerClosed
	case errors.Is(err, wire.ErrSurplusBytes):
		// Bytes readable before the handshake: a stuffing attempt, or a peer
		// that does not implement the negotiation. Either way the answer was
		// not what this step permits.
		return domain.FailureProtocolUnexpectedResponse
	case errors.Is(err, wire.ErrUnexpectedResponse):
		return domain.FailureProtocolUnexpectedResponse
	case errors.Is(err, wire.ErrFrameTooLarge), errors.Is(err, wire.ErrMalformedMessage):
		return domain.FailureProtocolMalformedResponse
	default:
		// An I/O failure svcdoctor could not classify further. The exchange
		// genuinely did not complete, so it is a failure; what broke is unknown,
		// and a precise-sounding wrong class would be worse than an honest vague
		// one.
		return domain.FailureProtocolUnexpectedResponse
	}
}
