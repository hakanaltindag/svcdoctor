package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// StepStartup names the startup exchange this adapter performs.
//
// An alias; the definition lives in internal/service/postgres. See
// StepSSLRequest.
const StepStartup = servicepostgres.StepStartup

// The attributes the startup exchange records.
const (
	// AttrProtocolVersion is the protocol version svcdoctor requested, as
	// "major.minor".
	AttrProtocolVersion domain.AttributeKey = "postgres.protocol_version"

	// AttrAuthMethod is the authentication the server demanded, normalized.
	// It is the fact that proves startup got far enough to matter.
	//
	// An alias. A session rule reads it to recognize the `trust` path, where no
	// authentication node exists and a session's parent is this node.
	AttrAuthMethod = servicepostgres.AttrAuthMethod

	// AttrSASLMechanisms lists the SASL mechanisms the server advertised, in its
	// stated preference order. A real server offers SCRAM-SHA-256-PLUS only over
	// TLS, so the list describes the channel as well as the server.
	AttrSASLMechanisms domain.AttributeKey = "postgres.sasl_mechanisms"

	// AttrSQLState is the server's SQLSTATE when it rejected the startup. Five
	// characters, machine-readable, carrying no identity.
	//
	// An alias. A floor finding renders it verbatim and never translates it.
	AttrSQLState = servicepostgres.AttrSQLState

	// AttrErrorSeverity is the non-localized severity field. It exists only
	// because the localized one cannot be compared across locales.
	AttrErrorSeverity domain.AttributeKey = "postgres.error_severity"

	// AttrErrorIsNative reports whether the rejection carried the non-localized
	// severity field at all.
	//
	// Every genuine PostgreSQL backend since 9.6 sends it and pgBouncer does
	// not, so this is the one structural, non-prose signal svcdoctor has for
	// whether it is talking to a real backend.
	//
	// An alias. A floor finding may state its absence as an observation, and may
	// not conclude a peer implementation from it: ADR 0040 section 18.1 makes
	// that normative and a guard enforces it.
	AttrErrorIsNative = servicepostgres.AttrErrorIsNative

	// AttrRole and AttrDatabase are the identities the StartupMessage declared.
	//
	// Both are recorded through domain.IdentityAttr, never StringAttr: they name
	// a principal and a named resource in the inspected environment, so a
	// shareable report must replace them with identity-NNN. Recording them as
	// plain strings would leak the tenant and dataset names of whoever ran the
	// tool (ADR 0037).
	AttrRole     domain.AttributeKey = "postgres.role"
	AttrDatabase domain.AttributeKey = "postgres.database"
)

// Startup sends a StartupMessage and reads the server's first decisive reply.
//
// It stops at the moment authentication becomes the question. A server that asks
// for a password, an MD5 digest or a SASL exchange has told svcdoctor everything
// this phase set out to learn: the endpoint speaks PostgreSQL, it accepted the
// protocol version, and it accepted the startup packet far enough to demand
// credentials. **Nothing answers that demand here.** There is no password in this
// package, no digest, no SCRAM, and no call to security.Reveal.
//
// # Same socket
//
// The message goes over the connection the Session owns, which is the one the
// SSL negotiation ran over, which is the one the TCP probe measured. Nothing
// dials.
//
// # Ownership
//
// The Session's connection is taken, so afterwards the Session no longer holds
// it. A failing exchange closes it here; a successful one leaves it open and
// owned by the returned StartupResult, because Phase 4.4 must continue on it.
//
// # A dead session still produces a node
//
// When the negotiation left nothing usable, this records a SKIPPED node blocked
// by whatever stopped it, and returns no result. That is how the graph explains
// why startup never happened rather than leaving a hole where a reader has to
// infer one.
func Startup(
	ctx context.Context,
	builder *domain.GraphBuilder,
	session *Session,
	params StartupParams,
) (*StartupResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if session == nil {
		return nil, fmt.Errorf("%w: session must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	if blocker, blocked := session.Blocker(); blocked {
		return nil, recordSkippedStartup(builder, session, blocker, params)
	}

	conn, ok := session.TakeConn()
	if !ok {
		return nil, fmt.Errorf("%w: session has no connection to speak over", ErrInvalidInput)
	}

	t := target{endpoint: session.endpoint, address: session.address}

	// The step's own budget, derived from the caller's context so that whichever
	// is earlier wins and the caller's remains the outer ceiling. Cancelled
	// immediately after the exchange rather than deferred: the connection
	// survives this call on the passing path, and a derived context outliving
	// the exchange it bounds would expire inside somebody else's.
	exchangeCtx, cancel := stepContext(ctx, params.ExchangeTimeout)
	startedAt := time.Now()
	auth, fields, err := exchangeStartup(exchangeCtx, conn, params)
	duration := time.Since(startedAt)
	cancel()

	state, failure := classifyStartup(ctx, auth, fields, err)

	evidence, buildErr := domain.NewEvidence(domain.EvidenceInput{
		ID:           startupID(t),
		Subject:      mustSubject(t.address),
		Layer:        domain.LayerProtocol,
		Step:         StepStartup,
		State:        state,
		FailureClass: failure,
		Attributes:   startupAttributes(params, auth, fields, err == nil),
		StartedAt:    startedAt,
		Elapsed:      domain.Measured(duration),
	})
	if buildErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("building %s evidence: %w", StepStartup, buildErr)
	}
	if recErr := record(builder, evidence, session.Evidence()); recErr != nil {
		_ = conn.Close()
		return nil, recErr
	}

	if state != domain.StatePass {
		// The exchange did not reach a point another step could continue from.
		// PostgreSQL closes after a fatal error anyway, and after a malformed
		// reply the socket's state is unknown — only this package is in a
		// position to know that.
		_ = conn.Close()
		return nil, nil //nolint:nilnil // a recorded non-passing outcome is evidence, not an error; see the doc comment.
	}

	channelEvidence, _ := session.ChannelEvidence()
	return &StartupResult{
		endpoint:        session.endpoint,
		address:         session.address,
		evidenceID:      evidence.ID(),
		channel:         session.Channel(),
		channelEvidence: channelEvidence,
		authMethod:      auth.Method.String(),
		mechanisms:      auth.Mechanisms,
		ownedConn:       ownedConn{conn: conn},
	}, nil
}

// exchangeStartup writes the startup packet and reads until the server says
// something decisive.
//
// NoticeResponse is skipped rather than treated as an answer: the protocol
// permits one almost anywhere, and a server that warns before authenticating has
// not answered the question. Everything else ends the loop and is judged by the
// caller.
func exchangeStartup(
	ctx context.Context, conn net.Conn, params StartupParams,
) (wire.AuthRequest, wire.ErrorFields, error) {
	if err := wire.SendStartup(ctx, conn, wire.StartupParams{
		User:     params.User,
		Database: params.Database,
	}); err != nil {
		return wire.AuthRequest{}, wire.ErrorFields{}, err
	}

	// A bound on notices, so a peer cannot hold the exchange open forever by
	// sending them. The caller's context bounds the total time regardless; this
	// bounds the message count independently of how fast they arrive.
	const maxNotices = 32

	for i := 0; i <= maxNotices; i++ {
		msg, err := wire.ReadMessage(ctx, conn)
		if err != nil {
			return wire.AuthRequest{}, wire.ErrorFields{}, err
		}

		switch msg.Type {
		case wire.MsgNoticeResponse:
			continue
		case wire.MsgAuthentication:
			auth, decodeErr := wire.DecodeAuthRequest(msg.Body)
			if decodeErr != nil {
				return wire.AuthRequest{}, wire.ErrorFields{}, decodeErr
			}
			return auth, wire.ErrorFields{}, nil
		case wire.MsgErrorResponse:
			fields, decodeErr := wire.DecodeErrorFields(msg.Body)
			if decodeErr != nil {
				return wire.AuthRequest{}, wire.ErrorFields{}, decodeErr
			}
			return wire.AuthRequest{}, fields, wire.ErrUnexpectedResponse
		default:
			// Something structurally valid that the protocol does not allow as
			// a first answer to a startup packet — including
			// NegotiateProtocolVersion, which cannot occur for the 3.0 this
			// phase requests, and which a later phase would handle if it asked
			// for a newer minor version.
			return wire.AuthRequest{}, wire.ErrorFields{}, wire.ErrUnexpectedResponse
		}
	}
	return wire.AuthRequest{}, wire.ErrorFields{}, wire.ErrUnexpectedResponse
}

// classifyStartup decides what the exchange is allowed to claim.
//
// PASS means the server answered as a PostgreSQL backend and named an
// authentication it wants — including AuthenticationOk, which is a server saying
// it wants none. The startup packet was accepted either way, and that is the
// whole of what this node claims.
func classifyStartup(
	ctx context.Context, auth wire.AuthRequest, fields wire.ErrorFields, err error,
) (domain.State, domain.FailureClass) {
	if err == nil {
		return domain.StatePass, domain.FailureNone
	}

	switch {
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}

	if !fields.IsZero() {
		return domain.StateFail, sqlStateFailure(fields.SQLState)
	}

	if isTimeout(err) {
		// **svcdoctor's own budget, not the peer's failure.** The step's
		// deadline is applied to the socket by wire.bindDeadline, so it comes
		// back as a net.Error timeout rather than as context.DeadlineExceeded —
		// the caller's context is still alive, and the two checks above cannot
		// see it. Without this branch the timeout fell through to
		// wireFailureClass, whose default is PROTOCOL_UNEXPECTED_RESPONSE, and a
		// slow endpoint was reported as one that answered wrongly.
		//
		// The peer's own facts are read first, above, so an ErrorResponse that
		// arrived before the deadline still wins. Nothing here reclassifies a
		// network-reported timeout: the read path has no kernel deadline of its
		// own, so a timeout on it is always the one this step set. The same
		// branch, in the same position, is what establish.go and authenticate.go
		// already do.
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}
	_ = auth
	return domain.StateFail, wireFailureClass(err)
}

// sqlStateFailure normalizes a startup rejection using the server's SQLSTATE.
//
// **Only codes this phase's state machine can actually receive are mapped.**
// Startup happens before any credential is presented, so a rejection here is
// either the protocol version or an access decision made on identity and origin
// alone. Everything a server says after authentication — a wrong credential, a
// missing database, a revoked CONNECT privilege — is unreachable from here and
// is deliberately not mapped: a mapping for a message this code cannot receive
// would be untested speculation, and ADR 0036 authorizes classes rather than
// requiring them all at once.
//
// The classification reads a five-character code and nothing else. No English
// message is examined, which is what keeps the claim stable across locales,
// PostgreSQL versions, and the poolers that rewrite the prose entirely.
func sqlStateFailure(sqlState string) domain.FailureClass {
	switch sqlState {
	case "0A000":
		// feature_not_supported: at startup this is the server refusing the
		// protocol version it was sent, and it names the range it supports.
		return domain.FailureProtocolUnsupportedVersion
	case "28000":
		// invalid_authorization_specification. At this point no authentication
		// request has been sent and no credential presented, so the server
		// refused on who is connecting and from where — pg_hba, or the absence
		// of a matching rule. That is a different fact from a refused
		// credential, and the distinction is the whole reason this class exists.
		return domain.FailureAuthzNotPermitted
	default:
		// A rejection svcdoctor cannot normalize. The code itself is recorded as
		// an attribute, so nothing is lost by declining to name a cause.
		return domain.FailureProtocolUnexpectedResponse
	}
}

// startupAttributes records the facts the exchange established.
// gotAuthRequest says whether the server actually named an authentication. It is
// passed rather than inferred from auth, because "the server demanded something
// this repository does not recognize" is a real and useful fact whose normalized
// name is "unknown" — and inferring it from the zero value would silently drop
// exactly that case.
func startupAttributes(
	params StartupParams, auth wire.AuthRequest, fields wire.ErrorFields, gotAuthRequest bool,
) map[domain.AttributeKey]domain.AttrValue {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		AttrProtocolVersion: domain.StringAttr("3.0"),
		// Identity, not a string. See AttrRole.
		AttrRole: domain.IdentityAttr(params.User),
	}
	if params.Database != "" {
		attributes[AttrDatabase] = domain.IdentityAttr(params.Database)
	}

	if gotAuthRequest {
		attributes[AttrAuthMethod] = domain.StringAttr(auth.Method.String())
	}
	if len(auth.Mechanisms) > 0 {
		attributes[AttrSASLMechanisms] = domain.StringListAttr(auth.Mechanisms...)
	}

	if fields.SQLState != "" {
		attributes[AttrSQLState] = domain.StringAttr(fields.SQLState)
	}
	if fields.Severity != "" {
		attributes[AttrErrorSeverity] = domain.StringAttr(fields.Severity)
	}
	if !fields.IsZero() {
		attributes[AttrErrorIsNative] = domain.BoolAttr(fields.Native)
	}
	return attributes
}

// recordSkippedStartup records that startup never ran, and why.
func recordSkippedStartup(
	builder *domain.GraphBuilder, session *Session, blocker domain.EvidenceID, params StartupParams,
) error {
	t := target{endpoint: session.endpoint, address: session.address}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           startupID(t),
		Subject:      mustSubject(t.address),
		Layer:        domain.LayerProtocol,
		Step:         StepStartup,
		State:        domain.StateSkipped,
		FailureClass: domain.FailureExecSkippedPrerequisiteFailed,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			// The identities are recorded even though nothing was sent, because
			// they are what the run was about: a reader needs to know which
			// role and database were never reached.
			AttrRole: domain.IdentityAttr(params.User),
		},
		StartedAt: time.Now(),
		Elapsed:   domain.Unmeasured(),
	})
	if err != nil {
		return fmt.Errorf("building skipped %s evidence: %w", StepStartup, err)
	}
	if err := record(builder, evidence, session.Evidence()); err != nil {
		return err
	}
	if err := builder.AddBlockedBy(evidence.ID(), blocker); err != nil {
		return fmt.Errorf("recording blocked-by for %s: %w", evidence.ID(), err)
	}
	return nil
}

// startupID mints the identifier of the startup node.
//
// Two components, matching every other two-component step. Neither the role nor
// the database appears: an identifier is bookkeeping, and logical identity does
// not enter one merely to make it unique.
func startupID(t target) domain.EvidenceID {
	return probe.ScopedEvidenceID(t.scope, StepStartup, t.endpoint, t.address.Addr().String())
}
