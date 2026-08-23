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

// StepSession names the session-establishment step.
//
// An alias; the definition lives in internal/service/postgres. See
// StepSSLRequest.
const StepSession = servicepostgres.StepSession

// The attributes session establishment records.
//
// Four come from the ParameterStatus allowlist and one from the frame that ends
// the window. Their values are the server's own strings, uninterpreted: this
// layer records what was observed, and turning "on" into "this is a replica" is
// a claim a Phase 4.6 rule makes over frozen evidence.
const (
	// AttrServerVersion is the server's own version string.
	//
	// It carries the packaging suffix a distribution adds — "18.6 (Debian
	// 18.6-1.pgdg13+2)" — because that is what the server sends. It is not a
	// number, and `server_version_num` is not sent by any version in the support
	// window, so a consumer that needs an ordered comparison must parse this.
	AttrServerVersion domain.AttributeKey = "postgres.server_version"

	// AttrInHotStandby is "on" when the session is attached to a server in
	// recovery.
	//
	// Measured "on" against a real streaming standby and "off" against its
	// primary, on 14.24 and 18.6 alike.
	AttrInHotStandby domain.AttributeKey = "postgres.in_hot_standby"

	// AttrDefaultTransactionReadOnly is the default_transaction_read_only GUC.
	//
	// **It is not the same fact as AttrInHotStandby, and it does not follow it.**
	// Measured on a real standby: in_hot_standby was "on" while this was "off". A
	// session on a standby is read-only because of recovery, not because this
	// parameter is set, so a rule reading only this one would call a replica
	// writable. Both are recorded and neither alone answers "can I write here".
	AttrDefaultTransactionReadOnly domain.AttributeKey = "postgres.default_transaction_read_only"

	// AttrIsSuperuser is "on" when the authenticated role is a superuser.
	//
	// One bit about the privilege of the connection svcdoctor established. It
	// names nobody: the role itself is on the startup node, as identity.
	AttrIsSuperuser domain.AttributeKey = "postgres.is_superuser"

	// AttrTransactionStatus is the ReadyForQuery status, normalized.
	//
	// "idle" on every path measured, and expected to stay so: svcdoctor issues no
	// command that could open a transaction. It is recorded because it is the
	// whole payload of the frame that defines success, and a value other than
	// "idle" would say something no other observation could.
	AttrTransactionStatus domain.AttributeKey = "postgres.transaction_status"
)

// SessionParams carries what one session establishment needs beyond the
// connection.
type SessionParams struct {
	// ReadTimeout optionally bounds the whole window, derived from the caller's
	// context. Zero means only the caller's context bounds the work.
	ReadTimeout time.Duration
}

func (p SessionParams) validate() error {
	if p.ReadTimeout < 0 {
		return fmt.Errorf(
			"%w: read timeout %s must not be negative", ErrInvalidInput, p.ReadTimeout)
	}
	return nil
}

// SessionResult is what a successfully established session leaves behind.
//
// **It carries no connection**, and that is the decision rather than an
// oversight. See EstablishSession.
type SessionResult struct {
	endpoint   string
	evidenceID domain.EvidenceID
}

// Endpoint returns the logical label the session was established against.
func (r *SessionResult) Endpoint() string { return r.endpoint }

// Evidence returns the identifier of the session node.
func (r *SessionResult) Evidence() domain.EvidenceID { return r.evidenceID }

// EstablishSession reads from AuthenticationOk to ReadyForQuery and stops there.
//
// Evidence goes into builder: one L5 node parented to the node the authenticated
// session names. A non-nil result means the session reached ReadyForQuery.
//
// # It is terminal, and returns no connection
//
// Every other step in this package hands its connection to the next one. This one
// does not, because there is no next one: svcdoctor v0.1 executes no statement
// and discovers no PostgreSQL topology, so a returned socket would have no
// consumer. Three things follow from that, and all three are the point:
//
//   - ADR 0036 requires Terminate before closing a session that reached
//     ReadyForQuery. That is the owner's courtesy, and if the connection escaped,
//     nobody would perform it.
//   - The ownership matrix has one rule instead of two: **every outcome closes**.
//   - No third type carrying this socket exists. `Session`, `AuthenticatedSession`
//     and a hypothetical `ReadySession` would be three names for one connection
//     at three moments, which is the speculative machinery ADR 0002 refuses.
//
// Reopen when a step exists that runs after ReadyForQuery. See ADR 0039
// section 15.
//
// # What a passing node claims
//
// That a PostgreSQL-protocol session reached ReadyForQuery at this endpoint, for
// the role and database this run named. **Not** that a PostgreSQL server is
// behind the endpoint: pgBouncer served a complete passing session from its cache
// with its backend stopped, measured. Not that the session is writable, not that
// any schema or table exists, and not that the connection would still work a
// second later.
//
// # Authentication is never rewritten
//
// A session that fails at 3D000 leaves the authentication node PASS, because the
// credential was accepted and the server said so. Two nodes answer two questions,
// and a later answer does not revise an earlier one.
//
// # Errors
//
// An error means the step could not run: unusable input, or an invariant failure
// such as a graph that rejected a node. Every protocol outcome is evidence, and a
// recorded non-passing outcome returns (nil, nil) — the idiom Negotiate, Startup
// and Authenticate already use here.
func EstablishSession(
	ctx context.Context,
	builder *domain.GraphBuilder,
	session *AuthenticatedSession,
	params SessionParams,
) (*SessionResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if session == nil {
		return nil, fmt.Errorf("%w: authenticated session must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	conn, ok := session.TakeConn()
	if !ok {
		return nil, fmt.Errorf(
			"%w: the session has no connection to establish over", ErrInvalidInput)
	}
	// The connection belongs to this call and leaves it closed, on every path.
	defer func() { _ = conn.Close() }()

	observed := observeSession(ctx, conn, params)

	evidence, err := observed.evidence(session)
	if err != nil {
		return nil, err
	}
	if err := record(builder, evidence, session.Evidence()); err != nil {
		return nil, err
	}

	if !observed.ready() {
		return nil, nil //nolint:nilnil // a recorded non-passing outcome is evidence, not an error; see the doc comment.
	}

	// The session reached the boundary, so say goodbye properly. A failure here
	// is deliberately ignored: the session already succeeded, and a courtesy
	// message that did not land does not unmake it.
	_ = wire.SendTerminate(ctx, conn)

	return &SessionResult{endpoint: session.endpoint, evidenceID: evidence.ID()}, nil
}

// sessionObservation is the producer-local record of one establishment window.
type sessionObservation struct {
	parameters wire.SessionParameters

	// status is the ReadyForQuery transaction byte, and statusRead says whether
	// one arrived. The two are separate because a zero byte is not a status.
	status     byte
	statusRead bool

	fields wire.ErrorFields

	err    error
	ctxErr error

	startedAt time.Time
	duration  time.Duration
}

// ready reports whether the session reached ReadyForQuery.
//
// It is the whole success condition, written once. AuthenticationOk is not part
// of it — that belonged to the previous step, and three distinct failures arrive
// after it: a missing database, a revoked CONNECT privilege and an exhausted
// connection limit, each measured as the first frame in this window.
func (o sessionObservation) ready() bool {
	return o.err == nil && o.statusRead
}

// observeSession runs the frame loop.
//
// This is the only function here that performs I/O or reads a clock; everything
// after it is a pure transformation.
func observeSession(
	ctx context.Context, conn net.Conn, params SessionParams,
) sessionObservation {
	readCtx, cancel := stepContext(ctx, params.ReadTimeout)
	defer cancel()

	startedAt := time.Now()
	observed := readSessionFrames(readCtx, conn)
	observed.ctxErr = ctx.Err()
	observed.startedAt = startedAt
	observed.duration = time.Since(startedAt)
	return observed
}

// readSessionFrames reads until the window ends, one exact-length frame at a
// time.
//
// # The frames it accepts, and the one it does not
//
//	ParameterStatus  allowlisted keys retained, everything else read and dropped
//	BackendKeyData   validated structurally, both values discarded
//	ReadyForQuery    ends the window; the status byte is the observation
//	ErrorResponse    ends the window; SQLSTATE and severity are the observation
//	NoticeResponse   skipped structurally, payload never decoded
//	anything else    refused
//
// **There is no generic skip-unknown-message branch**, and that is deliberate. A
// message type the protocol does not define at this point is a peer doing
// something svcdoctor cannot account for, and silently ignoring it would let a
// hostile or broken peer steer the loop by inserting frames. Only NoticeResponse
// is skipped, because the protocol permits one almost anywhere and it answers
// nothing — the same rule Startup and the SCRAM exchange already follow.
//
// # It never reads past ReadyForQuery
//
// The loop returns the moment that frame is decoded. Every read is an
// exact-length read straight off the net.Conn through wire.ReadMessage; there is
// no bufio.Reader on this path.
func readSessionFrames(ctx context.Context, conn net.Conn) sessionObservation {
	var out sessionObservation

	// A bound on notices and parameters, so a peer cannot hold the window open
	// forever by sending well-formed frames. The caller's context bounds total
	// time regardless; this bounds the message count independently of how fast
	// they arrive. A real backend sends fifteen parameters and one key frame.
	const maxFrames = 256

	for range maxFrames {
		msg, err := wire.ReadMessage(ctx, conn)
		if err != nil {
			out.err = err
			return out
		}

		switch msg.Type {
		case wire.MsgParameterStatus:
			if err := out.parameters.ApplyParameterStatus(msg.Body); err != nil {
				out.err = err
				return out
			}

		case wire.MsgBackendKeyData:
			if err := wire.ValidateBackendKeyData(msg.Body); err != nil {
				out.err = err
				return out
			}
			// Validated and gone. Neither the process ID nor the secret key has
			// anywhere to be stored, because wire returns neither.

		case wire.MsgReadyForQuery:
			status, err := wire.DecodeReadyForQuery(msg.Body)
			if err != nil {
				out.err = err
				return out
			}
			out.status, out.statusRead = status, true
			return out

		case wire.MsgErrorResponse:
			fields, err := wire.DecodeErrorFields(msg.Body)
			if err != nil {
				out.err = err
				return out
			}
			out.fields = fields
			out.err = wire.ErrUnexpectedResponse
			return out

		case wire.MsgNoticeResponse:
			// The protocol permits one almost anywhere and it answers nothing.
			// The payload is never decoded: a notice is deployment-authored
			// prose, and evidence has no sanitization step for prose.
			continue

		default:
			out.err = wire.ErrUnexpectedResponse
			return out
		}
	}

	out.err = wire.ErrUnexpectedResponse
	return out
}

// evidence normalizes the observation into the canonical model.
func (o sessionObservation) evidence(session *AuthenticatedSession) (domain.Evidence, error) {
	state, failure := o.classify()

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           sessionID(target{endpoint: session.endpoint, address: session.address}),
		Subject:      mustSubject(session.address),
		Layer:        domain.LayerAuth,
		Step:         StepSession,
		State:        state,
		FailureClass: failure,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Elapsed:      domain.Measured(o.duration),
	})
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("building %s evidence: %w", StepSession, err)
	}
	return evidence, nil
}

// classify decides what the observation is allowed to claim.
//
// The order is the one every producer here follows: a completed exchange is a
// fact, then the caller's context, then what the peer said, then what the wire
// boundary observed.
func (o sessionObservation) classify() (domain.State, domain.FailureClass) {
	if o.ready() {
		return domain.StatePass, domain.FailureNone
	}

	switch {
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded), errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}

	if !o.fields.IsZero() {
		return domain.StateFail, sessionSQLStateFailure(o.fields.SQLState)
	}

	if isTimeout(o.err) {
		// A deadline nothing identified as the network's is svcdoctor's own.
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}
	return domain.StateFail, wireFailureClass(o.err)
}

// sessionSQLStateFailure normalizes an ErrorResponse observed while establishing
// a session.
//
// # This classifier is scoped to this step, and there is no shared table
//
// svcdoctor has one classifier per protocol step — sqlStateFailure for startup,
// authSQLStateFailure for authentication, this one for session establishment —
// and they must not be merged. A shared SQLSTATE dictionary would answer *what
// does this code mean*, when the only answerable question is *what does this code
// prove here*. The same 3D000 or 42501 arriving at startup or at authentication
// stays PROTOCOL_UNEXPECTED_RESPONSE, because neither of those steps proves what
// this one proves. See ADR 0039 section 7.1.
//
// # 3D000
//
// PostgreSQL raises ERRCODE_UNDEFINED_DATABASE in this window from
// src/backend/utils/init/postinit.c, after PerformAuthentication and about the
// database name svcdoctor itself put in the StartupMessage. The peer asserts the
// absence with a code whose own name is "undefined database"; svcdoctor is not
// inferring it from position.
//
// **It carries no cause.** Three distinct conditions share the code: the lookup
// found no row, the row disappeared in a race, or the catalog row exists and its
// files do not — corruption reported as "does not exist". RESOURCE_NOT_FOUND
// states the fact true of all three and stops. It does not claim the database was
// never created, that it was deliberately dropped, or that the peer's catalog or
// filesystem is healthy.
//
// # 42501
//
// postinit.c has three ERRCODE_INSUFFICIENT_PRIVILEGE sites and **only one is
// reachable for svcdoctor**: CheckMyDatabase's CONNECT check. The other two need
// a startup option svcdoctor does not send — binary-upgrade mode, and the
// `replication` parameter — and wire.EncodeStartup emits `user` and `database`
// and nothing else, which TestStartupSendsNothingItWasNotAskedFor asserts by
// name.
//
// So here it means: the authenticated principal was denied CONNECT to the
// requested database. It does **not** imply a table, schema or function privilege
// denial, missing role membership, denied write access, or that superuser is
// required — none of those checks can have run, because svcdoctor issues no
// statement.
//
// # Everything else, 53300 included
//
// Falls through to the honest weak class with the SQLSTATE recorded beside it. A
// connection-limit refusal is a real operational fact and a different remedy from
// anything else here, and it still gets no class of its own: one producer and no
// authorizing record is not enough to grow a service-neutral vocabulary, and
// postgres.sqlstate carries it for a Phase 4.6 rule to read. The same applies to
// 08P01, which is pgBouncer's default code and proves nothing about a cause, and
// to 57P03, which Phase 4.5a measured arriving *before* authentication.
//
// No English message is examined, here or anywhere in this package.
func sessionSQLStateFailure(sqlState string) domain.FailureClass {
	switch sqlState {
	case "3D000":
		return domain.FailureResourceNotFound
	case "42501":
		return domain.FailureAuthzDenied
	}
	// A refusal svcdoctor cannot normalize. The code itself is recorded as an
	// attribute, so nothing is lost by declining to name a cause.
	return domain.FailureProtocolUnexpectedResponse
}

// attributes records the facts the window yielded.
//
// # Presence is decided per attribute, not per outcome
//
// A key appears when the observation actually produced it, whatever the node's
// state. A timeout after two ParameterStatus frames records those two on an
// UNKNOWN node, because they were observed and remain true; a window that never
// reached ReadyForQuery records no transaction status, because there was none.
//
// That is internal/probe/tls's rule, which records the certificate chain of a
// handshake that *failed* verification — "an absent fact and a zero value are
// different things". Nothing is fabricated to fill a gap.
//
// # What is deliberately absent
//
// BackendKeyData's process ID and secret key, because wire returns neither. The
// eleven ParameterStatus values outside the allowlist, because
// wire.SessionParameters has no field they could occupy — `session_authorization`
// is the role and `search_path` carries deployment schema names, and both are
// dropped at the wire boundary rather than filtered here. The role and database,
// because the startup node already records them as identity. Every ErrorResponse
// field other than C and V. Any NoticeResponse content.
func (o sessionObservation) attributes() map[domain.AttributeKey]domain.AttrValue {
	attributes := map[domain.AttributeKey]domain.AttrValue{}

	for key, parameter := range map[domain.AttributeKey]wire.Parameter{
		AttrServerVersion:              o.parameters.ServerVersion,
		AttrInHotStandby:               o.parameters.InHotStandby,
		AttrDefaultTransactionReadOnly: o.parameters.DefaultTransactionReadOnly,
		AttrIsSuperuser:                o.parameters.IsSuperuser,
	} {
		if parameter.Present {
			attributes[key] = domain.StringAttr(parameter.Value)
		}
	}

	if o.statusRead {
		attributes[AttrTransactionStatus] = domain.StringAttr(
			wire.TransactionStatusName(o.status))
	}

	if o.fields.SQLState != "" {
		attributes[AttrSQLState] = domain.StringAttr(o.fields.SQLState)
	}
	if o.fields.Severity != "" {
		attributes[AttrErrorSeverity] = domain.StringAttr(o.fields.Severity)
	}
	if !o.fields.IsZero() {
		attributes[AttrErrorIsNative] = domain.BoolAttr(o.fields.Native)
	}
	return attributes
}

// sessionID mints the identifier of the session node.
//
// Two components, matching every other step in this package. Neither the role,
// the database, nor any observed parameter value appears: an identifier is
// bookkeeping, and neither identity nor a server's configuration enters one
// merely to make it unique.
func sessionID(t target) domain.EvidenceID {
	return probe.ScopedEvidenceID(t.scope, StepSession, t.endpoint, t.address.Addr().String())
}
