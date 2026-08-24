package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// StepAuthentication names the authentication exchange this step performs.
//
// An alias; the definition lives in internal/service/postgres. See
// StepSSLRequest.
const StepAuthentication = servicepostgres.StepAuthentication

// The attributes authentication records.
const (
	// AttrSASLMechanism is the mechanism this authentication used.
	//
	// It is a **separate key** from postgres.sasl_mechanisms on the startup
	// node, which means what the server *advertised*. Here the mechanism is
	// settled: it is the one svcdoctor chose and the one an error on this node
	// has to be read against. One key, one meaning.
	//
	// It is absent when no mechanism was ever chosen — a server demanding md5,
	// cleartext or GSS produces no value here, because the startup node already
	// records postgres.auth_method and a second copy would be one fact with two
	// representations.
	AttrSASLMechanism domain.AttributeKey = "postgres.sasl_mechanism"

	// AttrSCRAMIterations is the PBKDF2 iteration count the server named.
	//
	// It is a fact about the target's configuration that nothing else in a run
	// reports, and it carries no identity. It has two consumers: it is what
	// explains a refusal when the count exceeded wire.MaxSCRAMIterations, and it
	// is the only value from which a later rule could say that a server is
	// configured below RFC 7677's recommended floor. Recorded, never acted on.
	AttrSCRAMIterations domain.AttributeKey = "postgres.scram_iterations"
)

// AuthParams carries what one authentication needs beyond the session and the
// credential.
type AuthParams struct {
	// TransportPolicy decides whether the credential may be written to this
	// session's channel.
	//
	// The zero value is security.RequireVerifiedTLS, so a caller that never set
	// it, never parsed it, or never threaded it through requires verified TLS
	// rather than permitting anything. Forgetting must refuse.
	//
	// The adapter obeys this policy and does not own it (ADR 0029).
	TransportPolicy security.CredentialTransportPolicy

	// ExchangeTimeout optionally bounds the exchange, derived from the caller's
	// context. Zero means only the caller's context bounds the work.
	ExchangeTimeout time.Duration
}

func (p AuthParams) validate() error {
	if p.ExchangeTimeout < 0 {
		return fmt.Errorf(
			"%w: exchange timeout %s must not be negative", ErrInvalidInput, p.ExchangeTimeout)
	}
	return nil
}

// Authenticate presents one credential to one endpoint over one connection.
//
// Evidence goes into builder: one L5 node parented to the startup node whose
// connection this continues. The returned AuthenticatedSession owns the
// connection only when authentication passed.
//
// # It takes one StartupResult, and that is the security decision
//
// An authentication attempt is logged, counted, and in directory-backed
// deployments a step towards lockout. So this step takes exactly one connection
// and the asymmetry with discovery is expressed in the type rather than in a
// comment: there is no ordering inside the call that could become a preference,
// no index that could become a selection, and no sessions[0]. Authenticating
// every path is still expressible, as a loop the caller writes, which is a
// visible act rather than a default. See ADR 0028 section 1.
//
// # What must be true before a byte is written
//
// The order below is the contract, and it is the order of the code:
//
//	result.AuthMethod()                        did the peer ask for SASL at all
//	  -> "SCRAM-SHA-256" is advertised         the one mechanism svcdoctor performs
//	  -> result.Channel()                      what this connection proved
//	  -> policy.PermitsCredentials(channel)    may a secret cross it
//	  -> security.NewEndpoint(result)          the logical name, never the address
//	  -> credential.SecretFor(endpoint)        is this credential authorized here
//	  -> wire.AuthenticateSCRAM                the only layer that may reveal
//
// Each step is a precondition for the next. **The two mechanism checks come
// first, and that placement is deliberate**: a peer demanding md5 cannot be
// authenticated to whatever the channel is, so reporting a policy refusal there
// would imply that fixing TLS would help. It also means security.Reveal is never
// reached — and credential.SecretFor is never called — for an endpoint svcdoctor
// cannot authenticate to at all.
//
// # Success is a conjunction
//
// The node passes only when the server's SCRAM signature verified **and**
// AuthenticationOk arrived. Neither alone is enough, and both halves were
// measured: a verifying signature is followed by an ErrorResponse and no
// AuthenticationOk through pgBouncer, and nothing in the protocol obliges a peer
// to prove itself before sending AuthenticationOk. See ADR 0038 section 2.
//
// # Errors
//
// An error means the step could not run: unusable input, a credential bound to a
// different endpoint, or an invariant failure such as a graph that rejected a
// node. Every protocol outcome is evidence, and a recorded non-passing outcome
// returns (nil, nil) — the idiom Negotiate and Startup already use in this
// package.
//
// A credential endpoint mismatch is deliberately in the first category. It is a
// defect in whoever wired the call, not a fact about the target, and an evidence
// node saying "the wrong credential was offered" would be svcdoctor reporting on
// its own caller. See ADR 0028 section 2.
func Authenticate(
	ctx context.Context,
	builder *domain.GraphBuilder,
	result *StartupResult,
	credential security.Credential,
	params AuthParams,
) (*AuthenticatedSession, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if result == nil {
		return nil, fmt.Errorf("%w: startup result must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	// A server that demanded no authentication has nothing for this step to do.
	// Handled before the credential is even looked at, because no credential
	// crosses the wire and the channel policy therefore has no question to
	// answer — which is what keeps `trust` over plaintext diagnosable.
	//
	// **No node is recorded.** svcdoctor presented nothing, so claiming a
	// passing authentication would be an overclaim; the startup node already
	// says postgres.auth_method=ok. See ADR 0038 section 12.
	if result.AuthMethod() == authMethodNone {
		conn, ok := result.TakeConn()
		if !ok {
			return nil, fmt.Errorf("%w: startup result has no connection", ErrInvalidInput)
		}
		return newAuthenticatedSession(conn, result, result.Evidence()), nil
	}

	conn, ok := result.TakeConn()
	if !ok {
		return nil, fmt.Errorf(
			"%w: the startup result has no connection to authenticate over", ErrInvalidInput)
	}

	// From here the connection belongs to this call. Every path below either
	// hands it to the returned session or closes it, and the two are exclusive.
	transferred := false
	defer func() {
		if !transferred {
			_ = conn.Close()
		}
	}()

	// 1. Did the peer ask for something svcdoctor can perform? Asked first, so a
	//    mechanism svcdoctor cannot do never reaches the credential at all.
	if state, failure, ok := admissibleMechanism(result); !ok {
		return nil, recordMechanismRefusal(builder, result, state, failure)
	}

	// 2. Was this run given anything to present?
	//
	// **Second, not first.** A mechanism svcdoctor cannot perform is refused
	// above whatever the run holds, because that refusal is true regardless — so
	// an endpoint demanding `md5` reports the capability gap rather than a
	// missing credential. Everything below is refused *after* this, because with
	// nothing to present the channel policy has no question to answer and there
	// is no endpoint binding to check: the same reasoning the trust branch uses.
	//
	// It was an invocation error until Phase 4.11b, which made the caller
	// responsible for not asking. That put a real diagnostic outcome outside the
	// report: a run against an endpoint demanding SCRAM with no credential
	// configured produced a graph indistinguishable from one cancelled at this
	// exact point, and reported itself healthy. See ADR 0046.
	if credential.IsZero() {
		return nil, recordMissingInput(builder, result)
	}

	// 3. May a credential cross this channel?
	if !params.TransportPolicy.PermitsCredentials(result.Channel()) {
		return nil, recordPolicyRefusal(builder, result)
	}

	// 4. Which endpoint authorizes this credential? The logical name the
	//    operator asked about, never the address it resolved to.
	endpoint, err := logicalEndpoint(result.Endpoint())
	if err != nil {
		return nil, err
	}

	// 5. Is this credential authorized here? A mismatch returns before the wire
	//    package exists in the call stack, so nothing can be revealed.
	secret, err := credential.SecretFor(endpoint)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: credential is not authorized for %s: %w", ErrInvalidInput, endpoint, err)
	}

	observed := observeAuthentication(ctx, conn, secret, params)

	evidence, err := observed.evidence(result)
	if err != nil {
		return nil, err
	}
	if err := record(builder, evidence, result.Evidence()); err != nil {
		return nil, err
	}

	if !observed.passed() {
		// Every non-passing outcome closes. PostgreSQL closes after a FATAL
		// anyway; after a malformed or abandoned exchange the socket's protocol
		// state is unknown; and after a signature svcdoctor refused, the peer is
		// unproven and nothing may continue on it.
		return nil, nil //nolint:nilnil // a recorded non-passing outcome is evidence, not an error; see the doc comment.
	}

	session := newAuthenticatedSession(conn, result, evidence.ID())
	transferred = true
	return session, nil
}

// authMethodNone is the normalized name wire gives AuthenticationOk: a server
// stating that it wants no authentication.
const authMethodNone = "ok"

// authMethodSASL is the normalized name for an AuthenticationSASL message.
const authMethodSASL = "sasl"

// admissibleMechanism decides whether svcdoctor can perform what the peer asked
// for, and says what to record when it cannot.
//
// Two outcomes, and the distinction between them is what a reader acts on.
//
// **The peer demanded something other than SASL**, or advertised a SASL
// mechanism list svcdoctor cannot satisfy while offering SCRAM-SHA-256-PLUS: the
// gap is in svcdoctor. `AUTH_MECHANISM_UNSUPPORTED` with `UNKNOWN`, because
// docs/ARCHITECTURE.md and internal/domain/state.go both require that an
// unsupported capability is not a FAIL — svcdoctor not supporting a mechanism is
// a gap in the tool, not a defect in the target.
//
// **The peer advertised SASL but not SCRAM-SHA-256, and no -PLUS either**: the
// peer positively evidenced that it does not offer what svcdoctor speaks.
// `AUTH_MECHANISM_NOT_OFFERED` with `FAIL`, matching the Kafka handshake's
// treatment of the same fact.
//
// The tie-break matters because a `-PLUS`-only peer is a channel-binding gap in
// svcdoctor rather than a peer that declines SCRAM, and reporting it as
// "not offered" would send a reader to the server's configuration for something
// only svcdoctor can fix.
func admissibleMechanism(result *StartupResult) (domain.State, domain.FailureClass, bool) {
	if result.AuthMethod() != authMethodSASL {
		// md5, cleartext, gss, sspi, kerberos, scm, or a code this repository
		// does not recognize. None is implemented and none ever will be by
		// accident: there is no code in this package that answers any of them.
		return domain.StateUnknown, domain.FailureAuthMechanismUnsupported, false
	}

	var offersPlus bool
	for _, mechanism := range result.SASLMechanisms() {
		if mechanism == wire.MechanismSCRAMSHA256 {
			return domain.StatePass, domain.FailureNone, true
		}
		if mechanism == mechanismSCRAMSHA256Plus {
			offersPlus = true
		}
	}

	if offersPlus {
		return domain.StateUnknown, domain.FailureAuthMechanismUnsupported, false
	}
	return domain.StateFail, domain.FailureAuthMechanismNotOffered, false
}

// mechanismSCRAMSHA256Plus is recognized and never performed.
//
// Channel binding would mean deriving a tls-server-end-point or tls-exporter
// value from the live connection, which is an adapter interrogating a *tls.Conn
// — the capability depguard removed from adapters in Phase 4.2 and the inference
// ADR 0029 exists to prevent. It is named here only to tell a channel-binding
// gap in svcdoctor apart from a peer that does not offer SCRAM at all.
const mechanismSCRAMSHA256Plus = "SCRAM-SHA-256-PLUS"

// logicalEndpoint recovers the endpoint a credential must be bound to from the
// connection's label.
//
// The label is the one transport.Params built with net.JoinHostPort, so
// net.SplitHostPort recovers the same parts, and security.NewEndpoint then
// applies the normalization that makes "DB.Internal." and "db.internal" one
// endpoint.
//
// **The resolved address is never an input here, and that is the whole point.**
// One lookup producing five addresses produces five connections that are all
// still the same authorized endpoint. A credential bound to a concrete
// 10.0.0.1:5432 does not authorize db.internal:5432 even when the name resolves
// to that address, because security.Endpoint compares normalized names and
// resolution is a runtime fact that changes, differs per vantage and can be
// attacker-influenced. DNS therefore cannot widen credential authority, and
// neither can the TLS server name, which is derived from this same label. See
// ADR 0028 section 2.
func logicalEndpoint(label string) (security.Endpoint, error) {
	host, port, err := net.SplitHostPort(label)
	if err != nil {
		return security.Endpoint{}, fmt.Errorf(
			"%w: endpoint %q is not a host:port label: %w", ErrInvalidInput, label, err)
	}

	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return security.Endpoint{}, fmt.Errorf(
			"%w: endpoint %q has no numeric port: %w", ErrInvalidInput, label, err)
	}

	endpoint, err := security.NewEndpoint(host, uint16(number))
	if err != nil {
		return security.Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return endpoint, nil
}

// authObservation is the producer-local record of one authentication exchange.
//
// It holds no secret and no secret-derived value. The wire boundary was handed a
// security.Secret and returned three booleans, an integer and a SQLSTATE;
// nothing that travelled towards the socket travels back.
type authObservation struct {
	scram wire.SCRAM

	// err is what the exchange returned, and ctxErr is what the caller's context
	// reported at the same moment. Both are needed because a deadline that
	// belongs to svcdoctor must never be reported as a claim about the peer.
	err    error
	ctxErr error

	startedAt time.Time
	duration  time.Duration
}

// observeAuthentication performs the exchange and records what happened.
//
// This is the only function here that performs I/O or reads a clock; everything
// after it is a pure transformation. The secret reaches it as a security.Secret
// and goes no further than the wire call: it is not stored on the observation,
// not captured by a closure, and not readable from anything this returns.
func observeAuthentication(
	ctx context.Context, conn net.Conn, secret security.Secret, params AuthParams,
) authObservation {
	exchangeCtx, cancel := stepContext(ctx, params.ExchangeTimeout)
	defer cancel()

	startedAt := time.Now()
	scram, err := wire.AuthenticateSCRAM(exchangeCtx, conn, secret)
	duration := time.Since(startedAt)

	return authObservation{
		scram:     scram,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  duration,
	}
}

// passed reports whether authentication succeeded.
//
// Both halves, explicitly, rather than trusting the absence of an error: the
// signature must have verified and AuthenticationOk must have arrived. Writing
// the conjunction here means a future edit to the wire package that stopped
// returning an error on one of them would fail this check rather than silently
// promote a half-exchange to PASS.
func (o authObservation) passed() bool {
	return o.err == nil && o.scram.Verified && o.scram.Complete
}

// evidence normalizes the observation into the canonical model.
func (o authObservation) evidence(result *StartupResult) (domain.Evidence, error) {
	state, failure := o.classify()

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           authenticationID(target{endpoint: result.endpoint, address: result.address}),
		Subject:      mustSubject(result.address),
		Layer:        domain.LayerAuth,
		Step:         StepAuthentication,
		State:        state,
		FailureClass: failure,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Elapsed:      domain.Measured(o.duration),
	})
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("building %s evidence: %w", StepAuthentication, err)
	}
	return evidence, nil
}

// classify decides what the observation is allowed to claim.
//
// The order is the one every producer in this repository follows: a completed
// exchange is a fact, then the caller's context, then what the peer said, then
// what the wire boundary observed.
func (o authObservation) classify() (domain.State, domain.FailureClass) {
	if o.passed() {
		return domain.StatePass, domain.FailureNone
	}

	switch {
	case errors.Is(o.err, context.Canceled), errors.Is(o.ctxErr, context.Canceled):
		return domain.StateUnknown, domain.FailureExecCancelled
	case errors.Is(o.err, context.DeadlineExceeded), errors.Is(o.ctxErr, context.DeadlineExceeded):
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}

	// Gaps in svcdoctor, not defects in the target. UNKNOWN rather than FAIL,
	// because docs/ARCHITECTURE.md requires that an unsupported capability is
	// never reported as a failure of the thing being inspected.
	switch {
	case errors.Is(o.err, wire.ErrPasswordUnsupported):
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	case errors.Is(o.err, wire.ErrIterationsUnsupported):
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	case errors.Is(o.err, wire.ErrSCRAMParametersUnsupported):
		// The peer's SCRAM message was legal and above svcdoctor's defensive
		// resource ceiling. Same claim as the iteration case above and the same
		// class. Before ADR 0061 this reached PROTOCOL_MALFORMED_RESPONSE via
		// ErrFrameTooLarge, which asserted the peer sent something undecodable
		// — untrue of every value this covers.
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	case errors.Is(o.err, wire.ErrLocalDerivation):
		// svcdoctor's own SCRAM derivation did not produce usable material.
		// Unreachable from this package's call path — the callback is a
		// literal, the exchange is driven linearly, and PBKDF2 is asked for
		// exactly sha256.Size bytes — and classified anyway, because the
		// alternative is that a defect in svcdoctor arrives as an accusation
		// against the target. No new class: this is the same "gap in the tool"
		// vocabulary the two cases above already use.
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	}

	// SCRAM authenticates both parties, so a failure has a direction, and the
	// two directions get different classes. Normalizing them together was this
	// package's own error until Phase 4.6a.5; see ADR 0038 amendment D.
	switch {
	case errors.Is(o.err, wire.ErrServerSignatureMismatch):
		// **svcdoctor refused the peer.** The server's ServerSignature did not
		// equal the one this credential derives, so the peer did not prove it
		// knows the credential.
		//
		// This is only reachable once the peer has *accepted* the client proof
		// — a peer that rejects the proof answers with an error in place of the
		// server-final and never sends a signature at all. So
		// AUTH_CREDENTIALS_REJECTED here would state the opposite of what
		// happened, which is why it no longer does.
		//
		// The class names what was observed and no cause: a peer that does not
		// hold the credential, an intermediary answering in its place, and a
		// defective implementation are indistinguishable from the wire.
		return domain.StateFail, domain.FailureAuthPeerVerificationFailed
	case errors.Is(o.err, wire.ErrSCRAMRejected):
		// **The peer refused svcdoctor.** The server-final carried
		// `e=invalid-proof` or `e=unknown-user`, which is the peer declining
		// the material it was presented — the same claim 28P01 carries below,
		// in SCRAM's vocabulary instead of a SQLSTATE.
		return domain.StateFail, domain.FailureAuthCredentialsRejected
	}

	if !o.scram.Fields.IsZero() {
		return domain.StateFail, authSQLStateFailure(o.scram.Fields.SQLState)
	}

	if isTimeout(o.err) {
		// A deadline nothing identified as the network's is svcdoctor's own.
		return domain.StateUnknown, domain.FailureExecLocalTimeout
	}
	return domain.StateFail, wireFailureClass(o.err)
}

// authSQLStateFailure normalizes an ErrorResponse observed during
// authentication.
//
// Five characters are read and nothing else. **No English message is examined**,
// which is what keeps the claim stable across locales, PostgreSQL versions, and
// the poolers that rewrite the prose entirely — and what keeps a byte the peer
// chose out of the report.
//
// 28P01 means the peer refused the authentication material it was presented, and
// that is the whole of the claim. It does **not** mean the password was wrong,
// that the role exists, that the role does not exist, that an account is
// enabled, or that the peer's authentication backend was healthy. That is not
// caution: a wrong password, an unknown role, a corrupted proof and a correct
// password that needed Unicode preparation produce byte-identical responses on a
// real server — same SQLSTATE, same message template, same source fields.
// PostgreSQL issues a mock salt for a non-existent role deliberately, so a
// client cannot enumerate roles.
//
// 28000 means the peer refused on who is connecting and from where, without
// evaluating any credential — a pg_hba decision, or the channel-binding
// negotiation error a server returns when a client claims a downgrade.
//
// # 08P01 is not mapped, and that is the conservative floor
//
// A pooler collapses every distinction into `08P01`. It is tempting to recover
// the credential case from svcdoctor's own protocol state — "we sent a proof and
// never got a verifying signature, so the peer must have refused it" — and an
// earlier draft of this function did exactly that. **It is not sound, and the
// evidence for that is pgBouncer's own source.**
//
// `disconnect_client()` passes a NULL sqlstate, and pgBouncer substitutes
// `08P01` for it. Its own comment says so: *"PgBouncer used to report SQLSTATE
// 08P01 (protocol_violation) for all cases but it diverges from what Postgres
// reports in some cases."* So `08P01` is the value emitted when there is **no
// specific code** — for a SASL failure, a certificate failure, an unknown user,
// an unconfigured auth database, an unsupported startup parameter, `SSL
// required`, an over-long username, and every `max_client_conn` limit alike.
//
// The protocol position does not narrow it either. In pgBouncer's SCRAM path,
// two conditions send an error after the client-final and before the server-final:
// a proof that did not verify, and a nonce that did not match. The second is a
// protocol fault, not a credential refusal, and nothing on the wire tells them
// apart.
//
// `AUTH_CREDENTIALS_REJECTED` claims *the peer refused the authentication
// material it was presented*. `08P01` proves only that **the exchange ended with
// the peer's generic error code**. Inferring the first from the second is a
// hypothesis about a cause, and a hypothesis over frozen evidence is diagnosis
// work — ADR 0014 — not a producer's to assert.
//
// So `08P01` falls through to the honest weak class. **Nothing is lost that a
// later rule needs**: the code itself is recorded as `postgres.sqlstate`, and
// `postgres.error_is_native` records that the `V` field was absent, which is the
// structural signal that the responder is not a genuine backend. A Phase 4.6
// rule may form a hypothesis from those two facts. This layer does not.
func authSQLStateFailure(sqlState string) domain.FailureClass {
	switch sqlState {
	case "28P01":
		// PostgreSQL's own invalid_password. The peer asserted the refusal;
		// svcdoctor is not inferring it.
		return domain.FailureAuthCredentialsRejected
	case "28000":
		return domain.FailureAuthzNotPermitted
	}
	// A rejection svcdoctor cannot normalize. The code itself is recorded as an
	// attribute, so nothing is lost by declining to name a cause.
	return domain.FailureProtocolUnexpectedResponse
}

// attributes records the facts the exchange yielded.
//
// # What is deliberately absent
//
// The password, the prepared password, the client nonce, the server nonce, the
// salt, the salted password, the client key, the stored key, the client
// signature, the client proof, the server key, the server signature, the auth
// message and the server's SCRAM error token are absent because **no field of
// wire.SCRAM holds any of them**. There is nothing here to filter and nothing a
// future edit could forget to filter.
//
// The role is absent because the startup node already records it as an
// IdentityAttr, and a second copy would be one fact with two representations.
// The server's ErrorResponse message is absent because it never crossed the wire
// boundary: it is deployment-authored prose that routinely names roles,
// databases and svcdoctor's own NAT-translated source address, and evidence has
// no sanitization step for prose.
func (o authObservation) attributes() map[domain.AttributeKey]domain.AttrValue {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		AttrSASLMechanism: domain.StringAttr(wire.MechanismSCRAMSHA256),
	}
	if o.scram.Iterations > 0 {
		attributes[AttrSCRAMIterations] = domain.IntAttr(int64(o.scram.Iterations))
	}
	if o.scram.Fields.SQLState != "" {
		attributes[AttrSQLState] = domain.StringAttr(o.scram.Fields.SQLState)
	}
	if o.scram.Fields.Severity != "" {
		attributes[AttrErrorSeverity] = domain.StringAttr(o.scram.Fields.Severity)
	}
	if !o.scram.Fields.IsZero() {
		attributes[AttrErrorIsNative] = domain.BoolAttr(o.scram.Fields.Native)
	}
	return attributes
}

// recordPolicyRefusal records that a credential was not sent because the policy
// refused this channel.
//
// # It is SKIPPED, not FAIL and not UNKNOWN
//
// Nothing failed and nothing is undetermined in the way an unsupported
// capability is. The step was intentionally not executed because a policy
// prevented it, which is exactly what domain.StateSkipped names and what
// EXEC_SKIPPED_BY_POLICY exists for.
//
// # The blocker is always available here
//
// ADR 0030 had to record a gap for Kafka: on a plaintext path no node anywhere
// in the graph stated that TLS was absent, so a refusal there could point at
// nothing. PostgreSQL closed that gap, because it negotiates encryption in band
// — the postgres.ssl_request node exists on every path and positively records
// whether TLS was attempted. A TLS path points at the handshake node instead.
//
// The absent case is still handled rather than asserted. A fabricated blocker
// would make the report read as though something had been established.
func recordPolicyRefusal(
	builder *domain.GraphBuilder, result *StartupResult,
) error {
	evidence, err := refusalEvidence(
		result, domain.StateSkipped, domain.FailureExecSkippedByPolicy, true)
	if err != nil {
		return err
	}
	if err := record(builder, evidence, result.Evidence()); err != nil {
		return err
	}

	blocker, ok := result.ChannelEvidence()
	if !ok {
		return nil
	}
	if err := builder.AddBlockedBy(evidence.ID(), blocker); err != nil {
		return fmt.Errorf("recording blocked-by for %s: %w", evidence.ID(), err)
	}
	return nil
}

// recordMissingInput records that authentication could not be attempted because
// the run held no material to attempt it with.
//
// # Why SKIPPED rather than FAIL or UNKNOWN
//
// SKIPPED is *"the step was intentionally not executed"*, which is exactly what
// happened: svcdoctor decided not to proceed, deliberately and for a reason it
// can state. FAIL would be a positively evidenced failure, and nothing failed —
// no byte was sent and the peer was never asked. UNKNOWN would say the result
// could not be determined, and it was determined precisely: there was nothing to
// determine it with.
//
// It is the same shape recordPolicyRefusal produces, with a different class,
// because the two are the same *kind* of event — svcdoctor declining to continue
// — for different reasons a reader acts on differently.
//
// # No mechanism attribute
//
// Written with withMechanism false, on recordMechanismRefusal's reasoning:
// svcdoctor selected nothing, so naming SCRAM-SHA-256 would claim a choice it
// never made. What the endpoint *asked for* is on the startup node as
// postgres.auth_method, which is where a rule reads it.
//
// # Nothing about the credential is recorded, because there is nothing
//
// No attribute says a credential was absent, empty or malformed. The class says
// the step lacked a required input and the step says which step it was; anything
// further would be describing a value that does not exist.
func recordMissingInput(builder *domain.GraphBuilder, result *StartupResult) error {
	evidence, err := refusalEvidence(
		result, domain.StateSkipped, domain.FailureExecRequiredInputMissing, false)
	if err != nil {
		return err
	}
	// No blocked-by edge. A policy refusal points at the channel that failed the
	// policy, because a node proves that claim. Nothing in the graph proves an
	// absence, and pointing at the startup node would suggest it caused this.
	return record(builder, evidence, result.Evidence())
}

// recordMechanismRefusal records that no credential was presented because
// svcdoctor cannot perform what the peer asked for, or because the peer does not
// offer what svcdoctor performs.
//
// No mechanism attribute is written: svcdoctor selected none, and the startup
// node already records postgres.auth_method and the advertised list. Naming
// SCRAM-SHA-256 here would claim a choice that was never made.
func recordMechanismRefusal(
	builder *domain.GraphBuilder,
	result *StartupResult,
	state domain.State,
	failure domain.FailureClass,
) error {
	evidence, err := refusalEvidence(result, state, failure, false)
	if err != nil {
		return err
	}
	return record(builder, evidence, result.Evidence())
}

// refusalEvidence builds the node for an authentication that was not attempted.
//
// Its attributes are only what is true when nothing was sent. There is no error
// code, no SQLSTATE and no iteration count, because each of those would assert
// that an exchange happened and was answered.
func refusalEvidence(
	result *StartupResult,
	state domain.State,
	failure domain.FailureClass,
	withMechanism bool,
) (domain.Evidence, error) {
	attributes := map[domain.AttributeKey]domain.AttrValue{}
	if withMechanism {
		attributes[AttrSASLMechanism] = domain.StringAttr(wire.MechanismSCRAMSHA256)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           authenticationID(target{endpoint: result.endpoint, address: result.address}),
		Subject:      mustSubject(result.address),
		Layer:        domain.LayerAuth,
		Step:         StepAuthentication,
		State:        state,
		FailureClass: failure,
		Attributes:   attributes,
		StartedAt:    time.Now(),
		Elapsed:      domain.Unmeasured(),
	})
	if err != nil {
		return domain.Evidence{}, fmt.Errorf(
			"building unattempted %s evidence: %w", StepAuthentication, err)
	}
	return evidence, nil
}

// authenticationID mints the identifier of the authentication node.
//
// Two components, matching every other step in this package. Neither the role
// nor the database appears: an identifier is bookkeeping, and logical identity
// does not enter one merely to make it unique.
func authenticationID(t target) domain.EvidenceID {
	return probe.ScopedEvidenceID(t.scope, StepAuthentication, t.endpoint, t.address.Addr().String())
}

// isTimeout reports whether err is a network timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
