package kafka

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// StepSASLAuthenticate names the operation this step performs.
//
// It is exported for the reason the two steps before it are: the string appears
// in every report and will be matched by automation.
const StepSASLAuthenticate = servicekafka.StepSASLAuthenticate

// The attributes authentication records. They live here for the reason given on
// the ApiVersions keys, and they will move with those when the first Kafka
// diagnosis rule needs them.
const (
	// AttrSASLMechanism is the mechanism this authentication used.
	//
	// It is a separate key from kafka.sasl.requested_mechanism, which means
	// what svcdoctor *asked about* at the handshake. Here the mechanism is
	// settled: it is the one the broker agreed to, carried on the session, and
	// it is what an error code on this node has to be read against. One key,
	// one meaning.
	AttrSASLMechanism = servicekafka.AttrSASLMechanism

	// AttrSASLSessionLifetimeMs is how long the broker considers this
	// authentication valid, in milliseconds, as the broker stated it.
	//
	// Zero is a statement rather than an absence — Kafka uses it for "no
	// expiry" — so it is recorded whenever the exchange completed, exactly as
	// the error code is. svcdoctor does not act on it; a client that
	// re-authenticated when it elapsed would be the client behaviour ADR 0008
	// keeps out of the measured path.
	AttrSASLSessionLifetimeMs domain.AttributeKey = "kafka.sasl.session_lifetime_ms"
)

// errorCodeSASLAuthenticationFailed is Kafka's SASL_AUTHENTICATION_FAILED.
//
// It is the one code this step normalizes beyond the shared mapping, under the
// test the two steps before it use: **the response must prove the generic fact
// by itself.** On a SaslAuthenticate response it means the broker refused the
// authentication material it was presented, which is what
// AUTH_CREDENTIALS_REJECTED says — and it means nothing further. Kafka returns
// this one code for an unknown principal, a wrong secret, a disabled account and
// a failing authentication backend alike, and its own error message is
// deliberately generic so that a client cannot tell which. So the code proves a
// refusal happened; it proves nothing about why.
//
// It exists because of KIP-152, which added it so that a rejected credential
// arrives as an error code instead of a closed socket — the same ambiguity ADR
// 0008 requires svcdoctor to avoid, resolved by the protocol itself.
const errorCodeSASLAuthenticationFailed int16 = 58

// AuthParams carries what one authentication needs beyond the session and the
// credential.
type AuthParams struct {
	// TransportPolicy decides whether the credential may be written to this
	// session's channel.
	//
	// The zero value is security.RequireVerifiedTLS, so a caller that never set
	// it, never parsed it, or never threaded it through requires verified TLS
	// rather than permitting anything. That is the whole reason the field is a
	// value rather than a pointer or a bool: forgetting it must refuse.
	//
	// The adapter obeys this policy and does not own it. Choosing one belongs
	// to whoever configures a run, and today exactly one value exists (ADR
	// 0029).
	TransportPolicy security.CredentialTransportPolicy

	// ExchangeTimeout optionally bounds the exchange, derived from the caller's
	// context. Zero means only the caller's context bounds the work.
	ExchangeTimeout time.Duration
}

// validate rejects input the step cannot turn into a meaningful exchange.
func (p AuthParams) validate() error {
	if p.ExchangeTimeout < 0 {
		return fmt.Errorf(
			"%w: exchange timeout %s must not be negative", ErrInvalidInput, p.ExchangeTimeout)
	}
	return nil
}

// Authenticate presents one credential to one broker over one session.
//
// Evidence goes into builder: one L5 node, parented to the SaslHandshake node
// whose connection this continues. The returned AuthResult owns the connection
// only when the broker accepted the credential.
//
// # It takes one session, and that is the security decision
//
// The two steps before it take a slice, ask every path and choose none, because
// discovery costs the target nothing. An authentication attempt is logged,
// counted, and in directory-backed deployments a step towards lockout, so this
// step takes exactly one session and the asymmetry is expressed in the type
// rather than in a comment.
//
// With one session per call there is no ordering inside the call that could
// become a preference, no index that could become a selection, and no
// sessions[0] — which would silently mean IPv4, since canonical address ordering
// puts it first. Authenticating every path is still expressible, as a loop the
// caller writes, which is a visible act rather than a default. **Selection is
// the caller's, and this function cannot make one.** See ADR 0028 section 1.
//
// # What must be true before a byte is written
//
// The order below is the contract, and it is the order of the code:
//
//	session.Mechanism()                        what the broker agreed to
//	  -> supportedMechanism(mechanism)         can svcdoctor perform it at all
//	  -> credential.IsZero()                   was this run given anything
//	  -> policy.PermitsCredentials(channel)    may a secret cross this channel
//	  -> security.NewEndpoint(session)         the logical name, never the address
//	  -> credential.SecretFor(endpoint)        is this credential authorized here
//	  -> wire.Authenticate                     the only layer that may reveal
//
// Each step is a precondition for the next. A mechanism svcdoctor cannot perform
// ends the call before the credential is looked at; a run holding no credential
// ends it before a channel or an endpoint is even considered; a channel the
// policy refuses ends it before an endpoint is parsed; a credential bound
// elsewhere ends it before the wire package is called. Nothing is revealed in
// any of those paths, because nothing reaches the only function that can reveal.
//
// The first four steps each record their own node and return normally. They are
// diagnostic outcomes, not invocation failures, and every one of them is a fact
// about this run or this broker that an operator has to see.
//
// # Errors
//
// An error means the step could not run: unusable input, a credential bound to
// a different endpoint, or an invariant failure such as a graph that rejected a
// node. Every protocol outcome is evidence.
//
// A credential endpoint mismatch is deliberately in the first category. It is a
// defect in whoever wired the call, not a fact about the target, and an evidence
// node saying "the wrong credential was offered" would be svcdoctor reporting on
// its own caller. See ADR 0028 section 2.
//
// # Ownership on a local invocation failure
//
// Authenticate consumes the session in every outcome, including the ones that
// send nothing. A mismatch is caught before any SaslAuthenticate byte is
// written, so the socket is left exactly as the handshake left it: the broker is
// waiting for that mechanism's SaslAuthenticate, and a corrected credential
// would be a legal next message on it.
//
// **The connection is closed anyway, and Kafka is not the reason.** It is closed
// because this function is a consuming ownership boundary: it takes the
// connection before it validates, so returning the pre-authenticated session on
// one error path would give ownership two exits, make retry semantics depend on
// which error was returned, and hand back a live socket already bound to a
// credential the caller got wrong. A caller that wants to retry re-runs the
// chain, which re-measures what it is about to authenticate over. See ADR 0030
// section 10.
func Authenticate(
	ctx context.Context,
	builder *domain.GraphBuilder,
	session *HandshakeSession,
	credential security.Credential,
	params AuthParams,
) (*AuthResult, error) {
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

	conn, ok := session.TakeConn()
	if !ok {
		return nil, fmt.Errorf(
			"%w: the session has no connection to authenticate over", ErrInvalidInput)
	}

	// From here the connection belongs to this call. Every path below either
	// hands it to the AuthResult or closes it, and the two are exclusive.
	result := &AuthResult{}
	transferred := false
	defer func() {
		if !transferred {
			_ = conn.Close()
		}
	}()

	// 0. Can svcdoctor perform the mechanism the broker agreed to? Asked before
	//    anything else, because every later step reasons about a credential and
	//    none of that reasoning is meaningful for an exchange this package
	//    cannot frame.
	if !supportedMechanism(session.Mechanism()) {
		if err := recordUnsupportedMechanism(builder, session, result); err != nil {
			return nil, err
		}
		return result, nil
	}

	// 1. Was this run given anything to present?
	//
	// **Second, not first.** A mechanism svcdoctor cannot perform is refused
	// above whatever the run holds, because that refusal is true regardless: a
	// broker demanding SCRAM-SHA-256 reports the capability gap rather than a
	// missing credential, since supplying one would change nothing.
	//
	// Everything below is decided *after* this, because with nothing to present
	// the channel policy has no question to answer and there is no endpoint
	// binding to check. A policy refusal means *a credential existed and was
	// deliberately not sent*; saying that when none exists would send an
	// operator to fix TLS for a run that would still have nothing to offer.
	//
	// It was an invocation error until Phase 6.1c-P1, which made the caller
	// responsible for not asking. That put a real diagnostic outcome outside the
	// report: a run against a broker demanding PLAIN with no credential
	// configured produced no authentication node at all, indistinguishable from
	// a run cancelled at this exact point. See ADR 0046 for the same reasoning
	// in internal/adapter/postgres, whose shape this follows.
	if credential.IsZero() {
		if err := recordMissingInput(builder, session, result); err != nil {
			return nil, err
		}
		return result, nil
	}

	// 2. May a credential cross this channel at all? A refused channel never
	//    reaches the code that handles a secret.
	if !params.TransportPolicy.PermitsCredentials(session.Channel()) {
		if err := recordRefusal(builder, session, result); err != nil {
			return nil, err
		}
		return result, nil
	}

	// 3. Which endpoint authorizes this credential? The logical name the
	//    operator asked about, never the address it resolved to.
	endpoint, err := logicalEndpoint(session)
	if err != nil {
		return nil, err
	}

	// 4. Is this credential authorized here? A mismatch returns before the wire
	//    package exists in the call stack.
	secret, err := credential.SecretFor(endpoint)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: credential is not authorized for %s: %w", ErrInvalidInput, endpoint, err)
	}

	observed := observeAuthentication(
		ctx, conn, session.Mechanism(), credential.Identity(), secret, params)

	evidence, err := observed.evidence(session)
	if err != nil {
		return nil, err
	}
	if err := record(builder, evidence, session.Evidence()); err != nil {
		return nil, err
	}
	result.evidenceID = evidence.ID()

	// Only an accepted credential leaves a socket with a defined continuation,
	// and the criterion is the protocol's rather than the recorded state's.
	//
	// A rejected credential is the clearest case: Kafka fails the connection
	// after SASL_AUTHENTICATION_FAILED, so there is nothing to inherit. A
	// broken or unreadable exchange leaves a socket whose protocol state nobody
	// knows. An expired budget leaves a request possibly in flight and a
	// response possibly unread, so the next reader would decode the wrong
	// bytes; that is why UNKNOWN closes too, even though nothing is known to be
	// wrong with the peer.
	//
	// This is not "FAIL closes the connection". The ApiVersions step keeps a
	// connection whose broker answered with an error code, because any request
	// may still follow it, and that difference is what
	// TestConnectionLifetimeIsNotDrivenByAuthEvidenceState holds apart — as its
	// sibling does for the handshake.
	if !observed.accepted() {
		return result, nil
	}

	result.authenticated(conn, session, evidence.ID())
	transferred = true
	return result, nil
}

// logicalEndpoint recovers the endpoint a credential must be bound to from the
// session's label.
//
// The label is the one transport.Params built with net.JoinHostPort, so
// net.SplitHostPort recovers the same parts, and security.NewEndpoint then
// applies the normalization that makes "KAFKA.Internal." and "kafka.internal"
// one endpoint.
//
// **The resolved address is never an input here, and that is the whole point.**
// One lookup producing five addresses produces five sessions that are all still
// the same authorized endpoint, so a credential works on every one of them. A
// credential bound to a concrete 10.0.0.1:9092 does not authorize
// primary.internal:9092 even when the name resolves to that address, because
// security.Endpoint compares normalized names and resolution is a runtime fact
// that changes, differs per vantage and can be attacker-influenced. DNS
// therefore cannot widen credential authority. See ADR 0028 section 2.
func logicalEndpoint(session *HandshakeSession) (security.Endpoint, error) {
	host, port, err := net.SplitHostPort(session.Endpoint())
	if err != nil {
		return security.Endpoint{}, fmt.Errorf(
			"%w: session endpoint %q is not a host:port label: %w",
			ErrInvalidInput, session.Endpoint(), err)
	}

	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return security.Endpoint{}, fmt.Errorf(
			"%w: session endpoint %q has no numeric port: %w",
			ErrInvalidInput, session.Endpoint(), err)
	}

	endpoint, err := security.NewEndpoint(host, uint16(number))
	if err != nil {
		return security.Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return endpoint, nil
}

// supportedMechanism reports whether this package can perform the mechanism the
// broker agreed to.
//
// # It is a whitelist, and that is the security property
//
// Exactly one mechanism has an exchange in internal/adapter/kafka/wire, so
// exactly one is supported. Every other name — SCRAM-SHA-256, SCRAM-SHA-512,
// OAUTHBEARER, GSSAPI, AWS_MSK_IAM, and anything a future broker invents — is
// unsupported, and an unknown name is unsupported for the same reason rather
// than by a separate rule.
//
// The comparison is exact. Kafka mechanism names are drawn from the SASL
// registry and brokers send them verbatim; case-folding or trimming here would
// let a name svcdoctor did not recognize reach a framing built for a different
// one, which is the whole failure this function exists to make impossible.
//
// **Nothing here falls back.** A mechanism outside the set does not become one
// inside it, is not retried as another, and is not approximated. Kafka's SASL
// mechanisms differ in their message framing, not only in their cryptography, so
// sending PLAIN's three NUL-separated fields into a SCRAM exchange would put the
// identity and the password on the wire in a shape the peer never agreed to
// receive. That is what this predicate prevents, and it is the defect Phase 6.1a
// found and fixed.
//
// Phase 6.2 added the second entry. **Two supported mechanisms is not a menu**:
// the broker names one during the handshake and this decides only whether
// svcdoctor can perform *that* one. A SCRAM-SHA-256 failure never becomes a
// PLAIN attempt and a PLAIN failure never becomes a SCRAM attempt, because there
// is one negotiated mechanism per session and one attempt per run.
//
// SCRAM-SHA-512 is still unsupported, and so are OAUTHBEARER, GSSAPI and
// AWS_MSK_IAM. Each is absent because no exchange in
// internal/adapter/kafka/wire performs it — which is the invariant
// TestSupportedMechanismsHaveExchanges pins in both directions.
func supportedMechanism(mechanism string) bool {
	return mechanism == wire.MechanismPLAIN || mechanism == wire.MechanismSCRAMSHA256
}

// recordUnsupportedMechanism records that svcdoctor could not perform the
// mechanism this session negotiated.
//
// # It is UNKNOWN, and the class is a capability class
//
// The peer did nothing wrong. It offered a mechanism, agreed to the one it was
// asked about, and is waiting for a message svcdoctor cannot construct. Nothing
// was presented, so nothing was accepted or refused, and the credential's
// validity is exactly as unknown afterwards as before. `UNKNOWN` +
// `AUTH_MECHANISM_UNSUPPORTED` says that and stops, which is the same shape
// internal/adapter/postgres records for md5, cleartext and SCRAM-SHA-256-PLUS.
//
// `FAIL` would assert an observation of the target that was never made.
// `AUTH_MECHANISM_NOT_OFFERED` is the opposite direction — a peer that does not
// offer what was asked for — and belongs to the handshake step, which already
// produces it. `AUTH_CREDENTIALS_REJECTED` would accuse a credential nobody
// evaluated. `SKIPPED` + `EXEC_SKIPPED_BY_POLICY` is the channel refusal beside
// it, and reads as *"a policy declined"* rather than *"svcdoctor cannot do
// this"*; the two lead to different actions and ADR 0030 keeps them apart.
//
// # It is a node, not silence
//
// An absent node is indistinguishable from a step nobody requested. The record
// says the run reached the point of authenticating, found a mechanism it could
// not perform, and sent nothing.
//
// # No blocker edge
//
// A `BlockedBy` edge points at the evidence that made a step impossible. Nothing
// in the graph did: the limitation is svcdoctor's own, and the handshake node
// above passed. Pointing at it would read as though the broker had obstructed
// something. The refusal beside this one carries a blocker precisely because
// there a TLS node proves the channel insufficient.
//
// # Attributes
//
// Only the mechanism, for the reason refusalEvidence records only the mechanism:
// it is a protocol fact drawn from a public registry, it is already on the
// handshake node, and every other attribute of this step would assert that a
// request was made and answered. Nothing credential-derived exists here to
// record — this function never receives a credential.
func recordUnsupportedMechanism(
	builder *domain.GraphBuilder, session *HandshakeSession, result *AuthResult,
) error {
	evidence, err := unsupportedMechanismEvidence(session)
	if err != nil {
		return err
	}
	if err := record(builder, evidence, session.Evidence()); err != nil {
		return err
	}
	result.evidenceID = evidence.ID()
	return nil
}

// unsupportedMechanismEvidence builds the node for an authentication svcdoctor
// declined to attempt.
//
// The duration is zero because nothing was attempted: no request was framed, no
// byte was written and no clock was waited on. That is the same value
// refusalEvidence records for the same reason.
func unsupportedMechanismEvidence(session *HandshakeSession) (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(session.Address().String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			StepSASLAuthenticate, session.Endpoint(), session.Address().Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         StepSASLAuthenticate,
		State:        domain.StateUnknown,
		FailureClass: domain.FailureAuthMechanismUnsupported,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			AttrSASLMechanism: domain.StringAttr(session.Mechanism()),
		},
		StartedAt: time.Now(),
		Elapsed:   domain.Unmeasured(),
	})
	if err != nil {
		return domain.Evidence{}, fmt.Errorf(
			"building unsupported-mechanism %s evidence: %w", StepSASLAuthenticate, err)
	}
	return evidence, nil
}

// recordMissingInput records that the broker required an authentication
// svcdoctor can perform, and the run held nothing to present.
//
// # It is SKIPPED, and the class is an execution class
//
// The exchange was intentionally not executed, so `SKIPPED` is the state:
// nothing was attempted and nothing is uncertain about why. `FAIL` would assert
// that the peer rejected something, and the peer was never asked.
// `UNKNOWN` would claim doubt about a cause that is fully known — the run was
// not given a credential. `AUTH_CREDENTIALS_REJECTED` would accuse a credential
// that does not exist.
//
// The class is `EXEC_REQUIRED_INPUT_MISSING`, whose contract is exactly this:
// the step could not run because a required input for it was not supplied to the
// run. The gap is in the invocation, not in the target and not in svcdoctor's
// capabilities.
//
// # Why it is not the refusal beside it
//
// `EXEC_SKIPPED_BY_POLICY` means *a credential existed and svcdoctor declined to
// send it over this channel*. That reads as "establish verified TLS and this
// will work", which is false here: with nothing configured, the run would still
// have nothing to offer over a perfect channel. recordRefusal keeps that
// meaning, and this function keeps the other; ADR 0030 requires the two stay
// apart, and the ordering in Authenticate is what enforces it.
//
// # Why it is not the mechanism gap above it
//
// `AUTH_MECHANISM_UNSUPPORTED` is decided first and wins, because it is true
// regardless of what the run holds. See Authenticate's step 1.
//
// # It is a node, not silence
//
// An absent node is indistinguishable from a step nobody requested. Until
// Phase 6.1c-P1 this path returned an invocation error, so a run that reached
// authentication with no credential configured produced no authentication node
// at all and a graph that read as though the step had never come up.
//
// # No blocker edge
//
// A `BlockedBy` edge points at the evidence that made a step impossible. Nothing
// in the graph did: the missing input is the run's own, and the handshake node
// above passed. The refusal beside this one carries a blocker precisely because
// there a TLS node proves the channel insufficient.
//
// # Attributes
//
// Only the mechanism, for the reason unsupportedMechanismEvidence records only
// the mechanism: it is a protocol fact from a public registry, already on the
// handshake node, and naming it says which authentication went unattempted.
// Nothing credential-derived exists to record — this function receives no
// credential, and a length or an "empty password" string would describe a secret
// that was never supplied.
func recordMissingInput(
	builder *domain.GraphBuilder, session *HandshakeSession, result *AuthResult,
) error {
	evidence, err := missingInputEvidence(session)
	if err != nil {
		return err
	}
	if err := record(builder, evidence, session.Evidence()); err != nil {
		return err
	}
	result.evidenceID = evidence.ID()
	return nil
}

// missingInputEvidence builds the node for an authentication the run had no
// credential for.
//
// The duration is zero because nothing was attempted: no request was framed, no
// byte was written and no clock was waited on. That is the same value
// unsupportedMechanismEvidence and refusalEvidence record for the same reason.
func missingInputEvidence(session *HandshakeSession) (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(session.Address().String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			StepSASLAuthenticate, session.Endpoint(), session.Address().Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         StepSASLAuthenticate,
		State:        domain.StateSkipped,
		FailureClass: domain.FailureExecRequiredInputMissing,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			AttrSASLMechanism: domain.StringAttr(session.Mechanism()),
		},
		StartedAt: time.Now(),
		Elapsed:   domain.Unmeasured(),
	})
	if err != nil {
		return domain.Evidence{}, fmt.Errorf(
			"building missing-input %s evidence: %w", StepSASLAuthenticate, err)
	}
	return evidence, nil
}

// recordRefusal records that a credential was not sent because the policy
// refused this channel.
//
// # It is SKIPPED, not FAIL
//
// Nothing failed. The target was never asked, so there is no observation of it
// to fail, and reporting one would be svcdoctor inventing a result for an
// exchange that did not happen. EXEC_SKIPPED_BY_POLICY exists for exactly this
// and predates the policy that uses it.
//
// # It is a node, not silence
//
// An absent node is indistinguishable from a step nobody requested. The refusal
// is a fact a reader needs: it says the run reached the point of authenticating,
// declined, and why.
//
// # The blocker is the fact, or there is none
//
// When a TLS handshake classified the channel, its node is what proves the
// channel insufficient — it carries tls.verified = false — and the refusal
// points at it. On a plaintext path there is no such node anywhere in the graph:
// the channel is plaintext because no TLS was asked for, and nothing recorded
// "TLS is absent here". So the refusal carries no blocker rather than pointing
// at the TCP node, which passed and says nothing about encryption. A fabricated
// blocker would make the report read as though something had been established.
// See ADR 0030.
func recordRefusal(
	builder *domain.GraphBuilder, session *HandshakeSession, result *AuthResult,
) error {
	evidence, err := refusalEvidence(session)
	if err != nil {
		return err
	}
	if err := record(builder, evidence, session.Evidence()); err != nil {
		return err
	}
	result.evidenceID = evidence.ID()

	blocker, ok := session.ChannelEvidence()
	if !ok {
		return nil
	}
	if err := builder.AddBlockedBy(evidence.ID(), blocker); err != nil {
		return fmt.Errorf("recording blocked-by for %s: %w", evidence.ID(), err)
	}
	return nil
}

// refusalEvidence builds the node for an authentication that was not attempted.
//
// Its attributes are only what is true when nothing was sent. The mechanism is
// one: the broker agreed to it at the handshake, so naming it says which
// authentication was skipped. The request version, the error code and the
// session lifetime are not, because each of them would assert that a request was
// made and answered.
func refusalEvidence(session *HandshakeSession) (domain.Evidence, error) {
	subject, err := domain.NewEndpointSubject(session.Address().String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			StepSASLAuthenticate, session.Endpoint(), session.Address().Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         StepSASLAuthenticate,
		State:        domain.StateSkipped,
		FailureClass: domain.FailureExecSkippedByPolicy,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			AttrSASLMechanism: domain.StringAttr(session.Mechanism()),
		},
		StartedAt: time.Now(),
		Elapsed:   domain.Unmeasured(),
	})
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("building skipped %s evidence: %w", StepSASLAuthenticate, err)
	}
	return evidence, nil
}

// authObservation is the producer-local record of one authentication exchange.
//
// It holds no secret and no secret-derived value. The wire boundary was handed
// a security.Secret and returned an error code and a duration; nothing that
// travelled towards the socket travels back.
type authObservation struct {
	response wire.SASLAuthenticate

	// err is what the exchange returned, and ctxErr is what the caller's
	// context reported at the same moment. Both are needed for the reason every
	// probe needs them: a deadline that belongs to svcdoctor must never be
	// reported as a claim about the peer.
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
	ctx context.Context,
	conn net.Conn,
	mechanism string,
	identity string,
	secret security.Secret,
	params AuthParams,
) authObservation {
	exchangeCtx := ctx
	if params.ExchangeTimeout > 0 {
		var cancel context.CancelFunc
		exchangeCtx, cancel = context.WithTimeout(ctx, params.ExchangeTimeout)
		defer cancel()
	}

	startedAt := time.Now()
	response, err := wire.Authenticate(exchangeCtx, conn, mechanism, identity, secret)
	duration := time.Since(startedAt)

	return authObservation{
		response:  response,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  duration,
	}
}

// accepted reports whether the broker accepted the credential.
func (o authObservation) accepted() bool {
	return o.err == nil && o.response.ErrorCode == 0
}

// evidence normalizes the observation into the canonical model.
//
// The subject is the concrete peer, matching the transport, ApiVersions and
// handshake nodes for the same path, so a reader can follow one address from L1
// to L5.
func (o authObservation) evidence(session *HandshakeSession) (domain.Evidence, error) {
	address := session.Address()

	subject, err := domain.NewEndpointSubject(address.String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			StepSASLAuthenticate, session.Endpoint(), address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         StepSASLAuthenticate,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(session.Mechanism()),
		StartedAt:    o.startedAt,
		Elapsed:      domain.Measured(o.duration),
	})
}

// classify decides what the observation is allowed to claim.
//
// The order of the checks is the contract every producer here follows: a
// completed exchange is a fact, then the caller's context, then what the wire
// boundary observed.
func (o authObservation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		if o.response.ErrorCode != 0 {
			return domain.StateFail, authenticationFailure(o.response.ErrorCode)
		}
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
	// never reported as a failure of the thing being inspected. Decided before
	// the peer-side classes below, so that a run svcdoctor could not perform is
	// never described as a run the broker refused.
	switch {
	case errors.Is(o.err, wire.ErrSCRAMUsernameUnsupported),
		errors.Is(o.err, wire.ErrSCRAMPasswordUnsupported):
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	case errors.Is(o.err, wire.ErrSCRAMIterationsUnsupported):
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	case errors.Is(o.err, wire.ErrSCRAMParametersUnsupported):
		// The broker's SCRAM message was legal and above svcdoctor's defensive
		// resource ceiling. Same claim as the iteration case above and the same
		// class: a gap in svcdoctor, never a defect in the cluster. Before
		// ADR 0061 this reached PROTOCOL_MALFORMED_RESPONSE, which said the
		// broker sent something it could not decode — untrue of every value
		// this covers.
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	case errors.Is(o.err, wire.ErrSCRAMLocalDerivation):
		return domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor
	}

	// SCRAM authenticates both parties, so a failure has a direction and the two
	// directions get different classes. Normalizing them together was the
	// PostgreSQL adapter's own error until Phase 4.6a.5; see ADR 0038 amendment
	// D, whose reasoning this follows exactly.
	switch {
	case errors.Is(o.err, wire.ErrSCRAMServerSignatureMismatch):
		// **svcdoctor refused the peer.** The broker's ServerSignature did not
		// equal the one this credential derives, so it did not prove it knows
		// the credential. Only reachable once the broker has *accepted* the
		// client proof, so AUTH_CREDENTIALS_REJECTED here would state the
		// opposite of what happened.
		return domain.StateFail, domain.FailureAuthPeerVerificationFailed
	case errors.Is(o.err, wire.ErrSCRAMRejected):
		// **The peer refused svcdoctor.** The server-final carried
		// `e=invalid-proof` or `e=unknown-user`, which is the broker declining
		// the material it was presented — the same claim
		// SASL_AUTHENTICATION_FAILED carries, in SCRAM's vocabulary instead of
		// an error code.
		return domain.StateFail, domain.FailureAuthCredentialsRejected
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

// authenticationFailure normalizes a broker error code from an authentication
// response.
//
// One code more than the handshake's mapping is translated, under the same test:
// SASL_AUTHENTICATION_FAILED means the broker refused the authentication
// material it was presented, which is what AUTH_CREDENTIALS_REJECTED says and
// nothing more.
//
// **It is authentication, never authorization.** AUTHZ_DENIED means an identity
// authenticated and was then refused an operation, and this exchange performs no
// operation to be refused.
//
// **And it is a refusal, not a cause.** Kafka answers with this one code for a
// wrong secret, an unknown principal, a disabled or locked account, and an
// authentication backend that failed while answering. Its error message is
// deliberately generic for the first two so that a client cannot probe which,
// and svcdoctor does not read that message anyway. The class therefore carries
// no claim that the secret was wrong, that the principal exists or does not, or
// that the peer's authentication backend was healthy. Which of those is true is
// a hypothesis over frozen evidence, and belongs to diagnosis.
//
// Everything else delegates to the handshake's mapping, so UNSUPPORTED_VERSION
// stays PROTOCOL_UNSUPPORTED_VERSION and UNSUPPORTED_SASL_MECHANISM stays the
// peer-side AUTH_MECHANISM_NOT_OFFERED. Both remain true on this response: the
// codes describe the broker's position, not which request carried them.
// ILLEGAL_SASL_STATE stays unmapped for the reason ADR 0026 gives — two causes
// behind one code prove no single generic fact.
//
// No Kafka-specific class is added to internal/domain, and no error text is
// parsed. The code itself is on the node as kafka.error_code, which is where a
// reader who needs the exact Kafka meaning gets it.
func authenticationFailure(code int16) domain.FailureClass {
	if code == errorCodeSASLAuthenticationFailed {
		return domain.FailureAuthCredentialsRejected
	}
	return handshakeFailure(code)
}

// attributes records the facts the exchange yielded.
//
// # What is deliberately absent
//
// The password, its length, the payload, the authorization identity and the raw
// response are absent because no field of this step ever holds them: the wire
// boundary was given a security.Secret and returned two integers.
//
// The broker's ErrorMessage is absent because it never crossed the wire
// boundary. It is deployment-authored prose that routinely names principals,
// listeners and internal hosts, and evidence has no sanitization step for prose.
//
// **The authenticating identity is absent, and that is a decision rather than an
// oversight.** A username is real deployment identity, and redaction's declared
// kinds cover hosts and addresses only (ADR 0022), so recording it as a plain
// string would put an unpseudonymizable principal into a report meant to be
// shareable. Nothing today reads it. Reopen when a diagnosis rule needs to tell
// two identities apart, at which point it needs a declared identity-bearing
// attribute kind first. See ADR 0030.
func (o authObservation) attributes(mechanism string) map[domain.AttributeKey]domain.AttrValue {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		AttrSASLMechanism:     domain.StringAttr(mechanism),
		AttrRequestAPIVersion: domain.IntAttr(int64(wire.SASLAuthenticateVersion())),
	}
	if o.err == nil {
		attributes[AttrErrorCode] = domain.IntAttr(int64(o.response.ErrorCode))
		attributes[AttrSASLSessionLifetimeMs] = domain.IntAttr(o.response.SessionLifetimeMillis)
	}
	return attributes
}
