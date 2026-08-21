package kafka

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// StepAPIVersions names the operation this adapter performs.
//
// It is exported because it is part of the report contract: the same string
// appears in every report and will be matched by automation.
const StepAPIVersions domain.Step = "kafka.api_versions"

// The attributes this adapter records.
//
// # Where these keys live
//
// They live here, with the code that produces them, and that is deliberate. A
// future rule in internal/diagnosis/kafka will need them and cannot import this
// package — depguard forbids diagnosis importing an adapter — so the keys will
// have to move to a leaf both can import, most likely internal/service/kafka.
//
// That package is not created yet because it would have exactly one consumer
// today, and a shared vocabulary invented before its second consumer exists is a
// guess about what the second consumer needs. The move is mechanical when the
// first Kafka rule is written. See docs/BACKLOG.md.
const (
	// AttrAPIVersions lists what the broker advertised, one API key per entry,
	// formatted "<key>:<min>-<max>" and sorted by key.
	//
	// One node with one list rather than a node per API key: a broker advertises
	// seventy of them, and seventy nodes per path would bury the transport
	// evidence in a report whose point is the transport evidence. The entries
	// carry no identity and need no redaction.
	//
	// API names are deliberately absent. The key number is what the broker sent;
	// a name is svcdoctor's local table and belongs to whatever renders the
	// report, not to the fact.
	AttrAPIVersions domain.AttributeKey = "kafka.api_versions"

	// AttrErrorCode is the broker's own error code for the exchange, always
	// recorded, because zero is a statement rather than an absence.
	AttrErrorCode domain.AttributeKey = "kafka.error_code"

	// AttrRequestAPIVersion is the version of ApiVersions svcdoctor asked for.
	// Without it an error code cannot be interpreted: the request is half of
	// what produced the answer.
	AttrRequestAPIVersion domain.AttributeKey = "kafka.request_api_version"
)

// errorCodeUnsupportedVersion is Kafka's UNSUPPORTED_VERSION.
//
// It is the only ApiVersions error code this package normalizes, because it is
// the only one whose meaning the protocol fixes exactly: the broker does not
// support the version of the request it was sent. Kafka error codes are a
// permanent numeric registry, so the number is as stable as the protocol.
//
// It stays unexported. The code itself reaches a report as the kafka.error_code
// attribute; this constant is only how the classification recognizes it.
const errorCodeUnsupportedVersion int16 = 35

// errorCodeUnsupportedSASLMechanism is Kafka's UNSUPPORTED_SASL_MECHANISM.
//
// It is the second and last code this adapter normalizes, and it earns that for
// the same narrow reason as the first: on a SaslHandshake response it means the
// broker does not offer the mechanism that was named, and nothing else. See
// handshakeFailure.
const errorCodeUnsupportedSASLMechanism int16 = 33

// ErrInvalidInput reports that the adapter was called with something it cannot
// use.
//
// It is the only error class this package returns. A broker that answers with an
// error, a peer that turns out not to speak Kafka, an exchange cut short by the
// caller's budget — those are diagnostic facts and come back as evidence.
var ErrInvalidInput = errors.New("invalid kafka adapter input")

// Params carries what the exchange needs beyond the transport paths.
type Params struct {
	// ExchangeTimeout optionally bounds each exchange, derived from the
	// caller's context. Zero means only the caller's context bounds the work.
	//
	// It exists for the same reason the transport chain has a per-step bound:
	// one unresponsive broker would otherwise consume the budget every later
	// path needs, and the report would say less the slower one broker is.
	ExchangeTimeout time.Duration
}

// Run performs one ApiVersions exchange over every transport path it is given.
//
// Evidence goes into builder, one node per path, parented to the transport node
// whose connection was used. The returned Result owns the connection of every
// path whose exchange succeeded.
//
// # Ownership
//
// The connection of each path is taken from its Continuation, so after this call
// the transport Result no longer holds it. A path whose exchange broke has its
// connection closed here; a path whose exchange completed keeps it open for the
// next phase, including one where the broker answered with an error code — that
// is a fact about the answer, not about the socket.
//
// # Errors
//
// An error means the adapter could not run: unusable input, or an invariant
// failure such as a graph that rejected a node. Every protocol outcome is
// evidence.
//
// There is deliberately no aggregate. If two brokers advertise different API
// ranges, that is two facts, and what it means about the cluster is a rule's
// decision.
func Run(
	ctx context.Context,
	builder *domain.GraphBuilder,
	paths []*transport.Continuation,
	params Params,
) (*Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if builder == nil {
		return nil, fmt.Errorf("%w: graph builder must not be nil", ErrInvalidInput)
	}
	if params.ExchangeTimeout < 0 {
		return nil, fmt.Errorf(
			"%w: exchange timeout %s must not be negative", ErrInvalidInput, params.ExchangeTimeout)
	}

	result := &Result{}
	completed := false
	defer func() {
		if !completed {
			_ = result.Close()
		}
	}()

	for _, path := range paths {
		if path == nil {
			continue
		}
		if err := exchange(ctx, builder, path, params, result); err != nil {
			return nil, err
		}
	}

	completed = true
	return result, nil
}

// exchange runs ApiVersions over one transport path.
//
// A path whose connection is no longer available is skipped without evidence:
// the adapter has nothing to say about an exchange it was never given the means
// to attempt, and inventing a node for it would be a synthetic fact.
func exchange(
	ctx context.Context,
	builder *domain.GraphBuilder,
	path *transport.Continuation,
	params Params,
	result *Result,
) error {
	conn, ok := path.TakeConn()
	if !ok {
		return nil
	}

	observed := observe(ctx, conn, params.ExchangeTimeout)

	evidence, err := observed.evidence(path)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if err := record(builder, evidence, path.Evidence()); err != nil {
		_ = conn.Close()
		return err
	}

	// Whether the connection survives depends on the exchange, not on the
	// answer. A broker that replied with an error code spoke Kafka correctly and
	// its socket is still usable for the next request; an exchange that broke
	// mid-flight leaves a socket whose protocol state nobody knows, and this
	// package is the only one in a position to tell the two apart.
	if observed.err != nil {
		_ = conn.Close()
		return nil
	}

	result.add(conn, path, evidence.ID())
	return nil
}

// observation is the producer-local record of one exchange.
//
// It holds the raw error, which is exactly what must not reach the canonical
// model, and the plain values the wire boundary returned. Normalization happens
// here and only domain.Evidence leaves.
type observation struct {
	response wire.APIVersions

	// err is what the exchange returned, and ctxErr is what the caller's
	// context reported at the same moment. Both are needed for the same reason
	// as in every probe: a deadline that belongs to svcdoctor must never be
	// reported as a claim about the peer.
	err    error
	ctxErr error

	startedAt time.Time
	duration  time.Duration
}

// observe performs the exchange and records what happened.
//
// This is the only function here that performs I/O or reads a clock; everything
// after it is a pure transformation.
func observe(ctx context.Context, conn net.Conn, timeout time.Duration) observation {
	exchangeCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		exchangeCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	startedAt := time.Now()
	response, err := wire.ExchangeAPIVersions(exchangeCtx, conn)
	duration := time.Since(startedAt)

	return observation{
		response:  response,
		err:       err,
		ctxErr:    ctx.Err(),
		startedAt: startedAt,
		duration:  duration,
	}
}

// evidence normalizes the observation into the canonical model.
//
// The subject is the concrete peer the exchange ran against, matching the
// transport nodes for the same path, so a reader can follow one address from L2
// to L4. The logical bootstrap name is not repeated here: it scopes the
// identifier, and the graph connects the layers.
func (o observation) evidence(path *transport.Continuation) (domain.Evidence, error) {
	address := path.Address()

	subject, err := domain.NewEndpointSubject(address.String())
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	state, failureClass := o.classify()

	return domain.NewEvidence(domain.EvidenceInput{
		ID: probe.EvidenceID(
			StepAPIVersions, path.Endpoint(), address.Addr().String()),
		Subject:      subject,
		Layer:        domain.LayerProtocol,
		Step:         StepAPIVersions,
		State:        state,
		FailureClass: failureClass,
		Attributes:   o.attributes(),
		StartedAt:    o.startedAt,
		Duration:     o.duration,
	})
}

// classify decides what the observation is allowed to claim.
//
// The order of the checks is the same contract every probe follows: a completed
// exchange is a fact, then the caller's context, then what the wire boundary
// observed.
func (o observation) classify() (domain.State, domain.FailureClass) {
	if o.err == nil {
		if o.response.ErrorCode != 0 {
			// The peer is Kafka and answered, but not with what was asked for.
			// Which error it was is always recorded as an attribute; the class
			// says only what the code proves on its own.
			return domain.StateFail, protocolFailure(o.response.ErrorCode)
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

// protocolFailure normalizes a broker error code into the service-neutral
// vocabulary.
//
// Exactly one code is translated, and only because the response proves the
// generic fact by itself: UNSUPPORTED_VERSION on an ApiVersions response means
// the broker does not support the request version it was sent, which is what
// PROTOCOL_UNSUPPORTED_VERSION says and nothing more. Which version was asked
// for is already on the node as kafka.request_api_version, so the reader has
// both halves and this function infers neither.
//
// The distinction it buys is the same one FailureTLSPeerNotTLS buys at L3.
// Without it, "this port is not Kafka at all" and "this Kafka broker declined
// the version" arrive as one class, and those two lead to opposite actions.
//
// Every other code stays PROTOCOL_UNEXPECTED_RESPONSE with the code itself as
// an attribute. Mapping further would either invent precision a number does not
// carry or infer a cause — an authentication state, a configuration — that the
// response does not state. The Kafka code and its name stay Kafka's; no
// service-specific class enters internal/domain (ADR 0025).
func protocolFailure(code int16) domain.FailureClass {
	if code == errorCodeUnsupportedVersion {
		return domain.FailureProtocolUnsupportedVersion
	}
	return domain.FailureProtocolUnexpectedResponse
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// attributes records the facts the exchange yielded.
//
// The advertised ranges appear only when the broker actually sent some, so an
// absent list and an empty one are not confused.
func (o observation) attributes() map[domain.AttributeKey]domain.AttrValue {
	attributes := map[domain.AttributeKey]domain.AttrValue{
		AttrRequestAPIVersion: domain.IntAttr(int64(wire.RequestAPIVersion())),
	}
	if o.err == nil {
		attributes[AttrErrorCode] = domain.IntAttr(int64(o.response.ErrorCode))
	}
	if ranges := canonicalRanges(o.response.Keys); len(ranges) > 0 {
		attributes[AttrAPIVersions] = domain.StringListAttr(ranges...)
	}
	return attributes
}

// canonicalRanges renders the advertised API keys in a stable grammar.
//
//	"<key>:<min>-<max>", sorted by key ascending
//
// Sorting is numeric rather than lexical, so key 2 precedes key 10 and a report
// reads in protocol order. A broker's own ordering is an encoding detail and
// must not reach a canonical report.
func canonicalRanges(keys []wire.APIKeyRange) []string {
	if len(keys) == 0 {
		return nil
	}

	sorted := slices.Clone(keys)
	slices.SortFunc(sorted, func(a, b wire.APIKeyRange) int {
		return int(a.Key) - int(b.Key)
	})

	out := make([]string, 0, len(sorted))
	var b strings.Builder
	for _, key := range sorted {
		b.Reset()
		b.WriteString(strconv.Itoa(int(key.Key)))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(int(key.MinVersion)))
		b.WriteByte('-')
		b.WriteString(strconv.Itoa(int(key.MaxVersion)))
		out = append(out, b.String())
	}
	return out
}

// record adds the node and its parent edge.
//
// The parent is the transport node whose connection carried the exchange, so the
// graph shows which measured path produced this protocol observation. It is
// derivation, not provenance (ADR 0013).
func record(builder *domain.GraphBuilder, evidence domain.Evidence, parent domain.EvidenceID) error {
	if err := builder.AddEvidence(evidence); err != nil {
		return fmt.Errorf("recording %s evidence: %w", evidence.Step(), err)
	}
	if err := builder.AddParent(evidence.ID(), parent); err != nil {
		return fmt.Errorf("recording parent of %s: %w", evidence.ID(), err)
	}
	return nil
}
